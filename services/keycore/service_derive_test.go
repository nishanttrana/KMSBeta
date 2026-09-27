package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
)

func serviceCtx(clientID string) context.Context {
	return contextWithAccessActor(context.Background(), AccessActor{
		ClientID: clientID, Role: "client-service", Authenticated: true, ServicePrincipal: true,
	})
}

func TestServiceDeriveBindsCallerPurposeAndVersion(t *testing.T) {
	_, svc := newHandlerForTest(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "dp-key", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	derive := func(ctx context.Context, purpose string, version int) (ServiceDeriveResponse, error) {
		return svc.ServiceDerive(ctx, key.ID, ServiceDeriveRequest{TenantID: "t1", Purpose: purpose, Version: version})
	}
	a, err := derive(serviceCtx("kms-dataprotect"), "tokenize", 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(a.DerivedB64)
	if len(raw) != 32 || a.Version != 1 || a.KDF != serviceDeriveKDF {
		t.Fatalf("unexpected derive result: %+v", a)
	}
	again, _ := derive(serviceCtx("kms-dataprotect"), "tokenize", 0)
	otherPurpose, _ := derive(serviceCtx("kms-dataprotect"), "fpe", 0)
	otherService, _ := derive(serviceCtx("kms-reporting"), "tokenize", 0)
	if again.DerivedB64 != a.DerivedB64 {
		t.Fatal("derivation must be deterministic")
	}
	if otherPurpose.DerivedB64 == a.DerivedB64 || otherService.DerivedB64 == a.DerivedB64 {
		t.Fatal("subkeys must be bound to purpose and to the calling service")
	}

	// Rotation must not change a subkey pinned to version 1.
	if _, err := svc.RotateKey(adminCtx(), "t1", key.ID, "test", ""); err != nil {
		t.Fatal(err)
	}
	pinned, err := derive(serviceCtx("kms-dataprotect"), "tokenize", 1)
	if err != nil || pinned.DerivedB64 != a.DerivedB64 {
		t.Fatalf("pinned version must keep the subkey stable: %v", err)
	}
	current, _ := derive(serviceCtx("kms-dataprotect"), "tokenize", 0)
	if current.Version != 2 || current.DerivedB64 == a.DerivedB64 {
		t.Fatalf("current version after rotation must be 2 with a new subkey, got %+v", current)
	}
}

func TestServiceDeriveRequiresServiceIdentity(t *testing.T) {
	_, svc := newHandlerForTest(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "dp-key-2", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, ctx := range map[string]context.Context{
		"anonymous": context.Background(),
		"admin user": contextWithAccessActor(context.Background(), AccessActor{
			UserID: "u1", Role: "admin", Authenticated: true,
		}),
		"external client-service": contextWithAccessActor(context.Background(), AccessActor{
			ClientID: "customer-app", Role: "client-service", Authenticated: true, ServicePrincipal: true,
		}),
	} {
		_, err := svc.ServiceDerive(ctx, key.ID, ServiceDeriveRequest{TenantID: "t1", Purpose: "tokenize"})
		if !errors.Is(err, errServiceIdentityRequired) {
			t.Fatalf("%s: got %v, want errServiceIdentityRequired", name, err)
		}
	}
}

type captureKeycorePublisher struct {
	mu       sync.Mutex
	subjects []string
	payloads [][]byte
}

func (c *captureKeycorePublisher) Publish(_ context.Context, subject string, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.subjects = append(c.subjects, subject)
	c.payloads = append(c.payloads, payload)
	return nil
}

func (c *captureKeycorePublisher) count(subject string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, s := range c.subjects {
		if s == subject {
			n++
		}
	}
	return n
}

// details returns the details of the last event published on subject.
func (c *captureKeycorePublisher) details(t *testing.T, subject string) map[string]any {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.subjects) - 1; i >= 0; i-- {
		if c.subjects[i] == subject {
			var ev struct {
				Details map[string]any `json:"details"`
			}
			if err := json.Unmarshal(c.payloads[i], &ev); err != nil {
				t.Fatal(err)
			}
			return ev.Details
		}
	}
	t.Fatalf("no %s event: %v", subject, c.subjects)
	return nil
}

// A service derive is audited with the calling service and purpose; a
// derive by anything but an internal service identity is refused and audited.
func TestServiceDeriveAudited(t *testing.T) {
	svc, pub := newCaptureService(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "dp-audit", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ServiceDerive(serviceCtx("kms-dataprotect"), key.ID, ServiceDeriveRequest{TenantID: "t1", Purpose: "tokenize"}); err != nil {
		t.Fatal(err)
	}
	if d := pub.details(t, "audit.key.service_derive"); d["service"] != "kms-dataprotect" || d["purpose"] != "tokenize" || d["result"] != "success" {
		t.Fatalf("derive details: %v", d)
	}
	admin := contextWithAccessActor(context.Background(), AccessActor{UserID: "u1", Role: "admin", Authenticated: true})
	if _, err := svc.ServiceDerive(admin, key.ID, ServiceDeriveRequest{TenantID: "t1", Purpose: "tokenize"}); !errors.Is(err, errServiceIdentityRequired) {
		t.Fatalf("admin derive: %v", err)
	}
	if d := pub.details(t, "audit.key.service_derive_refused"); d["reason"] != "service_identity_required" || d["result"] != "refused" {
		t.Fatalf("identity refusal details: %v", d)
	}
	if _, err := svc.ServiceDerive(serviceCtx("kms-dataprotect"), "missing", ServiceDeriveRequest{TenantID: "t1", Purpose: "tokenize"}); err == nil {
		t.Fatal("derive from a missing key")
	}
	if d := pub.details(t, "audit.key.service_derive_refused"); d["reason"] != "not_found" {
		t.Fatalf("missing-key refusal details: %v", d)
	}
	if pub.count("audit.key.service_derive") != 1 || pub.count("audit.key.service_derive_refused") != 2 {
		t.Fatalf("one derive and two refusals: %v", pub.subjects)
	}
}

func TestGenericDeriveCannotReproduceServiceSubkey(t *testing.T) {
	svc, pub := newCaptureService(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "dp-key-3", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "derive",
		Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	info := serviceDeriveInfo("kms-dataprotect", "t1", key.ID, "tokenize", 1)
	_, err = svc.Derive(adminCtx(), key.ID, DeriveRequest{
		TenantID: "t1", Algorithm: "HKDF-SHA256", LengthBits: 256,
		InfoB64: base64.StdEncoding.EncodeToString(info),
		SaltB64: base64.StdEncoding.EncodeToString([]byte(serviceDeriveSalt)),
	})
	if !errors.Is(err, errReservedDeriveInfo) {
		t.Fatalf("generic derive must refuse the reserved service-derive info, got %v", err)
	}
	found := false
	for _, s := range pub.subjects {
		found = found || s == "audit.key.derive_refused"
	}
	if !found {
		t.Fatalf("the refused attempt must be audited, got %v", pub.subjects)
	}
}
