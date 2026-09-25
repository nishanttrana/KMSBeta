package main

import (
	"context"
	"encoding/base64"
	"errors"
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
	if _, err := svc.RotateKey(context.Background(), "t1", key.ID, "test", ""); err != nil {
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

func TestGenericDeriveCannotReproduceServiceSubkey(t *testing.T) {
	_, svc := newHandlerForTest(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "dp-key-3", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "derive",
		Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	info := serviceDeriveInfo("kms-dataprotect", "t1", key.ID, "tokenize", 1)
	_, err = svc.Derive(context.Background(), key.ID, DeriveRequest{
		TenantID: "t1", Algorithm: "HKDF-SHA256", LengthBits: 256,
		InfoB64: base64.StdEncoding.EncodeToString(info),
		SaltB64: base64.StdEncoding.EncodeToString([]byte(serviceDeriveSalt)),
	})
	if !errors.Is(err, errReservedDeriveInfo) {
		t.Fatalf("generic derive must refuse the reserved service-derive info, got %v", err)
	}
}
