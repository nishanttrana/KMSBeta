package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestCredentialFingerprintMatchesSHA256(t *testing.T) {
	// This formula MUST match the posture leak scanner's credentialFingerprint.
	secret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	sum := sha256.Sum256([]byte(secret))
	if got := credentialFingerprint(secret); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("fingerprint mismatch: %s", got)
	}
}

func TestCredentialBindingUpsertAndResolve(t *testing.T) {
	_, svc := newHandlerForTest(t)
	ctx := context.Background()
	fp := credentialFingerprint("AKIAIOSFODNN7EXAMPLE")

	if _, err := svc.store.UpsertCredentialBinding(ctx, CredentialBinding{
		TenantID: "t1", Fingerprint: fp, CredentialType: "aws_access_key_id",
		KeyID: "key_aaaaaaaaaaaaaaaa", Label: "prod wrapping key",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Upsert again with a different key rebinds (idempotent on fingerprint).
	if _, err := svc.store.UpsertCredentialBinding(ctx, CredentialBinding{
		TenantID: "t1", Fingerprint: fp, CredentialType: "aws_access_key_id",
		KeyID: "key_bbbbbbbbbbbbbbbb",
	}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}

	resolved, err := svc.store.ResolveCredentialBindings(ctx, "t1", []string{fp, "deadbeef"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	b, ok := resolved[fp]
	if !ok {
		t.Fatal("expected fingerprint to resolve")
	}
	if b.KeyID != "key_bbbbbbbbbbbbbbbb" {
		t.Fatalf("expected rebind to key_bbbb..., got %s", b.KeyID)
	}
	if _, ok := resolved["deadbeef"]; ok {
		t.Fatal("unknown fingerprint must not resolve")
	}
}

func TestCredentialBindingTenantIsolation(t *testing.T) {
	_, svc := newHandlerForTest(t)
	ctx := context.Background()
	fp := credentialFingerprint("shared-secret-value-123456")

	if _, err := svc.store.UpsertCredentialBinding(ctx, CredentialBinding{
		TenantID: "t1", Fingerprint: fp, KeyID: "key_1111111111111111",
	}); err != nil {
		t.Fatal(err)
	}
	// Tenant t2 must not see t1's binding even for the same fingerprint.
	resolved, err := svc.store.ResolveCredentialBindings(ctx, "t2", []string{fp})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 0 {
		t.Fatalf("tenant isolation breach: %v", resolved)
	}
}

func TestWrapAutoRegistersCredentialBinding(t *testing.T) {
	_, svc := newHandlerForTest(t)
	ctx := context.Background()
	key, err := svc.CreateKey(ctx, CreateKeyRequest{
		TenantID: "t1", Name: "wrapping-key", Algorithm: "AES-256", KeyType: "symmetric",
		Purpose: "wrap", Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	credential := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	// A wrap that flags the plaintext as an external credential must auto-bind.
	if _, err := svc.Encrypt(ctx, key.ID, EncryptRequest{
		TenantID:     "t1",
		PlaintextB64: base64.StdEncoding.EncodeToString([]byte(credential)),
		Operation:    "wrap",
		CredentialBinding: &CredentialBindingIntent{
			Register: true, CredentialType: "aws_secret_access_key", Label: "prod backups",
		},
	}); err != nil {
		t.Fatalf("wrap: %v", err)
	}

	// The same fingerprint the leak scanner would compute must now resolve to
	// this key — closing the loop with no manual declaration.
	fp := credentialFingerprint(credential)
	resolved, err := svc.store.ResolveCredentialBindings(ctx, "t1", []string{fp})
	if err != nil {
		t.Fatal(err)
	}
	b, ok := resolved[fp]
	if !ok {
		t.Fatal("expected wrap to auto-register a resolvable binding")
	}
	if b.KeyID != key.ID || b.CredentialType != "aws_secret_access_key" {
		t.Fatalf("unexpected binding: %+v", b)
	}
}

func TestPlainEncryptDoesNotAutoBind(t *testing.T) {
	_, svc := newHandlerForTest(t)
	ctx := context.Background()
	key, err := svc.CreateKey(ctx, CreateKeyRequest{
		TenantID: "t1", Name: "data-key", Algorithm: "AES-256", KeyType: "symmetric",
		Purpose: "encrypt", Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	plaintext := "ordinary application data, not a credential"
	// No CredentialBinding intent -> nothing is fingerprinted or stored.
	if _, err := svc.Encrypt(ctx, key.ID, EncryptRequest{
		TenantID: "t1", PlaintextB64: base64.StdEncoding.EncodeToString([]byte(plaintext)),
	}); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	resolved, err := svc.store.ResolveCredentialBindings(ctx, "t1", []string{credentialFingerprint(plaintext)})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 0 {
		t.Fatal("plain encrypt must not create a credential binding")
	}
}

func TestCredentialBindingListAndDelete(t *testing.T) {
	_, svc := newHandlerForTest(t)
	ctx := context.Background()
	b, err := svc.store.UpsertCredentialBinding(ctx, CredentialBinding{
		TenantID: "t1", Fingerprint: credentialFingerprint("x"), KeyID: "key_cccccccccccccccc",
	})
	if err != nil {
		t.Fatal(err)
	}
	list, err := svc.store.ListCredentialBindingsByKey(ctx, "t1", "key_cccccccccccccccc")
	if err != nil || len(list) != 1 {
		t.Fatalf("list: n=%d err=%v", len(list), err)
	}
	if err := svc.store.DeleteCredentialBinding(ctx, "t1", b.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := svc.store.DeleteCredentialBinding(ctx, "t1", b.ID); err == nil {
		t.Fatal("expected error deleting an already-deleted binding")
	}
}
