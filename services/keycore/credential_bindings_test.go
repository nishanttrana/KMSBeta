package main

import (
	"context"
	"crypto/sha256"
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
