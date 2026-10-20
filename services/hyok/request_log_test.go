package main

import (
	"context"
	"strings"
	"testing"
)

// The request log keeps sizes, never the key a caller wrapped or the key
// unwrapped for it (13.29.0-beta).
func TestRequestLogHoldsNoKeyBytes(t *testing.T) {
	svc, store, keycore, _, _, _ := newHYOKService(t)
	ctx := context.Background()
	keycore.Seed("tenant-1", "key-1", "AES-256")
	identity := AuthIdentity{Mode: "jwt", Subject: "tenant-1:cloud"}
	const dek = "c2VjcmV0LWRhdGEtZW5jcnlwdGlvbi1rZXktMzJieXRlcw=="

	wrapped, err := svc.ProcessCrypto(ctx, "tenant-1", ProtocolGeneric, "wrap", "key-1", "/hyok/generic/v1/keys/key-1/wrap", identity, ProxyCryptoRequest{PlaintextB64: dek})
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := svc.ProcessCrypto(ctx, "tenant-1", ProtocolGeneric, "unwrap", "key-1", "/hyok/generic/v1/keys/key-1/unwrap", identity, ProxyCryptoRequest{CiphertextB64: wrapped.CiphertextB64, IVB64: wrapped.IVB64})
	if err != nil {
		t.Fatal(err)
	}
	if unwrapped.PlaintextB64 != dek {
		t.Fatalf("round trip lost the key: %q", unwrapped.PlaintextB64)
	}
	logs, err := store.ListRequestLogs(ctx, "tenant-1", ProtocolGeneric, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 2 {
		t.Fatalf("want 2 logged requests, got %d", len(logs))
	}
	for _, l := range logs {
		for _, stored := range []string{l.RequestJSON, l.ResponseJSON} {
			for _, secret := range []string{dek, wrapped.CiphertextB64, `"plaintext"`, `"ciphertext"`} {
				if strings.Contains(stored, secret) {
					t.Fatalf("%s log holds %s: %s", l.Operation, secret, stored)
				}
			}
		}
		if !strings.Contains(l.RequestJSON, "_bytes") {
			t.Fatalf("%s log records no size: %s", l.Operation, l.RequestJSON)
		}
	}
}
