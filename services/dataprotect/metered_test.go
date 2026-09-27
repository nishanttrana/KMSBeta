package main

import (
	"context"
	"testing"
)

func metered(t *testing.T, d map[string]interface{}, op, result string) {
	t.Helper()
	if d == nil || d["metered_op"] != op || (result != "" && d["result"] != result) {
		t.Fatalf("event not metered as %s/%s: %+v", op, result, d)
	}
	if _, ok := d["duration_ms"].(float64); !ok {
		t.Fatalf("metered event has no duration_ms: %+v", d)
	}
}

// Every data-protection operation is metered by exactly one event: its own
// success event, <op>_failed / <op>_refused when it doesn't complete, or
// fpe_refused for a withdrawn FPE algorithm (never also <op>_failed).
func TestDataProtectOperationsMetered(t *testing.T) {
	svc, _, pub := newDataProtectService(t)
	ctx := context.Background()

	// Holds in every FIPS mode: strict mode refuses identifier-derived
	// working keys, which must then be the metered outcome.
	if _, err := svc.FPEEncrypt(ctx, FPERequest{TenantID: "t1", KeyID: "key-1", Algorithm: "FF1", Plaintext: "4111111111111111"}); err == nil {
		metered(t, pub.Data("audit.dataprotect.fpe_encrypted"), "fpe_encrypt", "")
	} else if d := pub.Data("audit.dataprotect.fpe_encrypt_refused"); d != nil {
		metered(t, d, "fpe_encrypt", "refused")
	} else {
		metered(t, pub.Data("audit.dataprotect.fpe_encrypt_failed"), "fpe_encrypt", "failure")
	}

	if _, err := svc.FPEEncrypt(ctx, FPERequest{TenantID: "t1", KeyID: "key-1"}); err == nil {
		t.Fatal("empty plaintext accepted")
	}
	metered(t, pub.Data("audit.dataprotect.fpe_encrypt_failed"), "fpe_encrypt", "failure")

	before := pub.Count("audit.dataprotect.fpe_encrypt_failed") + pub.Count("audit.dataprotect.fpe_encrypt_refused")
	if _, err := svc.FPEEncrypt(ctx, FPERequest{TenantID: "t1", KeyID: "key-1", Algorithm: "FF3-1", Plaintext: "1234567890"}); err == nil {
		t.Fatal("FF3-1 accepted")
	}
	metered(t, pub.Data("audit.dataprotect.fpe_refused"), "fpe_encrypt", "refused")
	if after := pub.Count("audit.dataprotect.fpe_encrypt_failed") + pub.Count("audit.dataprotect.fpe_encrypt_refused"); after != before {
		t.Fatal("an FPE algorithm refusal was audited twice")
	}
}
