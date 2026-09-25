package main

import (
	"bytes"
	"context"
	"crypto/fips140"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vecta-kms/pkg/fips/fipstest"
)

func fakeKeycore(t *testing.T, svc *Service) *fakeDataProtectKeyCore {
	t.Helper()
	f, ok := svc.keycore.(*fakeDataProtectKeyCore)
	if !ok {
		t.Fatal("test service must use fakeDataProtectKeyCore")
	}
	return f
}

// addNewKey registers a key created after the v2 cutoff (a key born v2).
func addNewKey(t *testing.T, svc *Service, keyID string) {
	t.Helper()
	f := fakeKeycore(t, svc)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.items[keyID] = map[string]interface{}{
		"id": keyID, "kcv": "EEEE05", "algorithm": "AES-256", "key_type": "symmetric", "purpose": "encrypt-decrypt",
		"status": "active", "export_allowed": true, "current_version": float64(1),
		"created_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	}
}

// legacyKeyForCompare computes the identifier-derived key only so tests can
// assert the real working key differs from it; under strict mode that
// derivation panics (short HMAC key), so it runs outside enforcement.
func legacyKeyForCompare(tenantID, keyID, purpose string, meta map[string]interface{}) []byte {
	var out []byte
	fips140.WithoutEnforcement(func() { out = legacyIdentifierWorkingKey(tenantID, keyID, purpose, meta) })
	return out
}

func svcErrCode(err error) string {
	var se serviceError
	if errors.As(err, &se) {
		return se.Code
	}
	return ""
}

func fpeEncrypt(t *testing.T, ctx context.Context, svc *Service, tenant, keyID, pt string) (string, error) {
	t.Helper()
	out, err := svc.FPEEncrypt(ctx, FPERequest{TenantID: tenant, KeyID: keyID, Algorithm: "FF1", Radix: 10, Tweak: "abcd", Plaintext: pt})
	return firstString(out["ciphertext"]), err
}

func fpeDecrypt(t *testing.T, ctx context.Context, svc *Service, tenant, keyID, ct string) (string, error) {
	t.Helper()
	out, err := svc.FPEDecrypt(ctx, FPERequest{TenantID: tenant, KeyID: keyID, Algorithm: "FF1", Radix: 10, Tweak: "abcd", Ciphertext: ct})
	return firstString(out["plaintext"]), err
}

// A key created after the cutoff is v2 from birth: its working key comes from
// keycore service-derive and never from identifiers, in every FIPS mode.
func TestNewKeyUsesKeycoreDerivationOnly(t *testing.T) {
	svc, _, pub := newDataProtectService(t)
	ctx := context.Background()
	addNewKey(t, svc, "key-new")

	key, use, err := svc.resolveWorkingKeyWithKDF(ctx, "t-new", "key-new", "fpe", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if use.Version != kdfV2 || use.KeyVersion != 1 {
		t.Fatalf("new key must derive v2 pinned to version 1, got %+v", use)
	}
	legacy := legacyKeyForCompare("t-new", "key-new", "fpe", fakeKeycore(t, svc).items["key-new"])
	if bytes.Equal(key, legacy) {
		t.Fatal("working key must not equal the identifier-derived key")
	}
	if fakeKeycore(t, svc).deriveCalls == 0 {
		t.Fatal("working key must come from keycore service-derive")
	}
	ct, err := fpeEncrypt(t, ctx, svc, "t-new", "key-new", "1234567890")
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := fpeDecrypt(t, ctx, svc, "t-new", "key-new", ct); err != nil || pt != "1234567890" {
		t.Fatalf("fpe round trip on v2 key: %q %v", pt, err)
	}
	if _, err := fpeEncrypt(t, withRequestedKDF(ctx, kdfV1), svc, "t-new", "key-new", "1234567890"); svcErrCode(err) != "legacy_kdf_retired" {
		t.Fatalf("v1 on a v2 key must be refused, got %v", err)
	}
	if pub.Count("audit.dataprotect.kdf_legacy_used") != 0 {
		t.Fatal("a v2 key must never record legacy derivation")
	}
}

// Keys that existed before the release keep reading their data (v1) and every
// such use is audited, so nothing breaks silently.
func TestLegacyKeyStaysReadableAndIsAudited(t *testing.T) {
	fipstest.SkipIfStrict(t, "identifier-derived (v1) working keys")
	svc, store, pub := newDataProtectService(t)
	ctx := context.Background()
	ct, err := fpeEncrypt(t, ctx, svc, "t-leg", "key-1", "1234567890")
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := fpeDecrypt(t, ctx, svc, "t-leg", "key-1", ct); err != nil || pt != "1234567890" {
		t.Fatalf("legacy round trip: %q %v", pt, err)
	}
	if n := pub.Count("audit.dataprotect.kdf_legacy_used"); n != 1 {
		t.Fatalf("legacy use must be audited once per interval, got %d events", n)
	}
	st, err := store.GetKeyKDF(ctx, "t-leg", "key-1")
	if err != nil || st.State != kdfStateLegacy || st.LegacyUses < 1 {
		t.Fatalf("legacy key state: %+v %v", st, err)
	}
	if _, err := fpeEncrypt(t, withRequestedKDF(ctx, kdfV2), svc, "t-leg", "key-1", "1"); svcErrCode(err) != "kdf_migration_not_started" {
		t.Fatalf("v2 before migration must be refused, got %v", err)
	}
}

// Customer-held data (FPE here) migrates by reading with v1 and writing with
// v2 during "migrating"; after completion v1 is refused.
func TestKDFMigrationDualReadThenCutover(t *testing.T) {
	fipstest.SkipIfStrict(t, "identifier-derived (v1) working keys")
	svc, _, pub := newDataProtectService(t)
	ctx := context.Background()
	oldCT, err := fpeEncrypt(t, ctx, svc, "t-mig", "key-1", "1234567890")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.StartKDFMigration(ctx, "t-mig", "key-1", "tester"); err != nil {
		t.Fatal(err)
	}
	pt, err := fpeDecrypt(t, withRequestedKDF(ctx, kdfV1), svc, "t-mig", "key-1", oldCT)
	if err != nil || pt != "1234567890" {
		t.Fatalf("dual-read v1: %q %v", pt, err)
	}
	newCT, err := fpeEncrypt(t, withRequestedKDF(ctx, kdfV2), svc, "t-mig", "key-1", pt)
	if err != nil || newCT == oldCT {
		t.Fatalf("re-protect with v2 must produce new ciphertext: %q %v", newCT, err)
	}
	if _, err := svc.CompleteKDFMigration(ctx, "t-mig", "key-1", "tester", false); err != nil {
		t.Fatal(err)
	}
	if pt, err := fpeDecrypt(t, ctx, svc, "t-mig", "key-1", newCT); err != nil || pt != "1234567890" {
		t.Fatalf("after cutover v2 is the default: %q %v", pt, err)
	}
	if _, err := fpeDecrypt(t, withRequestedKDF(ctx, kdfV1), svc, "t-mig", "key-1", oldCT); svcErrCode(err) != "legacy_kdf_retired" {
		t.Fatalf("v1 after migration must be refused, got %v", err)
	}
	if pub.Count("audit.dataprotect.kdf_refused") != 1 {
		t.Fatal("a v1 request after migration must be audited")
	}
	for _, ev := range []string{"audit.dataprotect.kdf_migration_started", "audit.dataprotect.kdf_migration_completed"} {
		if pub.Count(ev) != 1 {
			t.Fatalf("missing audit event %s", ev)
		}
	}
}

// Stored vault tokens are re-protected server-side; token strings customers
// hold stay valid and the same input keeps its token.
func TestVaultReprotectKeepsTokens(t *testing.T) {
	fipstest.SkipIfStrict(t, "identifier-derived (v1) working keys")
	svc, store, _ := newDataProtectService(t)
	ctx := context.Background()
	vault, err := svc.CreateTokenVault(ctx, "t-vault", TokenVault{Name: "cards", TokenType: "credit_card", Format: "deterministic", KeyID: "key-1"})
	if err != nil {
		t.Fatal(err)
	}
	tokenize := func(v string) string {
		items, err := svc.Tokenize(ctx, TokenizeRequest{TenantID: "t-vault", VaultID: vault.ID, Values: []string{v}})
		if err != nil || len(items) != 1 {
			t.Fatalf("tokenize: %v %+v", err, items)
		}
		return firstString(items[0]["token"])
	}
	detokenize := func(tok string) string {
		out, err := svc.Detokenize(ctx, DetokenizeRequest{TenantID: "t-vault", Tokens: []string{tok}})
		if err != nil || len(out) != 1 {
			t.Fatalf("detokenize: %v %+v", err, out)
		}
		return firstString(out[0]["value"])
	}
	tokA := tokenize("4111111111111111")
	tokB := tokenize("5500000000000004")

	if _, err := svc.StartKDFMigration(ctx, "t-vault", "key-1", "tester"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteKDFMigration(ctx, "t-vault", "key-1", "tester", false); svcErrCode(err) != "legacy_tokens_remaining" {
		t.Fatalf("complete must wait for vault re-protection, got %v", err)
	}
	if got := tokenize("4111111111111111"); got != tokA {
		t.Fatalf("while migrating, the same input must keep its token: %s vs %s", got, tokA)
	}
	out, err := svc.ReprotectVaultTokens(ctx, "t-vault", "key-1", 100, "tester")
	if err != nil || out["converted"] != 2 || out["remaining"] != 0 {
		t.Fatalf("reprotect: %+v %v", out, err)
	}
	if _, err := svc.CompleteKDFMigration(ctx, "t-vault", "key-1", "tester", false); err != nil {
		t.Fatal(err)
	}
	if detokenize(tokA) != "4111111111111111" || detokenize(tokB) != "5500000000000004" {
		t.Fatal("re-protected tokens must detokenize to their originals")
	}
	if got := tokenize("4111111111111111"); got != tokA {
		t.Fatalf("after migration the same input must keep its token: %s vs %s", got, tokA)
	}
	rec, err := store.GetTokenByValue(ctx, "t-vault", tokA)
	if err != nil || rec.KDFVersion != kdfV2 || rec.KDFKeyVersion != 1 {
		t.Fatalf("stored token must be v2 pinned to version 1: %+v %v", rec, err)
	}
}

// After migration no path accepts identifier-derived keys, in every FIPS mode
// (the CI matrix runs this under off, on and only). The migration itself needs
// no v1 derivation when there is no stored v1 data, so it also runs in strict.
func TestIdentifierKeysRejectedAfterMigrationEveryMode(t *testing.T) {
	svc, _, pub := newDataProtectService(t)
	ctx := context.Background()
	if _, err := svc.StartKDFMigration(ctx, "t-any", "key-2", "tester"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteKDFMigration(ctx, "t-any", "key-2", "tester", false); err != nil {
		t.Fatal(err)
	}
	addNewKey(t, svc, "key-born-v2")
	for _, keyID := range []string{"key-2", "key-born-v2"} {
		for _, purpose := range []string{"tokenize", "fpe", "field-encrypt", "envelope-kek", "searchable", "masking"} {
			if _, _, err := svc.resolveWorkingKeyWithKDF(withRequestedKDF(ctx, kdfV1), "t-any", keyID, purpose, nil, ""); svcErrCode(err) != "legacy_kdf_retired" {
				t.Fatalf("%s/%s: v1 must be refused after migration, got %v", keyID, purpose, err)
			}
			key, use, err := svc.resolveWorkingKeyWithKDF(ctx, "t-any", keyID, purpose, nil, "")
			if err != nil || use.Version != kdfV2 {
				t.Fatalf("%s/%s: default must be v2: %+v %v", keyID, purpose, use, err)
			}
			if bytes.Equal(key, legacyKeyForCompare("t-any", keyID, purpose, fakeKeycore(t, svc).items[keyID])) {
				t.Fatalf("%s/%s: working key equals the identifier-derived key", keyID, purpose)
			}
		}
	}
	if pub.Count("audit.dataprotect.kdf_legacy_used") != 0 {
		t.Fatal("no legacy derivation may happen for migrated keys")
	}
}

func TestKDFHandlerRoutesAndHeader(t *testing.T) {
	h, svc, _ := newDataProtectHandler(t)
	addNewKey(t, svc, "key-born-v2")
	req := httptest.NewRequest(http.MethodPost, "/fpe/encrypt?tenant_id=t-h", bytes.NewReader([]byte(`{"tenant_id":"t-h","key_id":"key-born-v2","algorithm":"FF1","radix":10,"tweak":"abcd","plaintext":"1234567890"}`)))
	req.Header.Set(KDFVersionHeader, "v9")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("invalid %s must be rejected, got %d %s", KDFVersionHeader, rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/kdf/keys?tenant_id=t-h", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /kdf/keys: %d %s", rr.Code, rr.Body.String())
	}
}
