package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/fips/fipstest"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

// An X25519MLKEM768 key encapsulates a 64-byte secret (ML-KEM-768 then
// X25519) that decapsulation recovers; other "+" composites are still
// refused.
func TestHybridKEMKeyRoundTrip(t *testing.T) {
	fipstest.SkipIfStrict(t, "X25519MLKEM768 (X25519 half)")
	_, svc := newHandlerForTest(t)
	ctx := adminCtx()
	key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "hy", Algorithm: "X25519MLKEM768",
		KeyType: "asymmetric", Purpose: "key_establishment", Owner: "ops", CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := svc.KEMEncapsulate(ctx, key.ID, KEMEncapsulateRequest{TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	shared, _ := base64.StdEncoding.DecodeString(enc.SharedSecretB64)
	ct, _ := base64.StdEncoding.DecodeString(enc.EncapsulatedB64)
	if len(shared) != 64 || len(ct) != 1088+32 {
		t.Fatalf("shared %d bytes, ciphertext %d bytes", len(shared), len(ct))
	}
	dec, err := svc.KEMDecapsulate(ctx, key.ID, KEMDecapsulateRequest{TenantID: "t1", EncapsulatedB64: enc.EncapsulatedB64})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := base64.StdEncoding.DecodeString(dec.SharedSecretB64); !bytes.Equal(got, shared) {
		t.Fatal("decapsulated secret differs")
	}
	ct[5] ^= 1 // ML-KEM implicit rejection: a tampered ciphertext yields another secret
	if dec2, err := svc.KEMDecapsulate(ctx, key.ID, KEMDecapsulateRequest{TenantID: "t1", EncapsulatedB64: base64.StdEncoding.EncodeToString(ct)}); err == nil {
		if got, _ := base64.StdEncoding.DecodeString(dec2.SharedSecretB64); bytes.Equal(got, shared) {
			t.Fatal("tampered ciphertext produced the same secret")
		}
	}
	if _, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "cmp", Algorithm: "ML-DSA-65+ECDSA-P256",
		KeyType: "asymmetric", Purpose: "sign", Owner: "ops", CreatedBy: "tester"}); err == nil {
		t.Fatal("a composite other than X25519MLKEM768 was created")
	}
}

// A tenant's own cryptoperiod replaces the built-in one in the lifecycle
// scan; invalid values and unknown categories are refused and audited.
func TestTenantCryptoperiodDrivesRotation(t *testing.T) {
	h, svc := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	r := h.rotationRouter(rec)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		claims := &pkgauth.Claims{UserID: "tester", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
		req := httptest.NewRequest(method, path+"?tenant_id=t1", strings.NewReader(body))
		r.ServeHTTP(w, req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims)))
		return w
	}
	for _, bad := range []struct{ path, body, reason string }{
		{"/rotation/cryptoperiods/signing", `{"days":0}`, "invalid_days"},
		{"/rotation/cryptoperiods/nope", `{"days":30}`, "unknown_category"},
	} {
		if w := call(http.MethodPut, bad.path, bad.body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", bad.path, w.Code)
		}
		if ev := rec.Last(t); ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != bad.reason {
			t.Fatalf("%s audited %+v", bad.path, ev.Event)
		}
	}
	if w := call(http.MethodPut, "/rotation/cryptoperiods/signing", `{"days":30}`); w.Code != http.StatusOK {
		t.Fatalf("set: %d %s", w.Code, w.Body)
	}
	if ev := rec.Last(t); ev.Action != "cryptoperiod_set" || ev.Event.Result != route.ResultSuccess {
		t.Fatalf("set audited %s %+v", ev.Action, ev.Event)
	}
	ov, err := svc.store.ListCryptoperiodOverrides(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	cp := NewCryptoperiodPolicy()
	c := LifecycleCandidate{Status: "active", CreatedAt: time.Now().Add(-60 * 24 * time.Hour), Purpose: "sign", Algorithm: "ECDSA-P256"}
	if a, _ := EvaluateLifecycleFor(c, cp, nil, time.Now()); a != "" {
		t.Fatalf("60-day signing key due under the built-in year: %q", a)
	}
	if a, _ := EvaluateLifecycleFor(c, cp, ov, time.Now()); a != "rotate" {
		t.Fatalf("60-day signing key not due under the tenant's 30 days: %q", a)
	}
	if w := call(http.MethodDelete, "/rotation/cryptoperiods/signing", ""); w.Code != http.StatusOK {
		t.Fatalf("reset: %d", w.Code)
	}
	if w := call(http.MethodDelete, "/rotation/cryptoperiods/signing", ""); w.Code != http.StatusNotFound {
		t.Fatalf("second reset: %d", w.Code)
	}
	if ev := rec.Last(t); ev.Event.Details["reason"] != "not_custom" {
		t.Fatalf("second reset audited %+v", ev.Event)
	}
}

// Strict mode refuses an X25519MLKEM768 key cleanly (a FIPS violation, not a
// module panic); ML-KEM-768 keys still work.
func TestStrictModeRefusesHybridKEMKey(t *testing.T) {
	fipstest.StrictOnly(t)
	_, svc := newHandlerForTest(t)
	_, err := svc.CreateKey(adminCtx(), CreateKeyRequest{TenantID: "t1", Name: "hy", Algorithm: "X25519MLKEM768",
		KeyType: "asymmetric", Purpose: "key_establishment", Owner: "ops", CreatedBy: "tester"})
	var v fipsModeViolationError
	if !errors.As(err, &v) {
		t.Fatalf("X25519MLKEM768 in strict mode: %v", err)
	}
	if _, err := svc.CreateKey(adminCtx(), CreateKeyRequest{TenantID: "t1", Name: "kem", Algorithm: "ML-KEM-768",
		KeyType: "asymmetric", Purpose: "key_establishment", Owner: "ops", CreatedBy: "tester"}); err != nil {
		t.Fatalf("ML-KEM-768 in strict mode: %v", err)
	}
}
