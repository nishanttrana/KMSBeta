package main

import (
	"bytes"

	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

// signRequest posts body to path as a caller whose verified token names tenant.
func signRequest(t *testing.T, h http.Handler, path, tenant string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{TenantID: tenant, Role: "tenant-admin", UserID: "u-1"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// A sign or verify request naming a tenant other than the caller's is refused
// before it reaches a profile or key, and the refusal is audited.
func TestTenantMismatchRefusedAndAudited(t *testing.T) {
	for _, path := range []string{"/signing/blob", "/signing/git", "/signing/verify"} {
		pub := &recordingPublisher{}
		h := NewHandler(NewService(nil, nil, pub))
		rec := signRequest(t, h, path, "t-caller", map[string]any{"tenant_id": "t-victim", "record_id": "r", "payload_b64": "YQ=="})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: want 403, got %d %s", path, rec.Code, rec.Body)
		}
		d := pub.details(t, "audit.signing.request_refused")
		if d["reason"] != "tenant_mismatch" || d["result"] != "refused" || d["route"] != "POST "+path {
			t.Fatalf("%s: refusal details: %v", path, d)
		}
		if pub.count("audit.signing.sign_refused") != 0 || pub.count("audit.signing.artifact_signed") != 0 {
			t.Fatalf("%s: only the tenant refusal may be audited: %v", path, pub.subjects)
		}
	}
}

// A sign request the service refuses (disabled signing, then a forged OIDC
// token) returns 4xx and emits sign_refused with the refusal code; nothing is
// recorded as signed.
func TestSignRefusalAuditedPostgres(t *testing.T) {
	f := newSigningFixture(t)
	h := NewHandler(f.svc)
	in := f.validSignInput(t, "t-refuse", []byte("artifact"))

	rec := signRequest(t, h, "/signing/blob", "t-refuse", in)
	if rec.Code < 400 || rec.Code >= 500 {
		t.Fatalf("signing while disabled: want 4xx, got %d %s", rec.Code, rec.Body)
	}
	if d := f.pub.details(t, "audit.signing.sign_refused"); d["code"] != "disabled" || d["result"] != "refused" || d["reason"] == "" {
		t.Fatalf("disabled refusal details: %v", d)
	}

	f.enable(t, "t-refuse")
	in = f.validSignInput(t, "t-refuse", []byte("artifact"))
	in.OIDCToken = "not-a-jwt"
	rec = signRequest(t, h, "/signing/git", "t-refuse", in)
	if rec.Code < 400 || rec.Code >= 500 {
		t.Fatalf("forged token: want 4xx, got %d %s", rec.Code, rec.Body)
	}
	if d := f.pub.details(t, "audit.signing.sign_refused"); d["code"] != "oidc_token_invalid" || d["identity_mode"] != "oidc" {
		t.Fatalf("forged-token refusal details: %v", d)
	}
	if f.pub.count("audit.signing.sign_refused") != 2 || f.pub.count("audit.signing.artifact_signed") != 0 {
		t.Fatalf("each refusal is audited once and nothing is signed: %v", f.pub.subjects)
	}

	// The same request with a valid token signs and is not audited as refused.
	rec = signRequest(t, h, "/signing/blob", "t-refuse", f.validSignInput(t, "t-refuse", []byte("artifact")))
	if rec.Code != http.StatusCreated || f.pub.count("audit.signing.sign_refused") != 2 || f.pub.count("audit.signing.artifact_signed") != 1 {
		t.Fatalf("valid sign: %d %s %v", rec.Code, rec.Body, f.pub.subjects)
	}
}
