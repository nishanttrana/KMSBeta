package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

// signRequest posts body to path as a tenant administrator whose verified
// token names tenant.
func signRequest(t *testing.T, h http.Handler, path, tenant string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return signCall(t, h, http.MethodPost, path, body, &pkgauth.Claims{TenantID: tenant, Role: "tenant-admin", UserID: "u-1", Permissions: []string{"*"}})
}

func signCall(t *testing.T, h http.Handler, method, target string, body any, claims *pkgauth.Claims) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(raw))
	if claims != nil {
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Every route refuses a caller without a token, without the permission, or
// naming another tenant, and audits the refusal.
func TestRoutesRefuseAndAudit(t *testing.T) {
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, NewHandler(NewService(nil, nil, nil), rec, nil).router, rec)
}

// A request naming a tenant other than the caller's, in the query or the
// body, is refused before it reaches a profile, a record or a key, and the
// refusal is audited. Until 13.0.0-beta only sign and verify checked: the
// settings, profile, record and summary routes answered for any tenant named.
func TestTenantMismatchRefusedAndAudited(t *testing.T) {
	sign := map[string]any{"tenant_id": "t-victim", "record_id": "r", "payload_b64": "YQ=="}
	for _, tc := range []struct {
		method, target, action string
		body                   any
	}{
		{http.MethodPost, "/signing/blob", "blob_sign", sign},
		{http.MethodPost, "/signing/git", "git_sign", sign},
		{http.MethodPost, "/signing/verify", "artifact_verify", sign},
		{http.MethodPut, "/signing/settings", "settings_update", map[string]any{"tenant_id": "t-victim", "enabled": false}},
		{http.MethodPost, "/signing/profiles", "profile_upsert", map[string]any{"tenant_id": "t-victim", "name": "theirs"}},
		{http.MethodDelete, "/signing/profiles/p-1?tenant_id=t-victim", "profile_delete", nil},
		{http.MethodGet, "/signing/records?tenant_id=t-victim", "record_list", nil},
		{http.MethodGet, "/signing/settings?tenant_id=t-victim", "settings_read", nil},
		{http.MethodGet, "/signing/summary?tenant_id=t-victim", "summary_read", nil},
	} {
		pub, rec := &recordingPublisher{}, &routetest.Recorder{}
		// A nil store: a request that got past the kernel would panic.
		h := NewHandler(NewService(nil, nil, pub), rec, nil)
		w := signCall(t, h, tc.method, tc.target, tc.body, &pkgauth.Claims{TenantID: "t-caller", Role: "tenant-admin", UserID: "u-1", Permissions: []string{"*"}})
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s %s: want 403, got %d %s", tc.method, tc.target, w.Code, w.Body)
		}
		ev := rec.Last(t)
		if ev.Action != tc.action || ev.Event.Result != "refused" || ev.Event.Details["reason"] != "tenant_mismatch" || ev.Event.ActorID != "u-1" {
			t.Fatalf("%s %s: refusal event: %+v", tc.method, tc.target, ev)
		}
		if len(pub.subjects) != 0 {
			t.Fatalf("%s %s: the service was reached: %v", tc.method, tc.target, pub.subjects)
		}
	}
}

// Signing is its own permission: reading records and profiles neither signs
// nor changes a profile, and signing does not change one either.
func TestSigningNeedsItsPermission(t *testing.T) {
	h := NewHandler(NewService(nil, nil, &recordingPublisher{}), &routetest.Recorder{}, nil)
	as := func(perms ...string) *pkgauth.Claims {
		return &pkgauth.Claims{TenantID: "t1", Role: "custom", UserID: "u-2", Permissions: perms}
	}
	for _, tc := range []struct {
		claims         *pkgauth.Claims
		method, target string
	}{
		{as("signing.read"), http.MethodPost, "/signing/blob"},
		{as("signing.read"), http.MethodPost, "/signing/verify"},
		{as("signing.verify"), http.MethodPost, "/signing/blob"},
		{as("signing.use"), http.MethodPost, "/signing/verify"},
		{as("signing.read"), http.MethodPut, "/signing/settings"},
		{as("signing.use"), http.MethodPost, "/signing/profiles"},
		{as("signing.use"), http.MethodDelete, "/signing/profiles/p-1"},
		{as("signing.use"), http.MethodGet, "/signing/records"},
		{as("auth.self.read"), http.MethodGet, "/signing/settings"},
	} {
		if w := signCall(t, h, tc.method, tc.target, map[string]any{}, tc.claims); w.Code != http.StatusForbidden {
			t.Fatalf("%v %s %s: want 403, got %d %s", tc.claims.Permissions, tc.method, tc.target, w.Code, w.Body)
		}
	}
	if w := signCall(t, h, http.MethodGet, "/signing/settings", nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", w.Code)
	}
}

// A sign request the service refuses (disabled signing, then a forged OIDC
// token) returns 4xx and emits sign_refused with the refusal code; nothing is
// recorded as signed.
func TestSignRefusalAuditedPostgres(t *testing.T) {
	f := newSigningFixture(t)
	h := NewHandler(f.svc, nil, nil)
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

	// The record names who asked: the verified caller, not the "ci" the
	// request wrote, and who changed a profile likewise.
	var signed struct {
		Result struct {
			Record SigningRecord `json:"record"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &signed); err != nil {
		t.Fatal(err)
	}
	if by := signed.Result.Record.Metadata["requested_by"]; by != "u-1" {
		t.Fatalf("requested_by is the verified caller, got %v", by)
	}
	rec = signCall(t, h, http.MethodPut, "/signing/settings", map[string]any{"enabled": true, "updated_by": "somebody-else", "allowed_identity_modes": []string{"oidc", "workload"}},
		&pkgauth.Claims{TenantID: "t-refuse", Role: "tenant-admin", UserID: "u-1", Permissions: []string{"*"}})
	if got, err := f.svc.GetSettings(context.Background(), "t-refuse"); rec.Code != http.StatusOK || err != nil || got.UpdatedBy != "u-1" {
		t.Fatalf("updated_by is the verified caller: %d %s %+v %v", rec.Code, rec.Body, got, err)
	}
}
