package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
)

// clearJWTKeyEnv removes every source loadJWTParser reads.
func clearJWTKeyEnv(t *testing.T) {
	t.Helper()
	for _, prefix := range []string{"GOVERNANCE_", "KEYCORE_", ""} {
		t.Setenv(prefix+"JWT_PUBLIC_KEY_PEM", "")
		t.Setenv(prefix+"JWT_PUBLIC_KEY_B64", "")
	}
	t.Setenv("JWT_PUBLIC_KEY_PATH", filepath.Join(t.TempDir(), "missing.pem"))
}

// Governance refuses to start without a token-verification key, and loads
// the shared JWT_PUBLIC_KEY_B64 that compose sets (it used not to read it,
// so every compose deployment ran without verification).
func TestMissingJWTKeyRefusesStart(t *testing.T) {
	clearJWTKeyEnv(t)
	if parser, err := loadJWTParser("", ""); err == nil || parser != nil {
		t.Fatalf("no key: parser=%v err=%v, want a refusal", parser != nil, err)
	}
	t.Setenv("JWT_PUBLIC_KEY_B64", base64.StdEncoding.EncodeToString([]byte("not a key")))
	if _, err := loadJWTParser("", ""); err == nil {
		t.Fatal("a malformed key was accepted")
	}

	kp, err := pkgcrypto.GenerateKeyPair(pkgcrypto.AlgRSA2048)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := pkgcrypto.MarshalPublicKeyPEM(kp.Public)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("JWT_PUBLIC_KEY_B64", base64.StdEncoding.EncodeToString(pubPEM))
	parser, err := loadJWTParser("", "")
	if err != nil || parser == nil {
		t.Fatalf("shared JWT_PUBLIC_KEY_B64 not loaded: %v", err)
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, &pkgauth.Claims{
		TenantID: "root", Role: "admin", UserID: "root-admin",
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))},
	}).SignedString(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := parser(signed); err != nil || claims.UserID != "root-admin" {
		t.Fatalf("parser rejected a valid token: %v", err)
	}
}

func newAuthTestHandler(t *testing.T) (*Handler, *capturePublisher) {
	t.Helper()
	pub := &capturePublisher{}
	h := NewHandler(NewService(newGovernanceStore(t), pub, &mockEmailSender{}, &mockCallbackExecutor{}, "http://localhost:8050"))
	h.SetTokenParser(func(token string) (*pkgauth.Claims, error) {
		if token == "valid-root-admin" {
			return &pkgauth.Claims{TenantID: "root", Role: "admin", UserID: "root-admin"}, nil
		}
		return nil, jwt.ErrTokenSignatureInvalid
	})
	return h, pub
}

func lastRefusal(t *testing.T, pub *capturePublisher, subject string) map[string]interface{} {
	t.Helper()
	pub.mu.Lock()
	defer pub.mu.Unlock()
	evs := pub.events[subject]
	if len(evs) == 0 {
		t.Fatalf("no %s event", subject)
	}
	ev := evs[len(evs)-1]
	data, _ := ev["data"].(map[string]interface{})
	if ev["result"] != "refused" || data["result"] != "refused" || data["reason"] == nil {
		t.Fatalf("%s is not a refusal with a reason: %+v", subject, ev)
	}
	return data
}

// Without a token, no system-administration route is reachable, even with
// tenant_id=root; each refusal is audited with its reason.
func TestSystemAdminRoutesRequireVerifiedToken(t *testing.T) {
	h, pub := newAuthTestHandler(t)
	routes := []struct{ method, path, body string }{
		{http.MethodGet, "/governance/backups", ""},
		{http.MethodPost, "/governance/backups", `{"scope":"system"}`},
		{http.MethodPost, "/governance/backups/restore", `{}`},
		{http.MethodDelete, "/governance/backups/bkp_1", ""},
		{http.MethodGet, "/governance/backups/bkp_1/artifact", ""},
		{http.MethodGet, "/governance/backups/bkp_1/key", ""},
		{http.MethodGet, "/governance/system/state", ""},
		{http.MethodPut, "/governance/system/fips-mode", `{"mode":"off","confirm":"off"}`},
	}
	for _, rt := range routes {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(rt.method, rt.path+"?tenant_id=root", strings.NewReader(rt.body)))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without a token: %d, want 401 (%s)", rt.method, rt.path, rr.Code, rr.Body)
		}
		d := lastRefusal(t, pub, "audit.governance.system_admin_refused")
		if d["reason"] != "authentication_required" || d["route"] != rt.method+" "+rt.path || d["authenticated"] != false {
			t.Fatalf("%s %s refusal: %+v", rt.method, rt.path, d)
		}
	}
	if n := len(pub.events["audit.governance.system_admin_refused"]); n != len(routes) {
		t.Fatalf("%d refusals audited for %d requests", n, len(routes))
	}

	// A token that doesn't verify is refused before any route runs.
	req := httptest.NewRequest(http.MethodGet, "/governance/system/state?tenant_id=root", nil)
	req.Header.Set("Authorization", "Bearer forged")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("forged token: %d, want 401", rr.Code)
	}
	if d := lastRefusal(t, pub, "audit.governance.authentication_refused"); d["reason"] != "invalid_token" {
		t.Fatalf("authentication_refused: %+v", d)
	}

	// A verified root administrator gets through.
	req = httptest.NewRequest(http.MethodGet, "/governance/system/fips-mode/impact?tenant_id=root&target=bogus", nil)
	req.Header.Set("Authorization", "Bearer valid-root-admin")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("verified root admin: %d, want the route's own 400 (%s)", rr.Code, rr.Body)
	}
}

// Verified callers without root-admin standing are refused with a reason.
func TestSystemAdminRefusalReasons(t *testing.T) {
	h, pub := newAuthTestHandler(t)
	cases := []struct {
		name, tenant string
		claims       *pkgauth.Claims
		code         int
		reason       string
	}{
		{"no tenant", "", &pkgauth.Claims{TenantID: "root", Role: "admin"}, http.StatusBadRequest, "tenant_required"},
		{"token for another tenant", "root", &pkgauth.Claims{TenantID: "tenant-a", Role: "admin"}, http.StatusForbidden, "tenant_mismatch"},
		{"non-root tenant", "tenant-a", &pkgauth.Claims{TenantID: "tenant-a", Role: "admin"}, http.StatusForbidden, "not_root_tenant"},
		{"not an admin", "root", &pkgauth.Claims{TenantID: "root", Role: "viewer", UserID: "v1"}, http.StatusForbidden, "insufficient_privileges"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodPut, "/governance/system/fips-mode?tenant_id="+tc.tenant, strings.NewReader(`{"mode":"off","confirm":"off"}`))
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), tc.claims))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != tc.code {
			t.Fatalf("%s: %d, want %d (%s)", tc.name, rr.Code, tc.code, rr.Body)
		}
		if d := lastRefusal(t, pub, "audit.governance.system_admin_refused"); d["reason"] != tc.reason || d["authenticated"] != true {
			t.Fatalf("%s: %+v", tc.name, d)
		}
	}
}

// A platform service is admitted on the system-admin routes named for its
// identity in systemAdminServiceCallers, and nowhere else.
func TestSystemAdminServiceCallersAreRouteBound(t *testing.T) {
	h, pub := newAuthTestHandler(t)
	service := func(id string) *pkgauth.Claims {
		c := &pkgauth.Claims{TenantID: "root", Role: "client-service", ClientID: id, Permissions: []string{"service.internal"}}
		c.Subject = id
		return c
	}
	cases := []struct {
		name, method, path, body string
		claims                   *pkgauth.Claims
		admitted                 bool
	}{
		{"keycore reads state", http.MethodGet, "/governance/system/state", "", service("kms-keycore"), true},
		{"policy reads state", http.MethodGet, "/governance/system/state", "", service("kms-policy"), true},
		{"posture applies controls", http.MethodPut, "/governance/system/posture-controls", `{}`, service("kms-posture"), true},
		{"keycore changes FIPS mode", http.MethodPut, "/governance/system/fips-mode", `{"mode":"off","confirm":"off"}`, service("kms-keycore"), false},
		{"keycore lists backups", http.MethodGet, "/governance/backups", "", service("kms-keycore"), false},
		{"posture reads state", http.MethodGet, "/governance/system/state", "", service("kms-posture"), false},
		{"secrets reads state", http.MethodGet, "/governance/system/state", "", service("kms-secrets"), false},
		{"forged client_id without the service permission", http.MethodGet, "/governance/system/state", "",
			&pkgauth.Claims{TenantID: "root", Role: "client-service", ClientID: "kms-keycore"}, false},
	}
	for _, tc := range cases {
		before := len(pub.events["audit.governance.system_admin_refused"])
		req := httptest.NewRequest(tc.method, tc.path+"?tenant_id=root", strings.NewReader(tc.body))
		req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), tc.claims))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		refused := len(pub.events["audit.governance.system_admin_refused"]) > before
		if tc.admitted == refused || (!tc.admitted && rr.Code != http.StatusForbidden) {
			t.Fatalf("%s: status %d, refused=%v, want admitted=%v (%s)", tc.name, rr.Code, refused, tc.admitted, rr.Body)
		}
		if !tc.admitted {
			if d := lastRefusal(t, pub, "audit.governance.system_admin_refused"); d["reason"] != "insufficient_privileges" {
				t.Fatalf("%s: %+v", tc.name, d)
			}
		}
	}
}
