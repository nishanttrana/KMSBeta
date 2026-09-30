package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

func gateParser(raw string) (*pkgauth.Claims, error) {
	if raw != "valid-token" {
		return nil, errors.New("invalid")
	}
	return &pkgauth.Claims{UserID: "alice", TenantID: "t1", Role: "operator"}, nil
}

func newGatedHandler(t *testing.T) (http.Handler, *nopDataProtectPublisher) {
	t.Helper()
	svc, _, pub := newDataProtectService(t)
	h, err := NewAuthenticatedHandler(svc, gateParser)
	if err != nil {
		t.Fatal(err)
	}
	return h, pub
}

func TestAuthenticatedHandlerNeedsAParser(t *testing.T) {
	svc, _, _ := newDataProtectService(t)
	if _, err := NewAuthenticatedHandler(svc, nil); err == nil {
		t.Fatal("a handler without a token parser must not be built")
	}
}

// Until 7.2.0-beta a tokenless POST /fpe/encrypt returned ciphertext.
func TestUnauthenticatedRequestsAreRefusedAndAudited(t *testing.T) {
	h, pub := newGatedHandler(t)
	fpe := `{"tenant_id":"t1","key_id":"key-1","algorithm":"FF1","radix":10,"tweak":"abcd","plaintext":"1234567890"}`
	cases := []struct {
		name, method, path, body, reason string
		header                           map[string]string
	}{
		{"no token", http.MethodPost, "/fpe/encrypt?tenant_id=t1", fpe, "unauthenticated", nil},
		{"bad token", http.MethodPost, "/fpe/encrypt?tenant_id=t1", fpe, "invalid_token", map[string]string{"Authorization": "Bearer forged"}},
		{"not bearer", http.MethodPost, "/tokenize?tenant_id=t1", `{}`, "invalid_token", map[string]string{"Authorization": "valid-token"}},
		{"wrapper token off the wrapper routes", http.MethodPost, "/fpe/decrypt?tenant_id=t1", fpe, "unauthenticated", map[string]string{"X-Wrapper-Token": "w"}},
		{"registration needs an operator", http.MethodPost, "/field-encryption/register/complete?tenant_id=t1", `{}`, "unauthenticated", map[string]string{"X-Wrapper-Token": "w"}},
		{"resolve without a wrapper", http.MethodGet, "/field-protection/resolve?tenant_id=t1&app_id=a&wrapper_id=*", ``, "unauthenticated", map[string]string{"X-Wrapper-Token": "w"}},
		{"lease without a wrapper token", http.MethodPost, "/field-encryption/leases?tenant_id=t1", `{}`, "unauthenticated", nil},
	}
	for _, c := range cases {
		before := pub.Count("audit.dataprotect.request_refused")
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		for k, v := range c.header {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized || strings.Contains(rr.Body.String(), "ciphertext") {
			t.Fatalf("%s: %d %s", c.name, rr.Code, rr.Body)
		}
		if pub.Count("audit.dataprotect.request_refused") != before+1 {
			t.Fatalf("%s: refusal not audited", c.name)
		}
		if d := pub.Data("audit.dataprotect.request_refused"); d["reason"] != c.reason || d["result"] != "refused" {
			t.Fatalf("%s: audited %+v", c.name, d)
		}
	}
}

// A verified token reaches the context raw, so delegation.Attach forwards it
// to keycore and the key is used as the user (KEY_ACCESS_MODEL.md section 5).
func TestVerifiedTokenReachesTheService(t *testing.T) {
	svc, _, pub := newDataProtectService(t)
	h, err := NewAuthenticatedHandler(svc, gateParser)
	if err != nil {
		t.Fatal(err)
	}
	// A v2 key with AES-GCM works in every FIPS mode.
	addNewKey(t, svc, "key-gate-v2")
	req := httptest.NewRequest(http.MethodPost, "/app/encrypt-fields?tenant_id=t1", strings.NewReader(`{"tenant_id":"t1","document_id":"doc-1","document":{"email":"bob@example.com"},"fields":["$.email"],"key_id":"key-gate-v2","algorithm":"AES-GCM"}`))
	req.Header.Set("Authorization", "Bearer valid-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("authenticated encrypt-fields: %d %s", rr.Code, rr.Body)
	}
	if pub.Count("audit.dataprotect.request_refused") != 0 {
		t.Fatal("an authenticated call was audited as refused")
	}
	kc := fakeKeycore(t, svc)
	if len(kc.tokens) == 0 || kc.tokens[len(kc.tokens)-1] != "valid-token" {
		t.Fatalf("keycore call carried tokens %q, want the caller's verified token", kc.tokens)
	}
}

// Wrapper runtime calls pass the gate on their wrapper token alone and are
// then decided by the service's own wrapper-token check.
func TestWrapperRuntimeRoutesReachTheWrapperCheck(t *testing.T) {
	h, pub := newGatedHandler(t)
	for _, path := range []string{"/field-encryption/leases?tenant_id=t1", "/field-encryption/receipts?tenant_id=t1", "/field-encryption/leases/lease_1/renew?tenant_id=t1"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"tenant_id":"t1","wrapper_id":"missing","key_id":"key-1"}`))
		req.Header.Set("X-Wrapper-Token", "not-a-wrapper-jwt")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code == http.StatusOK || rr.Code == http.StatusCreated || rr.Code == http.StatusUnauthorized && strings.Contains(rr.Body.String(), "authentication required") {
			t.Fatalf("POST %s: %d %s", path, rr.Code, rr.Body)
		}
	}
	if pub.Count("audit.dataprotect.request_refused") != 0 {
		t.Fatal("wrapper calls were refused by the gate instead of the wrapper check")
	}
}
