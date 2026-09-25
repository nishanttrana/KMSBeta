package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

// Cluster administration decides where key material goes, so it must require
// a verified root administrator; node-to-node routes authenticate themselves.
func TestClusterRoutesRequireRootAdmin(t *testing.T) {
	tokens := map[string]*pkgauth.Claims{
		"root-admin":   {TenantID: "root", Role: "admin"},
		"tenant-admin": {TenantID: "tenant-a", Role: "admin"},
		"root-viewer":  {TenantID: "root", Role: "readonly"},
		"service":      {TenantID: "root", Role: "client-service", ClientID: "kms-governance", Permissions: []string{"service.internal"}},
	}
	parser := func(raw string) (*pkgauth.Claims, error) {
		if c, ok := tokens[strings.TrimSpace(raw)]; ok {
			return c, nil
		}
		return nil, errors.New("invalid token")
	}
	reached := ""
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = r.URL.Path; w.WriteHeader(http.StatusOK) })
	h := buildClusterHTTPHandler(inner, parser)

	call := func(method, path, token string) int {
		reached = ""
		req := httptest.NewRequest(method, path, strings.NewReader("{}"))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	for _, c := range []struct {
		method, path, token string
		want                int
	}{
		{"POST", "/cluster/join/request", "", http.StatusUnauthorized},
		{"POST", "/cluster/join/request", "bogus", http.StatusUnauthorized},
		{"POST", "/cluster/join/request", "tenant-admin", http.StatusForbidden},
		{"POST", "/cluster/join/request", "root-viewer", http.StatusForbidden},
		{"DELETE", "/cluster/nodes/n1", "tenant-admin", http.StatusForbidden},
		{"POST", "/cluster/join/request", "root-admin", http.StatusOK},
		{"GET", "/cluster/overview", "service", http.StatusOK},
		{"POST", "/cluster/join/exchange", "", http.StatusOK},
		{"POST", "/cluster/sync/events", "", http.StatusOK},
		{"GET", "/healthz", "", http.StatusOK},
	} {
		if got := call(c.method, c.path, c.token); got != c.want {
			t.Errorf("%s %s with %q: got %d, want %d", c.method, c.path, c.token, got, c.want)
		}
	}
	if call("POST", "/cluster/join/request", "tenant-admin"); reached != "" {
		t.Fatal("a refused request must not reach the handler")
	}
}
