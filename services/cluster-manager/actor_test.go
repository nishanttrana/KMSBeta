package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

// A cluster change is recorded under the verified caller. It was recorded
// under the body's requested_by, or an X-User-* / X-Actor header
// (11.8.0-beta).
func TestClusterChangeActorIsTheVerifiedCaller(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/cluster/nodes", nil)
	for _, h := range []string{"X-User-Email", "X-User-Name", "X-User-ID", "X-Actor"} {
		req.Header.Set(h, "ceo")
	}
	if got := firstActor(req); got != "system" {
		t.Fatalf("a request without a verified token was recorded as %q", got)
	}
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{UserID: "usr_root", TenantID: "root"}))
	if got := firstActor(req); got != "usr_root" {
		t.Fatalf("the actor is the verified caller, not a header: %q", got)
	}
}
