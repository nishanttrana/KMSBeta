package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

// The data protection log names the verified caller. It named "dashboard"
// for everyone, or whatever X-Actor said (11.8.0-beta).
func TestAuditActorIsTheVerifiedCaller(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/tokenize", nil)
	req.Header.Set("X-Actor", "ceo")
	req.Header.Set("X-Username", "ceo")
	if got := actorFromRequest(req); got != "" {
		t.Fatalf("a request without a verified token was logged as %q", got)
	}
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), &pkgauth.Claims{UserID: "usr_mallory", TenantID: "t1"}))
	if got := actorFromRequest(req); got != "usr_mallory" {
		t.Fatalf("the actor is the verified caller, not a header: %q", got)
	}
}
