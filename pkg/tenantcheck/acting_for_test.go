package tenantcheck

import (
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

type httptestRequest struct{ *http.Request }

func asCaller(claims *pkgauth.Claims) *httptestRequest {
	r := httptest.NewRequest("POST", "/x", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 198.51.100.7")
	if claims != nil {
		r = r.WithContext(pkgauth.ContextWithClaims(r.Context(), claims))
	}
	return &httptestRequest{r}
}

// A person is always themselves, whoever they name; only a platform service
// may name the person it acts for; nobody is anybody without a token.
func TestActingForIsTheVerifiedCaller(t *testing.T) {
	user := &pkgauth.Claims{TenantID: "t1", Role: "tenant-admin", UserID: "alice", Permissions: []string{"*"}}
	// An API client carries the role every service identity carries, a kms-
	// name it chose and the platform tenant's name is not enough: the
	// reserved permission is what only the platform grants.
	lookalike := &pkgauth.Claims{TenantID: InternalServiceTenant(), Role: "client-service", ClientID: "kms-mine", Permissions: []string{"*"}}
	service := &pkgauth.Claims{TenantID: InternalServiceTenant(), Role: "client-service", ClientID: "kms-compliance", Permissions: []string{"service.internal"}}

	for _, tc := range []struct {
		name   string
		claims *pkgauth.Claims
		named  string
		want   string
	}{
		{"a person naming somebody else", user, "bob", "alice"},
		{"a person naming nobody", user, "", "alice"},
		{"a client dressed as a service", lookalike, "bob", "kms-mine"},
		{"a platform service naming the person it acts for", service, "bob", "bob"},
		{"a platform service naming nobody", service, " ", "kms-compliance"},
		{"no token", nil, "bob", ""},
	} {
		if got := ActingFor(asCaller(tc.claims).Context(), tc.named); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The requester of something others approve is the caller at the address the
// edge saw; what the caller wrote about either is dropped.
func TestRequesterIsNotWhatTheCallerWrote(t *testing.T) {
	user := &pkgauth.Claims{TenantID: "t1", Role: "tenant-admin", UserID: "alice", Permissions: []string{"*"}}
	id, email, ip := Requester(asCaller(user).Request, "bob", "bob@example.com", "10.0.0.1")
	if id != "alice" || email != "" || ip != "198.51.100.7" {
		t.Fatalf("a person's requester: got %q %q %q", id, email, ip)
	}
	service := &pkgauth.Claims{TenantID: InternalServiceTenant(), Role: "client-service", ClientID: "kms-compliance", Permissions: []string{"service.internal"}}
	id, email, ip = Requester(asCaller(service).Request, "bob", "bob@example.com", "10.0.0.1")
	if id != "bob" || email != "bob@example.com" || ip != "10.0.0.1" {
		t.Fatalf("a platform service states who it acts for: got %q %q %q", id, email, ip)
	}
	id, _, ip = Requester(asCaller(service).Request, "", "", "")
	if id != "kms-compliance" || ip != "198.51.100.7" {
		t.Fatalf("a platform service stating nothing is itself: got %q %q", id, ip)
	}
	if id, email, _ := Requester(asCaller(nil).Request, "bob", "bob@example.com", ""); id != "" || email != "" {
		t.Fatalf("no token: got %q %q", id, email)
	}
}
