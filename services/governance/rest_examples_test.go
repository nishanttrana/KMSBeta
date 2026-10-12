package main

import (
	"net/http"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

// The REST API tab's examples for this service, sent to its real handlers.
// System settings and backups are the root tenant's, so the caller is a root
// administrator.
func TestRESTExamplesMatchTheService(t *testing.T) {
	h, _ := newAuthTestHandler(t)
	root := &pkgauth.Claims{UserID: "root-admin", TenantID: "root", Role: "admin", Permissions: []string{"*"}}
	routetest.Examples(t, routetest.ExampleSet{Service: "governance", Tenant: "root", Serve: func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), root)))
	}})
}
