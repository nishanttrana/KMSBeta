package main

import (
	"net/http"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

// The REST API tab's examples for this service, sent to its real handlers.
// The platform SBOM is managed from the platform tenant.
func TestRESTExamplesMatchTheService(t *testing.T) {
	h, _, _, _, _, _ := newSBOMHandler(t)
	root := &pkgauth.Claims{UserID: "root-admin", TenantID: "root", Role: "admin", Permissions: []string{"*"}}
	routetest.Examples(t, routetest.ExampleSet{Service: "sbom", Tenant: "root", Serve: func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), root)))
	}})
}
