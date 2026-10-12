package main

import (
	"net/http"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

// The REST API tab's examples for this service, sent to its real handlers.
func TestRESTExamplesMatchTheService(t *testing.T) {
	h, _, _, _ := newEKMHandler(t)
	admin := &pkgauth.Claims{UserID: "tester", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	routetest.Examples(t, routetest.ExampleSet{
		Service: "ekm",
		// What the other examples act on is registered first.
		First: []string{"ekm-agent-register", "ekm-bitlocker-register", "ekm-tde-create", "ekm-db-register", "ekm-tde-wrap"},
		Skip:  map[string]string{"ekm-bitlocker-network-scan": "it would scan a real network range"},
		Serve: func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), admin)))
		},
	})
}
