package main

import (
	"net/http"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

// The REST API tab's examples for this service, sent to its real handlers.
// They are written for the root tenant, whose trust domain the settings
// example sets before a workload is registered under it.
func TestRESTExamplesMatchTheService(t *testing.T) {
	h := newFixture(t).h
	root := &pkgauth.Claims{UserID: "tester", TenantID: "root", Role: "admin", Permissions: []string{"*"}}
	routetest.Examples(t, routetest.ExampleSet{
		Service: "workload", Tenant: "root",
		First: []string{"workload-put-workload-identity-settings", "workload-post-workload-identity-registrations", "workload-post-workload-identity-issue"},
		Serve: func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), root)))
		},
	})
}
