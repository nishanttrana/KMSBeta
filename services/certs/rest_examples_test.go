package main

import (
	"net/http"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

// The REST API tab's examples for this service, sent to its real handlers.
func TestRESTExamplesMatchTheService(t *testing.T) {
	h, _ := newCertsHandler(t)
	admin := &pkgauth.Claims{UserID: "tester", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	routetest.Examples(t, routetest.ExampleSet{
		Service: "certs",
		// A certificate needs its CA, and a subscription the CA too.
		First:   []string{"certs-ca-create", "cert-issue", "cert-star-create"},
		Aliases: map[string]string{"cert_id": "certificate_id"},
		Serve: func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), admin)))
		},
	})
}
