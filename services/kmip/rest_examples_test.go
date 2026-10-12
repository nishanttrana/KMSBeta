package main

import (
	"net/http"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

// The REST API tab's examples for this service's management routes, sent to
// its real handlers. Enrolling a client needs a profile, and a profile the
// certs service, which this handler does not have: those examples show no
// response.
func TestRESTExamplesMatchTheService(t *testing.T) {
	kh, _, _ := newKMIPHandler(t)
	h := kh.HTTPRouter(nil, nil)
	admin := &pkgauth.Claims{UserID: "tester", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	routetest.Examples(t, routetest.ExampleSet{Service: "kmip", Serve: func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), admin)))
	}})
}
