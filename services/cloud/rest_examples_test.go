package main

import (
	"net/http"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

// The REST API tab's examples for this service, sent to its real handlers.
// The BYOK routes are on the kernel router, mounted on the handler's mux as
// main does.
func TestRESTExamplesMatchTheService(t *testing.T) {
	h, svc, _, _ := newCloudHandler(t)
	rt, _ := byokRouter(svc)
	rt.MountOn(h.mux)
	admin := &pkgauth.Claims{UserID: "tester", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	routetest.Examples(t, routetest.ExampleSet{Service: "cloud", Serve: func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), admin)))
	}})
}
