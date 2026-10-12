package main

import (
	"net/http"
	"testing"

	"vecta-kms/pkg/route/routetest"
)

// The REST API tab's examples for this service, sent to its real handlers.
// auth verifies its own tokens, so the caller holds one it issued.
func TestRESTExamplesMatchTheService(t *testing.T) {
	h, logic, _, _ := newTestHandler(t)
	token, _, err := logic.IssueJWT("t1", "tenant-admin", []string{"*"}, "admin-1", false)
	if err != nil {
		t.Fatal(err)
	}
	routetest.Examples(t, routetest.ExampleSet{
		Service: "auth",
		First:   []string{"auth-users-create", "auth-login"}, // a login needs its user
		Serve: func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+token)
			h.ServeHTTP(w, r)
		},
	})
}
