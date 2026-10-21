package main

import (
	"context"
	"net/http"
	"testing"

	"vecta-kms/pkg/route/routetest"
)

// The REST API tab's examples for this service, sent to its real handlers.
// auth verifies its own tokens, so the caller holds one it issued: a root
// administrator, as the tenant list and other tenants are theirs alone.
func TestRESTExamplesMatchTheService(t *testing.T) {
	h, logic, store, _ := newTestHandler(t)
	if err := store.CreateTenant(context.Background(), Tenant{ID: "root", Name: "Root", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := h.ensureTenantDefaults(context.Background(), "root"); err != nil {
		t.Fatal(err)
	}
	token, _, err := logic.IssueJWT("root", "tenant-admin", []string{"*"}, "admin-1", false, "")
	if err != nil {
		t.Fatal(err)
	}
	routetest.Examples(t, routetest.ExampleSet{
		Service: "auth",
		Tenant:  "root",
		First:   []string{"auth-users-create", "auth-login"}, // a login needs its user
		Serve: func(w http.ResponseWriter, r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+token)
			h.ServeHTTP(w, r)
		},
	})
}
