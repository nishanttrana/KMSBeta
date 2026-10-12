package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route/routetest"
)

// The REST API tab's examples for this service, sent to its real handlers.
// Tokenizing needs a vault, which no example creates: one is made first.
func TestRESTExamplesMatchTheService(t *testing.T) {
	h, _, _ := newDataProtectHandler(t)
	admin := &pkgauth.Claims{UserID: "tester", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}
	serve := func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), admin)))
	}
	rr := httptest.NewRecorder()
	serve(rr, httptest.NewRequest(http.MethodPost, "/token-vaults", strings.NewReader(`{"tenant_id":"t1","name":"card-vault","token_type":"credit_card","format":"deterministic","key_id":"key-1"}`)))
	var made struct {
		Vault struct {
			ID string `json:"id"`
		} `json:"vault"`
	}
	if _ = json.Unmarshal(rr.Body.Bytes(), &made); rr.Code != http.StatusCreated || made.Vault.ID == "" {
		t.Fatalf("create vault: %d %s", rr.Code, rr.Body)
	}
	routetest.Examples(t, routetest.ExampleSet{
		Service: "dataprotect", Serve: serve,
		Values: map[string]string{"vault_id": made.Vault.ID, "key_id": "key-1"},
		First:  []string{"dataprotect-tokenize", "dataprotect-envelope-encrypt"},
	})
}
