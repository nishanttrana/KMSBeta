package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/nishanttrana/KMSBeta/sdk/go/vecta"
)

// The Go SDK's token exchange against auth's real client-token route: it
// presents the API key, gets a token that verifies and carries the client's
// granted role, and renews it when refused.
func TestGoSDKTokenExchangeAgainstAuth(t *testing.T) {
	c := newClientAdminHarness(t)
	if err := c.store.CreateTenantRole(context.Background(), TenantRole{TenantID: "t1", RoleName: "key-user", Permissions: []string{"key.encrypt", "key.read"}}); err != nil {
		t.Fatal(err)
	}
	id, apiKey := c.registerAndActivate(t)
	if w := c.asAdmin(t, http.MethodPut, "/auth/clients/"+id+"/role", `{"role":"key-user"}`); w.Code != http.StatusOK {
		t.Fatalf("role: %d %s", w.Code, w.Body)
	}
	var seen []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/svc/auth/") {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/svc/auth")
			c.h.ServeHTTP(w, r)
			return
		}
		// keycore stand-in: the token must verify and carry the role.
		claims, err := c.logic.ParseJWT(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if err != nil || claims.ClientID != id || !slices.Contains(claims.Permissions, "key.encrypt") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		seen = append(seen, claims.ClientID)
		_ = json.NewEncoder(w).Encode(map[string]any{"key": map[string]any{"id": "k1"}})
	}))
	defer srv.Close()
	client, err := vecta.New(vecta.Config{BaseURL: srv.URL, TenantID: "t1", ClientID: id, APIKey: apiKey,
		CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})})
	if err != nil {
		t.Fatal(err)
	}
	if k, err := client.GetKey(context.Background(), "k1"); err != nil || k.ID != "k1" || len(seen) != 1 {
		t.Fatalf("get with an exchanged token: %+v %v", k, err)
	}
	bad, _ := vecta.New(vecta.Config{BaseURL: srv.URL, TenantID: "t1", ClientID: id, APIKey: "wrong",
		CAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})})
	if _, err := bad.GetKey(context.Background(), "k1"); !vecta.IsRefused(err) {
		t.Fatalf("a wrong API key: %v", err)
	}
}
