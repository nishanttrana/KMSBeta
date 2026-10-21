package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vecta-kms/pkg/agentauth"
)

// The agents' API-key exchange (pkg/agentauth) against auth's real
// POST /auth/client-token. Until 13.33.0-beta agentauth posted
// {api_key, tenant_id, role} and read {token, expires_in}, which auth never
// accepted, then sent the key as X-API-Key on every call, which no service
// reads.
func TestAgentAuthExchangesAnAPIKeyWithTheRealHandler(t *testing.T) {
	c := newClientAdminHarness(t)
	clientID, apiKey := c.registerAndActivate(t)
	srv := httptest.NewServer(c.h)
	defer srv.Close()

	p, err := agentauth.New(agentauth.Config{APIKey: apiKey, ClientID: clientID, TenantID: "t1", JWTEndpoint: srv.URL + "/auth/client-token"})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://kms.example.com/svc/keycore/keys", nil)
	if err := p.ApplyAuth(req); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	authz := req.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") || req.Header.Get("X-API-Key") != "" {
		t.Fatalf("request carries %q / X-API-Key %q", authz, req.Header.Get("X-API-Key"))
	}
	if _, err := c.h.logic.ParseJWT(strings.TrimPrefix(authz, "Bearer ")); err != nil {
		t.Fatalf("the token auth issued does not verify: %v", err)
	}

	// A wrong key fails the call; nothing is sent in its place.
	bad, _ := agentauth.New(agentauth.Config{APIKey: apiKey + "x", ClientID: clientID, TenantID: "t1", JWTEndpoint: srv.URL + "/auth/client-token"})
	req, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, "https://kms.example.com/svc/keycore/keys", nil)
	if err := bad.ApplyAuth(req); err == nil || req.Header.Get("Authorization") != "" || req.Header.Get("X-API-Key") != "" {
		t.Fatalf("a refused exchange still authenticated the call: %v %v", err, req.Header)
	}
}
