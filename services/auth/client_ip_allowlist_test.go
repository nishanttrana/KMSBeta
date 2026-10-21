package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

// refusedClientToken returns the data of the last audit.auth.client_token_refused
// event, failing the test when none was published.
func refusedClientToken(t *testing.T, pub *mockPublisher) map[string]any {
	t.Helper()
	for i := len(pub.subjects) - 1; i >= 0; i-- {
		if pub.subjects[i] != "audit.auth.client_token_refused" {
			continue
		}
		var evt struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(pub.payloads[i], &evt); err != nil {
			t.Fatal(err)
		}
		return evt.Data
	}
	t.Fatalf("no audit.auth.client_token_refused among %v", pub.subjects)
	return nil
}

// A client's ip_whitelist was stored and shown but never checked until
// 13.41.0-beta: its API key was exchanged for a token from any address.
func TestClientIPAllowListEnforcedAtTokenExchange(t *testing.T) {
	c := newClientAdminHarness(t)
	id, key := c.registerAndActivate(t)
	// httptest requests come from 192.0.2.1.
	if w := c.asAdmin(t, http.MethodPut, "/auth/clients/"+id, `{"ip_whitelist":["10.10.10.0/24"]}`); w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	if code := c.clientToken(t, id, key); code != http.StatusForbidden {
		t.Fatalf("token from outside the allow-list: want 403, got %d", code)
	}
	if evt := refusedClientToken(t, c.pub); evt["code"] != "ip_not_allowed" || evt["result"] != "refused" || evt["source_ip"] != "192.0.2.1" {
		t.Fatalf("refusal audit: %v", evt)
	}
	if w := c.asAdmin(t, http.MethodPut, "/auth/clients/"+id, `{"ip_whitelist":["10.10.10.0/24"," 192.0.2.1 "]}`); w.Code != http.StatusOK {
		t.Fatalf("update: %d %s", w.Code, w.Body.String())
	}
	if code := c.clientToken(t, id, key); code != http.StatusOK {
		t.Fatalf("token from an allowed address: want 200, got %d", code)
	}
}

func TestClientIPAllowListRefusesMalformedEntries(t *testing.T) {
	c := newClientAdminHarness(t)
	id, key := c.registerAndActivate(t)
	for _, body := range []string{`{"ip_whitelist":["10.10.10.0/33"]}`, `{"ip_whitelist":["office-vpn"]}`} {
		if w := c.asAdmin(t, http.MethodPut, "/auth/clients/"+id, body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d %s", body, w.Code, w.Body.String())
		}
	}
	if code := c.clientToken(t, id, key); code != http.StatusOK {
		t.Fatalf("refused update changed the allow-list: token %d", code)
	}
}

func TestClientTokenRefusalsAudited(t *testing.T) {
	c := newClientAdminHarness(t)
	id, key := c.registerAndActivate(t)
	if code := c.clientToken(t, id, key+"x"); code != http.StatusUnauthorized {
		t.Fatalf("wrong key: want 401, got %d", code)
	}
	if evt := refusedClientToken(t, c.pub); evt["reason"] != "invalid api key" || evt["client_id"] != id {
		t.Fatalf("refusal audit: %v", evt)
	}
}
