package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"vecta-kms/pkg/servicetoken"
)

// Posture refuses tokenless callers, so reporting's findings and actions
// reads must carry the kms-reporting service token.
func TestPostureCallsCarryServiceIdentity(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["client_id"] != "kms-reporting" {
			http.Error(w, "wrong client", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "kms-reporting-jwt", "expires_at": "2099-01-01T00:00:00Z"})
	}))
	defer auth.Close()
	t.Setenv("AUTH_URL", auth.URL)
	t.Setenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET", "3f9c2a7d5e1b8c4f6a0d2e9b7c5a3f1e8d6b4c2a0f9e7d5c3b1a8f6e4d2c0b9a")
	servicetoken.SetDefault(servicetoken.FromEnv("kms-reporting"))
	t.Cleanup(func() { servicetoken.SetDefault(nil) })

	posture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kms-reporting-jwt" || r.URL.Query().Get("tenant_id") != "t1" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "authentication required"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"id": "x"}}})
	}))
	defer posture.Close()

	c := NewHTTPPostureClient(posture.URL, 0)
	if items, err := c.ListFindings(context.Background(), "t1", 10); err != nil || len(items) != 1 {
		t.Fatalf("findings: %v %v", items, err)
	}
	if items, err := c.ListActions(context.Background(), "t1", 10); err != nil || len(items) != 1 {
		t.Fatalf("actions: %v %v", items, err)
	}
}
