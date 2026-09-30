package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"vecta-kms/pkg/servicetoken"
)

// Audit refuses tokenless callers, so compliance's event reads must carry
// the kms-compliance service token or every assessment sees no events.
func TestAuditReadsCarryServiceIdentity(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "kms-compliance-jwt", "expires_at": "2099-01-01T00:00:00Z"})
	}))
	defer auth.Close()
	t.Setenv("AUTH_URL", auth.URL)
	t.Setenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET", "3f9c2a7d5e1b8c4f6a0d2e9b7c5a3f1e8d6b4c2a0f9e7d5c3b1a8f6e4d2c0b9a")
	servicetoken.SetDefault(servicetoken.FromEnv("kms-compliance"))
	t.Cleanup(func() { servicetoken.SetDefault(nil) })

	audit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kms-compliance-jwt" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "unauthorized"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"id": "evt_1"}}})
	}))
	defer audit.Close()

	items, err := NewHTTPAuditClient(audit.URL, 0).ListEvents(context.Background(), "t1", 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("audit events: %v %v", items, err)
	}
}
