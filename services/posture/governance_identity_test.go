package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"vecta-kms/pkg/servicetoken"
)

// Governance serves the platform system state to this service's own
// identity only (tenant_id=root); an anonymous call is refused.
func TestGovernanceCallsCarryServiceIdentity(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "kms-posture-jwt", "expires_at": "2099-01-01T00:00:00Z"})
	}))
	defer auth.Close()
	t.Setenv("AUTH_URL", auth.URL)
	t.Setenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET", "3f9c2a7d5e1b8c4f6a0d2e9b7c5a3f1e8d6b4c2a0f9e7d5c3b1a8f6e4d2c0b9a")
	servicetoken.SetDefault(servicetoken.FromEnv("kms-posture"))
	t.Cleanup(func() { servicetoken.SetDefault(nil) })

	var mu sync.Mutex
	var seen []*http.Request
	gov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Clone(context.Background()))
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"state": map[string]any{}})
	}))
	defer gov.Close()

	if err := NewHTTPGovernanceControlClient(gov.URL, "", 0).ApplyPostureControls(context.Background(), PostureControlPatch{}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("governance calls = %d, want 1", len(seen))
	}
	for _, r := range seen {
		if r.URL.Query().Get("tenant_id") != "root" || r.Header.Get("Authorization") != "Bearer kms-posture-jwt" {
			t.Fatalf("%s %s: tenant_id=%q Authorization=%q, want root and the kms-posture service token",
				r.Method, r.URL.Path, r.URL.Query().Get("tenant_id"), r.Header.Get("Authorization"))
		}
	}
}
