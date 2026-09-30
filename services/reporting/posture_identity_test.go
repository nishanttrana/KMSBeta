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

// Audit and compliance refuse tokenless callers too. Before 7.6.0-beta the
// audit reads went out without a token, every alert sync failed on audit's
// plain-text 401, and the Alert Center stayed empty.
func TestAuditAndComplianceCallsCarryServiceIdentity(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "kms-reporting-jwt", "expires_at": "2099-01-01T00:00:00Z"})
	}))
	defer auth.Close()
	t.Setenv("AUTH_URL", auth.URL)
	t.Setenv("INTERNAL_SERVICE_BOOTSTRAP_SECRET", "3f9c2a7d5e1b8c4f6a0d2e9b7c5a3f1e8d6b4c2a0f9e7d5c3b1a8f6e4d2c0b9a")
	servicetoken.SetDefault(servicetoken.FromEnv("kms-reporting"))
	t.Cleanup(func() { servicetoken.SetDefault(nil) })

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kms-reporting-jwt" || r.URL.Query().Get("tenant_id") != "t1" {
			http.Error(w, "unauthorized", http.StatusUnauthorized) // the JWT gate's plain-text answer
			return
		}
		switch r.URL.Path {
		case "/audit/events":
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{map[string]any{"id": "evt_1"}}})
		case "/compliance/posture":
			_ = json.NewEncoder(w).Encode(map[string]any{"posture": map[string]any{"overall_score": 80}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	if items, err := NewHTTPAuditClient(upstream.URL, 0).ListEvents(context.Background(), "t1", 10); err != nil || len(items) != 1 {
		t.Fatalf("audit events: %v %v", items, err)
	}
	if p, err := NewHTTPComplianceClient(upstream.URL, 0).GetPosture(context.Background(), "t1"); err != nil || p["overall_score"] == nil {
		t.Fatalf("compliance posture: %v %v", p, err)
	}

	// A refusal reads as one, not as a JSON syntax error.
	servicetoken.SetDefault(nil)
	_, err := NewHTTPAuditClient(upstream.URL, 0).ListEvents(context.Background(), "t1", 10)
	if err == nil || err.Error() != "401 Unauthorized: request failed" {
		t.Fatalf("tokenless audit read: got %v", err)
	}
}
