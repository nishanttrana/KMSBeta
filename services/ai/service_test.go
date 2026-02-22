package main

import (
	"context"
	"testing"
)

func TestServiceQueryAndRedaction(t *testing.T) {
	svc, store, llm, pub := newAIService(t)
	llm.text = "Here is a token: sk-secret1234567890 and encrypted_material: 0123456789abcdef0123456789abcdef"

	_, err := svc.UpdateConfig(context.Background(), "tenant-q", AIConfigUpdate{
		Backend:         "openai",
		Endpoint:        "https://api.example.test/v1/chat/completions",
		Model:           "gpt-4o-mini",
		RedactionFields: []string{"encrypted_material", "wrapped_dek", "pwd_hash"},
	})
	if err != nil {
		t.Fatalf("update config: %v", err)
	}

	out, err := svc.Query(context.Background(), QueryRequest{
		TenantID:       "tenant-q",
		Query:          "show weak keys",
		IncludeContext: true,
	})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if out.Action != "query" {
		t.Fatalf("unexpected action: %+v", out)
	}
	if out.RedactionsApplied <= 0 {
		t.Fatalf("expected redactions to be applied")
	}
	if out.Context == nil {
		t.Fatalf("expected context in response")
	}
	keys, _ := out.Context["keys"].([]interface{})
	if len(keys) == 0 {
		t.Fatalf("expected keys in context")
	}
	firstKey, _ := keys[0].(map[string]interface{})
	if _, ok := firstKey["encrypted_material"]; ok {
		t.Fatalf("expected encrypted_material to be removed from context: %+v", firstKey)
	}
	if pub.Count("audit.ai.query") == 0 || pub.Count("audit.ai.query_completed") == 0 {
		t.Fatalf("expected audit query events")
	}
	items, err := store.ListRecentInteractions(context.Background(), "tenant-q", 10)
	if err != nil {
		t.Fatalf("list interactions: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("expected interactions to be persisted")
	}
}

func TestServiceFallbackWhenLLMUnavailable(t *testing.T) {
	svc, _, llm, _ := newAIService(t)
	llm.err = errUnavailable()
	_, err := svc.UpdateConfig(context.Background(), "tenant-fallback", AIConfigUpdate{
		Backend:  "claude",
		Endpoint: "https://api.invalid.local",
	})
	if err != nil {
		t.Fatalf("update config: %v", err)
	}
	out, err := svc.RecommendPosture(context.Background(), PostureRecommendationRequest{
		TenantID: "tenant-fallback",
	})
	if err != nil {
		t.Fatalf("recommend posture: %v", err)
	}
	if out.Backend != "fallback" {
		t.Fatalf("expected fallback backend, got %s", out.Backend)
	}
	if len(out.Warnings) == 0 {
		t.Fatalf("expected warning for unavailable llm")
	}
}

func TestServiceExplainPolicy(t *testing.T) {
	svc, _, _, _ := newAIService(t)
	out, err := svc.ExplainPolicy(context.Background(), PolicyExplainRequest{
		TenantID: "tenant-pol",
		Policy: map[string]interface{}{
			"id":      "policy-1",
			"name":    "rotate-90d",
			"status":  "active",
			"version": 1,
		},
	})
	if err != nil {
		t.Fatalf("explain policy: %v", err)
	}
	if out.Action != "policy_explanation" {
		t.Fatalf("unexpected action: %s", out.Action)
	}
}
