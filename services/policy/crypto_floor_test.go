package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

type recordingPublisher struct {
	mu     sync.Mutex
	events []map[string]any
}

func (p *recordingPublisher) Publish(_ context.Context, subject string, raw []byte) error {
	var ev map[string]any
	_ = json.Unmarshal(raw, &ev)
	ev["subject"] = subject
	p.mu.Lock()
	p.events = append(p.events, ev)
	p.mu.Unlock()
	return nil
}

func (p *recordingPublisher) find(subject string) (map[string]any, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, ev := range p.events {
		if ev["subject"] == subject {
			return ev, true
		}
	}
	return nil, false
}

func floorPolicy(tier string) string {
	return `apiVersion: kms.vecta.com/v1
kind: CryptoPolicy
metadata:
  name: nist-floor
  tenant: tenant-a
spec:
  type: algorithm
  minAlgorithmTier: ` + tier + `
  targets:
    selector: {}
  rules:
    - name: noop
      condition: "key.algorithm == NEVER"
      action: warn
`
}

// The floor compares SP 800-57 strengths from pkg/cryptocatalog. Before
// 3.2.0-beta RSA-2048 passed a classical-128 floor (it is 112-bit) and
// HMAC-SHA256 was refused as "deprecated".
func TestCryptoFloorUsesNISTStrengths(t *testing.T) {
	doc, _, err := parsePolicyYAML(floorPolicy("classical-128"))
	if err != nil {
		t.Fatal(err)
	}
	for alg, want := range map[string]Decision{
		"RSA-2048":    DecisionDeny,
		"RSA-3072":    DecisionAllow,
		"HMAC-SHA256": DecisionAllow,
		"Ed25519":     DecisionAllow,
		"ML-DSA-65":   DecisionAllow,
		"3DES":        DecisionDeny,
		"RSA":         DecisionDeny, // not assessed: no key size
	} {
		er := evaluatePolicy(doc, "p1", 1, EvaluatePolicyRequest{TenantID: "tenant-a", Operation: "key.sign", Algorithm: alg})
		if er.Decision != want {
			t.Errorf("%s under classical-128: %s, want %s (%+v)", alg, er.Decision, want, er.Outcomes)
		}
		if want == DecisionDeny && (len(er.Outcomes) != 1 || er.Outcomes[0].RuleName != "crypto-floor") {
			t.Errorf("%s: denial must be the crypto-floor outcome, got %+v", alg, er.Outcomes)
		}
	}
	if er := evaluatePolicy(doc, "p1", 1, EvaluatePolicyRequest{TenantID: "tenant-a", Operation: "key.sign", Algorithm: "RSA-2048"}); !strings.Contains(er.Outcomes[0].Message, "classical-112") {
		t.Errorf("denial should name the algorithm's tier: %q", er.Outcomes[0].Message)
	}
}

// A policy stored with a floor that is not a tier used to enforce nothing;
// it is now refused on create and update, and the refusal is audited.
func TestUnknownFloorRefusedAndAudited(t *testing.T) {
	pub := &recordingPublisher{}
	svc := NewService(newPolicyStore(t), pub)
	_, err := svc.CreatePolicy(context.Background(), CreatePolicyRequest{TenantID: "tenant-a", Actor: "alice", YAML: floorPolicy("classical-100")})
	if err == nil || !strings.Contains(err.Error(), "minAlgorithmTier") {
		t.Fatalf("create with unknown floor: err=%v", err)
	}
	ev, ok := pub.find("audit.policy.floor_refused")
	if !ok {
		t.Fatal("audit.policy.floor_refused not emitted")
	}
	data, _ := ev["data"].(map[string]any)
	if ev["result"] != "refused" || data["reason"] != "invalid_min_algorithm_tier" || data["min_algorithm_tier"] != "classical-100" {
		t.Fatalf("refusal event = %+v", ev)
	}

	created, err := svc.CreatePolicy(context.Background(), CreatePolicyRequest{TenantID: "tenant-a", Actor: "alice", YAML: floorPolicy("classical-112")})
	if err != nil {
		t.Fatalf("create with classical-112: %v", err)
	}
	pub.events = nil
	if _, err := svc.UpdatePolicy(context.Background(), created.ID, UpdatePolicyRequest{TenantID: "tenant-a", Actor: "alice", YAML: floorPolicy("deprecated")}); err == nil {
		t.Fatal("update to a non-floor tier accepted")
	}
	if _, ok := pub.find("audit.policy.floor_refused"); !ok {
		t.Fatal("update refusal not audited")
	}
}

// A floor denial is audited as a refusal naming the crypto-floor rule.
func TestCryptoFloorDenialAudited(t *testing.T) {
	pub := &recordingPublisher{}
	svc := NewService(newPolicyStore(t), pub)
	ctx := context.Background()
	if _, err := svc.CreatePolicy(ctx, CreatePolicyRequest{TenantID: "tenant-a", Actor: "alice", YAML: floorPolicy("classical-128")}); err != nil {
		t.Fatal(err)
	}
	out, err := svc.Evaluate(ctx, EvaluatePolicyRequest{TenantID: "tenant-a", Operation: "key.sign", Algorithm: "RSA-2048", KeyID: "k1"})
	if err != nil || out.Decision != DecisionDeny {
		t.Fatalf("RSA-2048 under classical-128: %+v %v", out, err)
	}
	ev, ok := pub.find("audit.policy.violated")
	if !ok {
		t.Fatal("audit.policy.violated not emitted")
	}
	data, _ := ev["data"].(map[string]any)
	rules, _ := data["rules"].([]any)
	if ev["result"] != "refused" || data["algorithm"] != "RSA-2048" || len(rules) != 1 || rules[0] != "crypto-floor" {
		t.Fatalf("violation event = %+v", ev)
	}
	// The catalogued HIGH-severity event operators alert on
	// (docs/AUTOMATION_ALKM_PQC.md) was never emitted before 3.2.0-beta.
	ev, ok = pub.find("audit.policy.crypto_floor_violation")
	if !ok {
		t.Fatal("audit.policy.crypto_floor_violation not emitted")
	}
	data, _ = ev["data"].(map[string]any)
	if ev["result"] != "refused" || data["tier"] != "classical-112" || data["reason"] != "below_min_algorithm_tier" {
		t.Fatalf("crypto floor event = %+v", ev)
	}
	// An allowed algorithm emits neither.
	pub.events = nil
	if out, _ := svc.Evaluate(ctx, EvaluatePolicyRequest{TenantID: "tenant-a", Operation: "key.sign", Algorithm: "ML-DSA-65"}); out.Decision == DecisionDeny {
		t.Fatalf("ML-DSA-65 denied: %+v", out)
	}
	if _, ok := pub.find("audit.policy.crypto_floor_violation"); ok {
		t.Fatal("floor event emitted for an allowed algorithm")
	}
}
