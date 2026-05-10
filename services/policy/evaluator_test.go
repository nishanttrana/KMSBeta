package main

import "testing"

func TestParsePolicyYAMLAndEvaluateDeny(t *testing.T) {
	raw := `
apiVersion: kms.vecta.com/v1
kind: CryptoPolicy
metadata:
  name: deny-non-aes
  tenant: tenant-a
spec:
  type: algorithm
  targets:
    selector:
      status: active
  rules:
    - name: algorithm-check
      condition: "key.algorithm != AES-256"
      action: enforce
      message: "Only AES-256 allowed"
`
	doc, _, err := parsePolicyYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	er := evaluatePolicy(doc, "p1", 1, EvaluatePolicyRequest{
		TenantID:  "tenant-a",
		Operation: "key.encrypt",
		Algorithm: "3DES",
		Purpose:   "encrypt",
		KeyStatus: "active",
		OpsTotal:  10,
		OpsLimit:  100,
		IVMode:    "internal",
		KeyID:     "k1",
		Labels:    map[string]any{},
	})
	if er.Decision != DecisionDeny {
		t.Fatalf("expected DENY, got %s", er.Decision)
	}
	if len(er.Outcomes) != 1 {
		t.Fatalf("expected 1 outcome, got %d", len(er.Outcomes))
	}
}

func TestEvaluateWarnRule(t *testing.T) {
	raw := `
apiVersion: kms.vecta.com/v1
kind: CryptoPolicy
metadata:
  name: rotation-warning
  tenant: tenant-a
spec:
  type: rotation
  targets:
    selector: {}
  rules:
    - name: near-expiry
      condition: "key.days_since_rotation > 80"
      action: warn
      message: "Rotate soon"
`
	doc, _, err := parsePolicyYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	er := evaluatePolicy(doc, "p1", 1, EvaluatePolicyRequest{
		TenantID:          "tenant-a",
		Operation:         "key.encrypt",
		DaysSinceRotation: 81,
	})
	if er.Decision != DecisionWarn {
		t.Fatalf("expected WARN, got %s", er.Decision)
	}
	if len(er.Outcomes) != 1 || er.Outcomes[0].Message == "" {
		t.Fatalf("unexpected outcomes %#v", er.Outcomes)
	}
}
