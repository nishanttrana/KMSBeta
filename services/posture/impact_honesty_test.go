package main

import "testing"

// A modeled reduction comes from the finding; approval does not inflate it.
func TestActionImpactHasNoInventedFloor(t *testing.T) {
	if got := deriveActionImpact(RemediationAction{ApprovalRequired: true}, Finding{RiskScore: 0}).RiskReduction; got != 0 {
		t.Fatalf("zero-risk finding modeled as %d points", got)
	}
	if got := deriveActionImpact(RemediationAction{}, Finding{RiskScore: 30}).RiskReduction; got != 10 {
		t.Fatalf("risk 30 modeled as %d, want 10", got)
	}
}
