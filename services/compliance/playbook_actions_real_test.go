package main

import (
	"context"
	"log"
	"testing"
)

type recordingOps struct{ assessments, postures int }

func (r *recordingOps) RunAssessment(context.Context, string, string, bool, string) (AssessmentResult, error) {
	r.assessments++
	return AssessmentResult{}, nil
}

func (r *recordingOps) GetPosture(context.Context, string, bool) (PostureSnapshot, error) {
	r.postures++
	return PostureSnapshot{}, nil
}

// Actions that only logged (reported OK) or called endpoints that don't exist
// are refused, at save time and at run time.
func TestPlaybookActionsAreRealOrRefused(t *testing.T) {
	removed := []string{"send_alert", "notify_soc", "disable_access", "send_email", "generate_evidence_report", "create_backup", "quarantine_tenant", "failover_cluster", "enforce_mfa"}
	e := NewPlaybookExecutor(nil, "https://keycore.invalid", "https://certs.invalid", "https://policy.invalid", "https://audit.invalid", nil, log.Default())
	for _, a := range removed {
		if validActionTypes[a] {
			t.Fatalf("%s can still be saved in a playbook", a)
		}
		if err := e.executeAction(context.Background(), PlaybookAction{Type: a}, RunContext{TenantID: "t1", RunID: "r1"}); err == nil {
			t.Fatalf("%s reported success", a)
		}
	}
	ops := &recordingOps{}
	e.ops = ops
	for _, a := range []string{"trigger_assessment", "snapshot_posture"} {
		if err := e.executeAction(context.Background(), PlaybookAction{Type: a}, RunContext{TenantID: "t1", RunID: "r1"}); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
	}
	if ops.assessments != 1 || ops.postures != 1 {
		t.Fatalf("compliance actions did not run: %+v", ops)
	}
	if err := e.executeAction(context.Background(), PlaybookAction{Type: "create_audit_event"}, RunContext{TenantID: "t1"}); err == nil {
		t.Fatal("create_audit_event reported success with no audit client")
	}
}
