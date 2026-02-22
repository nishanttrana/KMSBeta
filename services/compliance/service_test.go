package main

import (
	"context"
	"testing"
	"time"
)

func TestServiceRecomputePostureAndFrameworks(t *testing.T) {
	svc, _, keycore, policy, audit, certs, pub := newComplianceService(t)
	ctx := context.Background()

	keycore.keys["tenant-a"] = []map[string]interface{}{
		{"id": "k1", "name": "db-master", "algorithm": "AES-256", "status": "active", "current_version": 3, "ops_total": 120, "approval_required": true, "approval_policy_id": "pol-1"},
		{"id": "k2", "name": "legacy-mac", "algorithm": "3DES", "status": "active", "current_version": 1, "ops_total": 0},
		{"id": "k3", "name": "pqc-key", "algorithm": "ML-KEM-768", "status": "active", "current_version": 1, "ops_total": 5},
	}
	policy.policies["tenant-a"] = []map[string]interface{}{
		{"id": "pol-1", "status": "active"},
	}
	audit.events["tenant-a"] = []map[string]interface{}{
		{"action": "auth.login_failed", "result": "failure", "correlation_id": "c1", "timestamp": time.Now().UTC().Format(time.RFC3339)},
		{"action": "auth.login_failed", "result": "failure", "correlation_id": "c1", "timestamp": time.Now().UTC().Format(time.RFC3339)},
		{"action": "policy.violated", "result": "denied", "correlation_id": "c2", "timestamp": time.Now().UTC().Format(time.RFC3339)},
	}
	audit.stats["tenant-a"] = map[string]interface{}{"critical": 1, "high": 1}
	certs.certs["tenant-a"] = []map[string]interface{}{
		{"id": "cert-1", "algorithm": "RSA-1024-SHA1", "status": "active", "not_after": time.Now().UTC().Add(10 * 24 * time.Hour).Format(time.RFC3339)},
	}

	posture, err := svc.RecomputePosture(ctx, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if posture.OverallScore < 0 || posture.OverallScore > 100 {
		t.Fatalf("overall score out of range: %+v", posture)
	}
	if len(posture.FrameworkScores) < 4 {
		t.Fatalf("expected framework scores, got %+v", posture.FrameworkScores)
	}
	if pub.Count("audit.compliance.posture_calculated") == 0 {
		t.Fatal("expected posture audit event")
	}

	controls, assess, err := svc.GetFrameworkControls(ctx, "tenant-a", frameworkPCIDSS)
	if err != nil {
		t.Fatal(err)
	}
	if len(controls) == 0 || assess.FrameworkID != frameworkPCIDSS {
		t.Fatalf("unexpected framework assessment: %+v controls=%d", assess, len(controls))
	}

	gaps, err := svc.GetFrameworkGaps(ctx, "tenant-a", frameworkPCIDSS)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) == 0 {
		t.Fatal("expected at least one gap due to legacy algorithm")
	}
}

func TestServiceCBOMAndPQCReadiness(t *testing.T) {
	svc, _, keycore, _, _, _, _ := newComplianceService(t)
	ctx := context.Background()

	keycore.keys["tenant-b"] = []map[string]interface{}{
		{"id": "k1", "algorithm": "AES-256"},
		{"id": "k2", "algorithm": "RSA-2048"},
		{"id": "k3", "algorithm": "ML-DSA-65"},
	}

	cbom, err := svc.GenerateCBOM(ctx, "tenant-b")
	if err != nil {
		t.Fatal(err)
	}
	if cbom.TotalAssetCount != 3 {
		t.Fatalf("unexpected cbom count: %+v", cbom)
	}

	readiness, err := svc.CBOMPQCReadiness(ctx, "tenant-b")
	if err != nil {
		t.Fatal(err)
	}
	if extractFloat(readiness["pqc_readiness_percent"]) <= 0 {
		t.Fatalf("expected positive pqc readiness: %+v", readiness)
	}

	diff, err := svc.CBOMDiff(ctx, "tenant-b", time.Now().UTC().Add(-24*time.Hour), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := diff["algorithm_delta"]; !ok {
		t.Fatalf("expected algorithm_delta in diff: %+v", diff)
	}
}

func TestServiceAssessmentRunAndSchedule(t *testing.T) {
	svc, _, keycore, _, _, certs, _ := newComplianceService(t)
	ctx := context.Background()

	keycore.keys["tenant-c"] = []map[string]interface{}{
		{"id": "k1", "algorithm": "RSA-1024", "status": "active", "current_version": 1, "ops_total": 1, "created_at": time.Now().UTC().Add(-500 * 24 * time.Hour).Format(time.RFC3339), "updated_at": time.Now().UTC().Add(-500 * 24 * time.Hour).Format(time.RFC3339)},
	}
	certs.certs["tenant-c"] = []map[string]interface{}{
		{"id": "c1", "algorithm": "RSA-1024-SHA1", "status": "active", "not_after": time.Now().UTC().Add(7 * 24 * time.Hour).Format(time.RFC3339)},
	}

	run, err := svc.RunAssessment(ctx, "tenant-c", "manual", true)
	if err != nil {
		t.Fatal(err)
	}
	if run.OverallScore < 0 || len(run.Findings) == 0 {
		t.Fatalf("unexpected run result: %+v", run)
	}

	sched, err := svc.UpsertAssessmentSchedule(ctx, AssessmentSchedule{
		TenantID:  "tenant-c",
		Enabled:   true,
		Frequency: "daily",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sched.Enabled || sched.NextRunAt.IsZero() {
		t.Fatalf("unexpected schedule: %+v", sched)
	}
}
