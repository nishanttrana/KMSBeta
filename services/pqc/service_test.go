package main

import (
	"context"
	"testing"
)

func TestPQCServiceReadinessPlanExecuteRollback(t *testing.T) {
	svc, _, pub, keycore := newPQCService(t)
	ctx := context.Background()
	tenantID := "tenant-svc"

	scan, err := svc.StartReadinessScan(ctx, ScanRequest{TenantID: tenantID, Trigger: "test"})
	if err != nil {
		t.Fatalf("start scan: %v", err)
	}
	if scan.Status != "completed" || scan.TotalAssets == 0 {
		t.Fatalf("unexpected scan: %+v", scan)
	}
	if pub.Count("audit.pqc.scan_initiated") == 0 || pub.Count("audit.pqc.scan_completed") == 0 {
		t.Fatalf("expected scan audit events")
	}

	policy, err := svc.GetPolicy(ctx, tenantID)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if policy.ProfileID == "" || policy.InterfaceDefaultMode == "" {
		t.Fatalf("unexpected default policy: %+v", policy)
	}
	updatedPolicy, err := svc.UpdatePolicy(ctx, PQCPolicy{
		TenantID:               tenantID,
		ProfileID:              "quantum_first",
		DefaultKEM:             "ML-KEM-1024",
		DefaultSignature:       "ML-DSA-87",
		InterfaceDefaultMode:   "pqc_only",
		CertificateDefaultMode: "pqc_only",
		HQCBackupEnabled:       true,
		FlagClassicalUsage:     true,
		FlagClassicalCerts:     true,
		FlagNonMigratedIfaces:  true,
		RequirePQCForNewKeys:   true,
		UpdatedBy:              "tester",
	})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}
	if updatedPolicy.ProfileID != "quantum_first" || updatedPolicy.DefaultSignature != "ML-DSA-87" {
		t.Fatalf("unexpected updated policy: %+v", updatedPolicy)
	}
	inventory, err := svc.GetInventory(ctx, tenantID)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if inventory.Keys.Total == 0 || inventory.Interfaces.Total == 0 || inventory.Certificates.Total == 0 {
		t.Fatalf("unexpected inventory: %+v", inventory)
	}
	if len(inventory.NonMigratedInterfaces) == 0 || len(inventory.NonMigratedCertificates) == 0 {
		t.Fatalf("expected migration gaps: %+v", inventory)
	}
	report, err := svc.GetMigrationReport(ctx, tenantID)
	if err != nil {
		t.Fatalf("migration report: %v", err)
	}
	if report.Inventory.ReadinessScore <= 0 || len(report.TopRisks) == 0 || len(report.Timeline) == 0 {
		t.Fatalf("unexpected migration report: %+v", report)
	}

	plan, err := svc.CreateMigrationPlan(ctx, PlanRequest{TenantID: tenantID, Name: "plan", CreatedBy: "tester"})
	if err != nil {
		t.Fatalf("create plan: %v", err)
	}
	if len(plan.Steps) == 0 {
		t.Fatalf("expected migration steps")
	}
	if pub.Count("audit.pqc.migration_planned") == 0 {
		t.Fatalf("expected migration planned audit event")
	}

	run, err := svc.ExecuteMigrationPlan(ctx, tenantID, plan.ID, ExecuteRequest{TenantID: tenantID, Actor: "tester", DryRun: false})
	if err != nil {
		t.Fatalf("execute plan: %v", err)
	}
	// Key steps change keys in keycore; certificate and interface steps are
	// manual and never reported as done.
	if run.Status != "manual_steps_remaining" {
		t.Fatalf("unexpected run: %+v", run)
	}
	after, _ := svc.GetMigrationPlan(ctx, tenantID, plan.ID)
	successors, rotated := 0, 0
	for _, step := range after.Steps {
		switch step.Status {
		case "successor_created":
			successors++
			if step.Metadata["successor_key_id"] == nil {
				t.Fatalf("successor step without a key id: %+v", step)
			}
		case "rotated":
			rotated++
			if step.TargetAlg != step.CurrentAlg {
				t.Fatalf("rotation reported as migration to %s: %+v", step.TargetAlg, step)
			}
		case "manual_required":
			if isKeyAsset(step.AssetType) {
				t.Fatalf("key step left manual: %+v", step)
			}
		default:
			t.Fatalf("step status %q: %+v", step.Status, step)
		}
	}
	keycore.mu.Lock()
	created := keycore.created
	keycore.mu.Unlock()
	if successors == 0 || len(created) != successors {
		t.Fatalf("successors %d, keycore creates %d", successors, len(created))
	}
	// One step event per key actually changed; manual steps emit none.
	if n := pub.Count("audit.pqc.migration_step_executed"); n != successors+rotated {
		t.Fatalf("migration_step_executed %d, want %d (steps that changed a key)", n, successors+rotated)
	}
	for _, req := range created {
		if req["algorithm"] != "ML-DSA-65" && req["algorithm"] != "ML-KEM-768" {
			t.Fatalf("successor algorithm %v", req["algorithm"])
		}
	}

	rolled, err := svc.RollbackMigrationPlan(ctx, tenantID, plan.ID, "tester")
	if err != nil {
		t.Fatalf("rollback plan: %v", err)
	}
	keycore.mu.Lock()
	deactivated := len(keycore.deactivateCalls)
	keycore.mu.Unlock()
	if deactivated != successors {
		t.Fatalf("rollback deactivated %d of %d successor keys", deactivated, successors)
	}
	if rolled.Status != "rolled_back" && rolled.Status != "partially_rolled_back" {
		t.Fatalf("unexpected rollback status: %+v", rolled)
	}
	if pub.Count("audit.pqc.migration_rolled_back") == 0 {
		t.Fatalf("expected rollback audit event")
	}
}

func TestPQCTimelineAndCBOM(t *testing.T) {
	svc, _, _, _ := newPQCService(t)
	ctx := context.Background()
	tenantID := "tenant-timeline"

	if _, err := svc.StartReadinessScan(ctx, ScanRequest{TenantID: tenantID, Trigger: "test"}); err != nil {
		t.Fatalf("start scan: %v", err)
	}
	milestones, readiness, err := svc.Timeline(ctx, tenantID)
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	if len(milestones) == 0 || readiness.ReadinessScore <= 0 {
		t.Fatalf("unexpected timeline readiness: milestones=%d readiness=%+v", len(milestones), readiness)
	}
	doc, err := svc.ExportCBOM(ctx, tenantID)
	if err != nil {
		t.Fatalf("export cbom: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" {
		t.Fatalf("unexpected cbom format: %+v", doc)
	}
}
