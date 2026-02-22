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
	if run.Status != "completed" && run.Status != "failed" {
		t.Fatalf("unexpected run: %+v", run)
	}
	keycore.mu.Lock()
	rotated := len(keycore.rotateCalls)
	keycore.mu.Unlock()
	if rotated == 0 {
		t.Fatalf("expected rotate calls")
	}

	rolled, err := svc.RollbackMigrationPlan(ctx, tenantID, plan.ID, "tester")
	if err != nil {
		t.Fatalf("rollback plan: %v", err)
	}
	if rolled.Status != "rolled_back" {
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
