package main

import (
	"context"
	"testing"
	"time"
)

func TestPQCStoreFlows(t *testing.T) {
	_, store, _, _ := newPQCService(t)
	ctx := context.Background()
	tenantID := "tenant-store"

	scan := ReadinessScan{
		ID:               "scan1",
		TenantID:         tenantID,
		Status:           "completed",
		TotalAssets:      5,
		PQCReadyAssets:   2,
		HybridAssets:     1,
		ClassicalAssets:  2,
		AverageQSL:       71.5,
		ReadinessScore:   68,
		AlgorithmSummary: map[string]int{"RSA-2048": 2, "ML-DSA-65": 1},
		TimelineStatus:   map[string]interface{}{"cnsa2": "at_risk"},
		RiskItems:        []AssetRisk{{AssetID: "a1", Algorithm: "RSA-2048", Priority: 80}},
		Metadata:         map[string]interface{}{"trigger": "test"},
		CompletedAt:      time.Now().UTC(),
	}
	if err := store.CreateReadinessScan(ctx, scan); err != nil {
		t.Fatalf("create scan: %v", err)
	}
	gotScan, err := store.GetLatestReadinessScan(ctx, tenantID)
	if err != nil {
		t.Fatalf("get latest scan: %v", err)
	}
	if gotScan.ReadinessScore != 68 || gotScan.TotalAssets != 5 {
		t.Fatalf("unexpected scan: %+v", gotScan)
	}

	plan := MigrationPlan{
		ID:               "plan1",
		TenantID:         tenantID,
		Name:             "plan",
		Status:           "planned",
		TargetProfile:    "hybrid-first",
		TimelineStandard: "cnsa2",
		Deadline:         time.Now().Add(24 * time.Hour).UTC(),
		Summary:          map[string]interface{}{"total_steps": 1},
		Steps:            []MigrationStep{{ID: "s1", AssetID: "k1", Status: "pending", Priority: 80}},
		CreatedBy:        "tester",
	}
	if err := store.CreateMigrationPlan(ctx, plan); err != nil {
		t.Fatalf("create plan: %v", err)
	}
	plan.Status = "completed"
	plan.ExecutedAt = time.Now().UTC()
	if err := store.UpdateMigrationPlan(ctx, plan); err != nil {
		t.Fatalf("update plan: %v", err)
	}
	gotPlan, err := store.GetMigrationPlan(ctx, tenantID, plan.ID)
	if err != nil {
		t.Fatalf("get plan: %v", err)
	}
	if gotPlan.Status != "completed" || len(gotPlan.Steps) != 1 {
		t.Fatalf("unexpected plan: %+v", gotPlan)
	}

	run := MigrationRun{ID: "run1", TenantID: tenantID, PlanID: plan.ID, Status: "running", DryRun: true, Summary: map[string]interface{}{"x": 1}}
	if err := store.CreateMigrationRun(ctx, run); err != nil {
		t.Fatalf("create run: %v", err)
	}
	run.Status = "dry_run_completed"
	run.CompletedAt = time.Now().UTC()
	if err := store.UpdateMigrationRun(ctx, run); err != nil {
		t.Fatalf("update run: %v", err)
	}
	runs, err := store.ListMigrationRuns(ctx, tenantID, plan.ID)
	if err != nil {
		t.Fatalf("list runs: %v", err)
	}
	if len(runs) != 1 || runs[0].Status != "dry_run_completed" {
		t.Fatalf("unexpected runs: %+v", runs)
	}
}
