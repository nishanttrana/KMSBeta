package main

import (
	"context"
	"testing"
)

func TestStorePostureAndAssessments(t *testing.T) {
	_, store, _, _, _, _, _ := newComplianceService(t)
	ctx := context.Background()

	posture := PostureSnapshot{
		ID:               "p1",
		TenantID:         "tenant-1",
		OverallScore:     78,
		KeyHygiene:       80,
		PolicyCompliance: 70,
		AccessSecurity:   75,
		CryptoPosture:    88,
		PQCReadiness:     60,
		FrameworkScores:  map[string]int{frameworkPCIDSS: 75},
		Metrics:          map[string]float64{"qsl_avg": 82.5},
		GapCount:         3,
	}
	if err := store.CreatePostureSnapshot(ctx, posture); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetLatestPosture(ctx, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.OverallScore != 78 || got.GapCount != 3 {
		t.Fatalf("unexpected posture: %+v", got)
	}

	assess := FrameworkAssessment{
		ID:          "fa1",
		TenantID:    "tenant-1",
		FrameworkID: frameworkPCIDSS,
		Score:       74,
		Status:      "at_risk",
		Controls: []FrameworkControl{
			{ID: "c1", Title: "ctrl", Category: "key_hygiene", Status: "partial", Score: 74},
		},
		Gaps: []ComplianceGap{
			{ID: "g1", TenantID: "tenant-1", FrameworkID: frameworkPCIDSS, ControlID: "c1", Severity: "high", Title: "gap", Description: "desc", Status: "open"},
		},
		PQCReady: 55,
		QSLAvg:   80,
	}
	if err := store.UpsertFrameworkAssessment(ctx, assess); err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceFrameworkGaps(ctx, "tenant-1", frameworkPCIDSS, assess.Gaps); err != nil {
		t.Fatal(err)
	}
	gotAssess, err := store.GetFrameworkAssessment(ctx, "tenant-1", frameworkPCIDSS)
	if err != nil {
		t.Fatal(err)
	}
	if gotAssess.Score != 74 {
		t.Fatalf("unexpected assessment: %+v", gotAssess)
	}
	gaps, err := store.ListFrameworkGaps(ctx, "tenant-1", frameworkPCIDSS)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 1 || gaps[0].ID != "g1" {
		t.Fatalf("unexpected gaps: %+v", gaps)
	}
}

func TestStoreCBOMSnapshots(t *testing.T) {
	_, store, _, _, _, _, _ := newComplianceService(t)
	ctx := context.Background()

	if err := store.SaveCBOMSnapshot(ctx, CBOMSnapshot{
		ID:           "cb1",
		TenantID:     "tenant-2",
		SummaryJSON:  `{"algorithm_summary":{"AES-256":2},"deprecated_count":0,"pqc_readiness_percent":50}`,
		DocumentJSON: `{"tenant_id":"tenant-2"}`,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetLatestCBOMSnapshot(ctx, "tenant-2")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "cb1" {
		t.Fatalf("unexpected cbom snapshot: %+v", got)
	}
	items, err := store.ListCBOMSnapshots(ctx, "tenant-2", parseTimeString(""), parseTimeString(""), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one cbom snapshot got %d", len(items))
	}
}

func TestStoreAssessmentRunsAndSchedule(t *testing.T) {
	_, store, _, _, _, _, _ := newComplianceService(t)
	ctx := context.Background()

	run := AssessmentResult{
		ID:              "a1",
		TenantID:        "tenant-3",
		Trigger:         "manual",
		TemplateID:      "default",
		TemplateName:    "Built-in Baseline",
		OverallScore:    81,
		FrameworkScores: map[string]int{frameworkFIPS: 90},
		Findings:        []AssessmentFinding{{ID: "f1", Severity: "warning", Title: "sample", Fix: "fix", Count: 1}},
		PQC:             AssessmentPQC{ReadyPercent: 33.3, Pending: 2, TotalEvaluated: 3},
		CertMetrics:     map[string]float64{"cert_total": 4},
		Posture: PostureSnapshot{
			ID:           "p1",
			TenantID:     "tenant-3",
			OverallScore: 81,
		},
	}
	if err := store.CreateAssessmentRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	runs, err := store.ListAssessmentRuns(ctx, "tenant-3", "default", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].ID != "a1" {
		t.Fatalf("unexpected assessment runs: %+v", runs)
	}
	if runs[0].TemplateID != "default" {
		t.Fatalf("unexpected template id: %+v", runs[0])
	}

	sched, err := store.GetAssessmentSchedule(ctx, "tenant-3")
	if err != nil {
		t.Fatal(err)
	}
	if sched.Enabled {
		t.Fatalf("unexpected default schedule: %+v", sched)
	}
	sched.Enabled = true
	sched.Frequency = "daily"
	sched.NextRunAt = parseTimeString("2026-02-22T00:00:00Z")
	if err := store.UpsertAssessmentSchedule(ctx, sched); err != nil {
		t.Fatal(err)
	}

	due, err := store.ListDueAssessmentSchedules(ctx, parseTimeString("2026-02-23T00:00:00Z"), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].TenantID != "tenant-3" {
		t.Fatalf("unexpected due schedules: %+v", due)
	}
}

func TestStoreComplianceTemplates(t *testing.T) {
	_, store, _, _, _, _, _ := newComplianceService(t)
	ctx := context.Background()

	tpl := ComplianceTemplate{
		ID:          "tpl-1",
		TenantID:    "tenant-5",
		Name:        "Custom PCI Focus",
		Description: "Higher PCI emphasis",
		Enabled:     true,
		Frameworks: []ComplianceTemplateFramework{
			{
				FrameworkID: frameworkPCIDSS,
				Label:       "PCI DSS 4.0",
				Enabled:     true,
				Weight:      2,
				Controls: []ComplianceTemplateControl{
					{ID: "pci-3.6.4", Title: "Rotation", Category: "key_hygiene", Requirement: "rotate", Enabled: true, Weight: 2, Threshold: 85},
				},
			},
		},
	}
	if err := store.UpsertComplianceTemplate(ctx, tpl); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetComplianceTemplate(ctx, "tenant-5", "tpl-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != tpl.Name || len(got.Frameworks) != 1 {
		t.Fatalf("unexpected template: %+v", got)
	}
	items, err := store.ListComplianceTemplates(ctx, "tenant-5")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != "tpl-1" {
		t.Fatalf("unexpected list output: %+v", items)
	}
	if err := store.DeleteComplianceTemplate(ctx, "tenant-5", "tpl-1"); err != nil {
		t.Fatal(err)
	}
}
