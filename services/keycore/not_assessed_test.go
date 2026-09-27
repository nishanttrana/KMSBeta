package main

import (
	"context"
	"testing"
)

// Scores with nothing behind them are absent, not invented.
func TestComplianceDashboardDoesNotInventScores(t *testing.T) {
	svc, _ := newCaptureService(t)
	dash, err := svc.BuildEnterpriseComplianceDashboard(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := dash.ControlScores["enterprise_controls"]; ok {
		t.Fatalf("control coverage scored with no controls: %+v", dash.ControlScores)
	}
	if _, ok := controlCoverageScore([]EnterpriseControlRecord{{Category: controlCategoryFederationProvider, Status: "active"}}); ok {
		t.Fatal("a preview (stored-only) record counted as a control")
	}
	cost, err := svc.BuildEnterpriseCostOptimization(context.Background(), "t1", 30)
	if err != nil {
		t.Fatal(err)
	}
	if cost.EstimatedOperations != 0 {
		t.Fatalf("operations counted with no usage: %+v", cost)
	}
}
