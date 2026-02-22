package main

import (
	"context"
	"testing"
)

func TestServiceScanAndSummary(t *testing.T) {
	svc, _, pub := newDiscoveryService(t)
	ctx := context.Background()
	tenantID := "tenant-svc"

	scan, err := svc.StartScan(ctx, ScanRequest{TenantID: tenantID, ScanTypes: []string{"network", "cloud", "certs"}, Trigger: "test"})
	if err != nil {
		t.Fatalf("start scan: %v", err)
	}
	if scan.Status != "completed" {
		t.Fatalf("unexpected scan status: %+v", scan)
	}
	if pub.Count("audit.discovery.scan_initiated") == 0 || pub.Count("audit.discovery.scan_completed") == 0 {
		t.Fatalf("expected discovery scan audit events")
	}
	assets, err := svc.ListAssets(ctx, tenantID, 200, 0, "", "", "")
	if err != nil {
		t.Fatalf("list assets: %v", err)
	}
	if len(assets) == 0 {
		t.Fatalf("expected discovered assets")
	}
	summary, err := svc.Summary(ctx, tenantID)
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if summary.TotalAssets == 0 || summary.PostureScore <= 0 {
		t.Fatalf("unexpected summary: %+v", summary)
	}

	asset := assets[0]
	updated, err := svc.ClassifyAsset(ctx, tenantID, asset.ID, ClassifyRequest{Classification: "strong", Status: "reviewed", Notes: "manual override"})
	if err != nil {
		t.Fatalf("classify asset: %v", err)
	}
	if updated.Classification != "strong" || updated.Status != "reviewed" {
		t.Fatalf("unexpected classified asset: %+v", updated)
	}
	if pub.Count("audit.discovery.asset_classified") == 0 {
		t.Fatalf("expected asset_classified event")
	}
}
