package main

import (
	"context"
	"testing"
	"time"
)

func TestStoreScanAndAssetFlows(t *testing.T) {
	_, store, _ := newDiscoveryService(t)
	ctx := context.Background()
	tenantID := "tenant-store"

	scan := DiscoveryScan{ID: "scan1", TenantID: tenantID, ScanType: "network", Status: "running", Trigger: "manual", Stats: map[string]interface{}{"x": 1}, StartedAt: time.Now().UTC()}
	if err := store.CreateScan(ctx, scan); err != nil {
		t.Fatalf("create scan: %v", err)
	}
	scan.Status = "completed"
	scan.CompletedAt = time.Now().UTC()
	if err := store.UpdateScan(ctx, scan); err != nil {
		t.Fatalf("update scan: %v", err)
	}
	gotScan, err := store.GetScan(ctx, tenantID, scan.ID)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if gotScan.Status != "completed" {
		t.Fatalf("unexpected scan: %+v", gotScan)
	}

	asset := CryptoAsset{ID: "a1", TenantID: tenantID, ScanID: scan.ID, AssetType: "tls_endpoint", Name: "api", Location: "api:443", Source: "network", Algorithm: "RSA-2048", StrengthBits: 2048, Status: "active", Classification: "vulnerable", PQCReady: false, QSLScore: 35, Metadata: map[string]interface{}{"k": "v"}, FirstSeen: time.Now().UTC(), LastSeen: time.Now().UTC()}
	if err := store.UpsertAsset(ctx, asset); err != nil {
		t.Fatalf("upsert asset: %v", err)
	}
	asset.Classification = "weak"
	if err := store.UpsertAsset(ctx, asset); err != nil {
		t.Fatalf("upsert asset update: %v", err)
	}
	gotAsset, err := store.GetAsset(ctx, tenantID, asset.ID)
	if err != nil {
		t.Fatalf("get asset: %v", err)
	}
	if gotAsset.Classification != "weak" {
		t.Fatalf("unexpected asset classification: %+v", gotAsset)
	}
	items, err := store.ListAssets(ctx, tenantID, 10, 0, "network", "", "")
	if err != nil {
		t.Fatalf("list assets: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("unexpected asset count: %d", len(items))
	}
}
