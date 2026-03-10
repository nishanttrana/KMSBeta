package main

import (
	"context"
	"testing"
	"time"
)

func TestStoreSBOMSnapshotCRUD(t *testing.T) {
	_, store, _, _, _, _ := newSBOMService(t)

	item := SBOMSnapshot{
		ID:         "sbom_test_1",
		SourceHash: "hash-a",
		Document: SBOMDocument{
			Format:      "cyclonedx",
			SpecVersion: "1.6",
			GeneratedAt: time.Now().UTC(),
			Appliance:   "vecta-kms",
			Components: []BOMComponent{
				{Name: "mod/a", Version: "v1.0.0", Type: "library"},
			},
		},
		Summary: map[string]interface{}{"component_count": 1},
	}
	if err := store.SaveSBOMSnapshot(context.Background(), item); err != nil {
		t.Fatalf("save sbom snapshot: %v", err)
	}

	got, err := store.GetSBOMSnapshotByID(context.Background(), item.ID)
	if err != nil {
		t.Fatalf("get sbom snapshot: %v", err)
	}
	if got.ID != item.ID || len(got.Document.Components) != 1 {
		t.Fatalf("unexpected sbom snapshot: %+v", got)
	}

	list, err := store.ListSBOMSnapshots(context.Background(), 10)
	if err != nil {
		t.Fatalf("list sbom snapshots: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 sbom snapshot got %d", len(list))
	}
}

func TestStoreCBOMSnapshotCRUD(t *testing.T) {
	_, store, _, _, _, _ := newSBOMService(t)

	item := CBOMSnapshot{
		ID:         "cbom_test_1",
		TenantID:   "tenant-x",
		SourceHash: "hash-b",
		Document: CBOMDocument{
			Format:                "cyclonedx-crypto",
			SpecVersion:           "1.6",
			TenantID:              "tenant-x",
			GeneratedAt:           time.Now().UTC(),
			Assets:                []CryptoAsset{{ID: "k1", Source: "keycore", AssetType: "key", Algorithm: "AES-256"}},
			AlgorithmDistribution: map[string]int{"AES-256": 1},
			StrengthHistogram:     map[string]int{"<128": 0, "128-255": 0, "256-3071": 1, ">=3072": 0},
			SourceCount:           map[string]int{"keycore": 1},
		},
		Summary: map[string]interface{}{"total_assets": 1},
	}
	if err := store.SaveCBOMSnapshot(context.Background(), item); err != nil {
		t.Fatalf("save cbom snapshot: %v", err)
	}

	got, err := store.GetCBOMSnapshotByID(context.Background(), item.TenantID, item.ID)
	if err != nil {
		t.Fatalf("get cbom snapshot: %v", err)
	}
	if got.ID != item.ID || got.TenantID != item.TenantID {
		t.Fatalf("unexpected cbom snapshot: %+v", got)
	}

	list, err := store.ListCBOMSnapshots(context.Background(), item.TenantID, 10)
	if err != nil {
		t.Fatalf("list cbom snapshots: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 cbom snapshot got %d", len(list))
	}

	tenants, err := store.ListKnownCBOMTenants(context.Background())
	if err != nil {
		t.Fatalf("list known tenants: %v", err)
	}
	if len(tenants) != 1 || tenants[0] != item.TenantID {
		t.Fatalf("unexpected tenants: %+v", tenants)
	}
}

func TestStoreManualAdvisoriesCRUD(t *testing.T) {
	_, store, _, _, _, _ := newSBOMService(t)

	item := ManualAdvisory{
		ID:                "CVE-2026-9999",
		Component:         "example/module",
		Ecosystem:         "go",
		IntroducedVersion: "v1.0.0",
		FixedVersion:      "v1.2.0",
		Severity:          "high",
		Summary:           "Offline advisory for air-gapped validation.",
		Reference:         "https://example.test/advisories/CVE-2026-9999",
	}
	if err := store.UpsertManualAdvisory(context.Background(), item); err != nil {
		t.Fatalf("upsert manual advisory: %v", err)
	}

	list, err := store.ListManualAdvisories(context.Background())
	if err != nil {
		t.Fatalf("list manual advisories: %v", err)
	}
	if len(list) != 1 || list[0].ID != item.ID {
		t.Fatalf("unexpected manual advisories: %+v", list)
	}

	item.Summary = "Updated summary."
	if err := store.UpsertManualAdvisory(context.Background(), item); err != nil {
		t.Fatalf("update manual advisory: %v", err)
	}
	list, err = store.ListManualAdvisories(context.Background())
	if err != nil {
		t.Fatalf("list manual advisories after update: %v", err)
	}
	if len(list) != 1 || list[0].Summary != item.Summary {
		t.Fatalf("expected updated advisory, got %+v", list)
	}

	if err := store.DeleteManualAdvisory(context.Background(), item.ID); err != nil {
		t.Fatalf("delete manual advisory: %v", err)
	}
	list, err = store.ListManualAdvisories(context.Background())
	if err != nil {
		t.Fatalf("list manual advisories after delete: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected manual advisories to be deleted, got %+v", list)
	}
}
