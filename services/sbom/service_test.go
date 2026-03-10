package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestServiceSBOMGenerationAndDiff(t *testing.T) {
	svc, store, _, _, _, pub := newSBOMService(t)

	first, err := svc.GenerateSBOM(context.Background(), "test")
	if err != nil {
		t.Fatalf("generate sbom: %v", err)
	}
	if first.ID == "" || len(first.Document.Components) == 0 {
		t.Fatalf("unexpected first snapshot: %+v", first)
	}
	if pub.Count("audit.sbom.generated") == 0 {
		t.Fatalf("expected sbom audit event")
	}

	second := first
	second.ID = newID("sbom")
	second.Document.GeneratedAt = time.Now().UTC().Add(time.Minute)
	second.Document.Components = append(second.Document.Components, BOMComponent{
		Name:      "example/new-component",
		Version:   "v0.1.0",
		Type:      "library",
		PURL:      "pkg:golang/example/new-component@0.1.0",
		Supplier:  "example",
		Licenses:  []string{"MIT"},
		Hashes:    map[string]string{},
		Metadata:  map[string]string{"source": "test"},
		Ecosystem: "go",
	})
	second.SourceHash = hashSBOMComponents(second.Document.Components)
	second.Summary = summarizeSBOM(second.Document)
	if err := store.SaveSBOMSnapshot(context.Background(), second); err != nil {
		t.Fatalf("save second snapshot: %v", err)
	}

	diff, err := svc.DiffSBOM(context.Background(), first.ID, second.ID)
	if err != nil {
		t.Fatalf("diff sbom: %v", err)
	}
	if len(diff.Added) == 0 {
		t.Fatalf("expected added components in diff: %+v", diff)
	}

	vuln, err := svc.correlateVulnerabilities(context.Background(), []BOMComponent{{Name: "golang.org/x/net", Version: "v0.20.0", Type: "library", Ecosystem: "go"}})
	if err != nil {
		t.Fatalf("correlate vulnerabilities: %v", err)
	}
	if len(vuln) == 0 {
		t.Fatalf("expected vulnerability match")
	}
}

func TestServiceCBOMGenerationAndDiff(t *testing.T) {
	svc, _, keycore, certs, discovery, pub := newSBOMService(t)

	tenantID := "tenant-a"
	keycore.keys[tenantID] = []map[string]interface{}{
		{"id": "k1", "name": "data-key", "algorithm": "AES-256", "status": "active", "purpose": "encrypt"},
		{"id": "k2", "name": "legacy", "algorithm": "3DES", "status": "active", "purpose": "legacy"},
	}
	certs.items[tenantID] = []map[string]interface{}{
		{"id": "c1", "subject_cn": "svc.example", "algorithm": "ML-DSA-65", "cert_class": "pqc", "status": "active"},
	}
	discovery.items[tenantID] = []map[string]interface{}{
		{"id": "d1", "name": "disk-encryption", "algorithm": "AES-256", "asset_type": "discovered", "status": "active"},
	}

	first, err := svc.GenerateCBOM(context.Background(), tenantID, "test")
	if err != nil {
		t.Fatalf("generate cbom: %v", err)
	}
	if first.Document.TotalAssetCount != 4 {
		t.Fatalf("unexpected asset count: %+v", first.Document)
	}
	if pub.Count("audit.cbom.generated") == 0 {
		t.Fatalf("expected cbom audit event")
	}

	keycore.keys[tenantID] = append(keycore.keys[tenantID], map[string]interface{}{
		"id": "k3", "name": "pqc-key", "algorithm": "ML-KEM-768", "status": "active", "purpose": "kem",
	})
	second, err := svc.GenerateCBOM(context.Background(), tenantID, "test")
	if err != nil {
		t.Fatalf("generate second cbom: %v", err)
	}

	readiness, err := svc.CBOMPQCReadiness(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("readiness: %v", err)
	}
	if readiness["status"] == "" {
		t.Fatalf("expected readiness status")
	}

	diff, err := svc.DiffCBOM(context.Background(), tenantID, first.ID, second.ID)
	if err != nil {
		t.Fatalf("diff cbom: %v", err)
	}
	if len(diff.Added) == 0 && len(diff.Changed) == 0 {
		t.Fatalf("expected cbom diff changes: %+v", diff)
	}
}

func TestServiceVulnerabilityLookupFallsBackToCatalog(t *testing.T) {
	svc, _, _, _, _, _ := newSBOMService(t)
	svc.vulnProvider = &stubVulnerabilityProvider{err: errors.New("osv down")}

	items, err := svc.correlateVulnerabilities(context.Background(), []BOMComponent{
		{Name: "golang.org/x/net", Version: "v0.20.0", Type: "library", Ecosystem: "go"},
	})
	if err != nil {
		t.Fatalf("correlate vulnerabilities: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected catalog fallback match, got %+v", items)
	}
	if items[0].ID == "" || items[0].FixedVersion == "" {
		t.Fatalf("expected populated fallback vulnerability: %+v", items[0])
	}
}
