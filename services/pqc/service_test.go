package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPQCServiceReadinessPlanExecuteRollback(t *testing.T) {
	svc, _, pub, keycore := newPQCService(t)
	// keycore refuses to move this key in place, so the plan falls back to
	// a successor key (TestPQCMigrationChangesAlgorithmInPlace covers the
	// preferred path).
	keycore.refuseAlgorithmChange = map[string]bool{"k1": true}
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

	inventory, err := svc.GetInventory(ctx, tenantID)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	// Counts come from each asset's algorithm (fakes: RSA / hybrid / ML-DSA
	// keys; RSA / hybrid / ML-DSA certificates). No listener has been
	// measured by certs yet, so none is reported.
	if k := inventory.Keys; k.Total != 3 || k.Classical != 1 || k.Hybrid != 1 || k.PQCOnly != 1 ||
		inventory.Certificates.Total != 3 || inventory.Certificates.Classical != 1 || inventory.Certificates.Hybrid != 1 || inventory.Certificates.PQCOnly != 1 {
		t.Fatalf("unexpected inventory counts: keys=%+v certs=%+v", inventory.Keys, inventory.Certificates)
	}
	if inventory.Interfaces != "not_measured" || len(inventory.Listeners) != 0 {
		t.Fatalf("interfaces = %q %+v, want not_measured", inventory.Interfaces, inventory.Listeners)
	}
	if len(inventory.ClassicalUsage) != 2 || len(inventory.NonMigratedCertificates) != 1 {
		t.Fatalf("expected every classical asset listed: %+v", inventory)
	}
	report, err := svc.GetMigrationReport(ctx, tenantID)
	if err != nil {
		t.Fatalf("migration report: %v", err)
	}
	// No plan has a deadline yet, so there is no timeline: the product sets
	// no dates of its own.
	if report.Inventory.Keys.Total == 0 || len(report.TopRisks) == 0 || len(report.Timeline) != 0 {
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
			// A key is manual only when its algorithm is not assessed
			// (ML-KEM-768-HYBRID names no classical group), so no target
			// is proposed for it.
			if isKeyAsset(step.AssetType) && (step.TargetAlg != "" || !strings.Contains(step.Metadata["reason"].(string), "no migration target")) {
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
	if _, err := svc.CreateMigrationPlan(ctx, PlanRequest{TenantID: tenantID, Deadline: "2028-12-31"}); err != nil {
		t.Fatalf("plan: %v", err)
	}
	milestones, readiness, err := svc.Timeline(ctx, tenantID)
	if err != nil {
		t.Fatalf("timeline: %v", err)
	}
	if len(milestones) == 0 || readiness.TotalAssets == 0 {
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

// The inventory reports the external listeners as certs measured them, and
// classifies them from pkg/cryptocatalog: a listener that still accepts a
// quantum-vulnerable group is classical; if certs can't answer, the
// listeners are "unavailable", never a guess.
func TestInventoryReportsMeasuredListeners(t *testing.T) {
	svc, _, pub, _ := newPQCService(t)
	certs := &fakePQCCerts{listeners: []ListenerMeasurement{
		{Name: "envoy", AcceptedGroups: []string{"X25519MLKEM768"}, NegotiatedGroup: "X25519MLKEM768", MeasuredAt: time.Now()},
		{Name: "kmip", AcceptedGroups: []string{"X25519MLKEM768", "SecP256r1MLKEM768", "CurveP256", "CurveP384"}, NegotiatedGroup: "X25519MLKEM768", MeasuredAt: time.Now()},
		{Name: "odd", AcceptedGroups: []string{"brainpoolP256r1"}},
	}}
	svc.certs = certs
	inv, err := svc.GetInventory(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]ListenerPQCItem{}
	for _, l := range inv.Listeners {
		got[l.Name] = l
	}
	if inv.Interfaces != "measured" || got["envoy"].Classification != "hybrid" || got["kmip"].Classification != "classical" ||
		strings.Join(got["kmip"].QuantumVulnerableGroups, ",") != "CurveP256,CurveP384" || got["odd"].Classification != "not_assessed" {
		t.Fatalf("listeners: %s %+v", inv.Interfaces, inv.Listeners)
	}
	if pub.Count("audit.pqc.inventory_viewed") == 0 {
		t.Fatal("the inventory view is audited")
	}

	certs.listeners, certs.edgeErr = nil, errors.New("certs unreachable")
	inv, err = svc.GetInventory(context.Background(), "t1")
	if err != nil || inv.Interfaces != "unavailable" || len(inv.Listeners) != 0 {
		t.Fatalf("unavailable measurement: %s %+v %v", inv.Interfaces, inv.Listeners, err)
	}
}

// The HTTP client reads certs' measurement route.
func TestCertsClientEdgeMeasurement(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/certs/edge-tls/measurement" || r.URL.Query().Get("tenant_id") != "t1" {
			http.Error(w, `{"error":{"message":"wrong route"}}`, http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"listeners":[{"name":"envoy","accepted_groups":["X25519MLKEM768"],"negotiated_group":"X25519MLKEM768","measured_at":"2026-09-29T10:00:00Z"}],"configured":2}`))
	}))
	defer srv.Close()
	got, err := NewHTTPCertsClient(srv.URL, time.Second).EdgeMeasurement(context.Background(), "t1")
	if err != nil || len(got) != 1 || got[0].Name != "envoy" || got[0].AcceptedGroups[0] != "X25519MLKEM768" || got[0].MeasuredAt.IsZero() {
		t.Fatalf("measurement: %+v %v", got, err)
	}
}

// The preferred migration keeps the key ID: keycore rotates the key onto the
// target algorithm, and rollback rotates it back.
func TestPQCMigrationChangesAlgorithmInPlace(t *testing.T) {
	svc, _, pub, keycore := newPQCService(t)
	ctx := context.Background()
	tenantID := "tenant-inplace"
	if _, err := svc.StartReadinessScan(ctx, ScanRequest{TenantID: tenantID, Trigger: "test"}); err != nil {
		t.Fatal(err)
	}
	plan, err := svc.CreateMigrationPlan(ctx, PlanRequest{TenantID: tenantID, Name: "plan", CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteMigrationPlan(ctx, tenantID, plan.ID, ExecuteRequest{TenantID: tenantID, Actor: "tester"}); err != nil {
		t.Fatal(err)
	}
	after, _ := svc.GetMigrationPlan(ctx, tenantID, plan.ID)
	changed := 0
	for _, step := range after.Steps {
		if step.Status == "algorithm_changed" {
			changed++
			if step.AssetID != "k1" || step.Metadata["successor_key_id"] != nil || step.Metadata["source"] != "keycore" {
				t.Fatalf("in-place step %+v", step)
			}
		}
	}
	keycore.mu.Lock()
	created := len(keycore.created)
	keycore.mu.Unlock()
	// k1 (keycore) moves in place; a discovered cloud key still gets a
	// keycore successor, as it isn't keycore's to rotate.
	if changed != 1 || created != 1 {
		t.Fatalf("changed %d in place, created %d successors", changed, created)
	}
	if pub.Count("audit.pqc.migration_step_executed") == 0 {
		t.Fatal("no step event")
	}
	rolled, err := svc.RollbackMigrationPlan(ctx, tenantID, plan.ID, "tester")
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range rolled.Steps {
		if step.AssetID == "k1" && step.Status != "rolled_back" {
			t.Fatalf("in-place change not rolled back: %+v", step)
		}
	}
}
