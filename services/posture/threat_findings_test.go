package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

// threatEvent is an audit record as keycore's sweeper emits it.
func threatEvent(id, signalID, signalType, severity string) map[string]interface{} {
	return map[string]interface{}{
		"id": id, "action": threatSignalAction, "service": "keycore", "result": "success",
		"tenant_id": "t1", "target_id": "key_1", "node_id": "node-a",
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"details": map[string]interface{}{
			"signal_id": signalID, "signal_type": signalType, "key_id": "key_1",
			"actor_id": "mallory", "severity": severity, "description": "Canary key probed by mallory",
		},
	}
}

func threatFindings(t *testing.T, svc *Service) []Finding {
	t.Helper()
	items, err := svc.ListFindings(context.Background(), "t1", FindingQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var out []Finding
	for _, f := range items {
		if strings.HasPrefix(f.FindingType, "threat_") {
			out = append(out, f)
		}
	}
	return out
}

// A synced threat signal becomes one finding with its evidence, audited as
// threat_finding_raised. Later scans neither duplicate it nor reopen it once
// resolved; an unknown signal type raises nothing.
func TestThreatSignalBecomesFindingOnce(t *testing.T) {
	_, store, _ := newPostureHandler(t, nil)
	bus := &recordedPublish{}
	trail := auditTrail{
		threatEvent("e1", "tsig_1", "canary_tripped", "critical"),
		threatEvent("e2", "tsig_2", "dormant_key_activity", "medium"),
		threatEvent("e3", "tsig_3", "made_up", "critical"),
	}
	svc := NewService(store, trail, bus)
	ctx := context.Background()
	if _, err := svc.RunScanTenant(ctx, "t1", true); err != nil {
		t.Fatal(err)
	}

	got := threatFindings(t, svc)
	if len(got) != 2 {
		t.Fatalf("threat findings: %+v", got)
	}
	bySignal := map[string]Finding{}
	for _, f := range got {
		bySignal[firstString(f.Evidence["signal_id"])] = f
	}
	canary := bySignal["tsig_1"]
	if canary.FindingType != "threat_canary_tripped" || canary.Severity != severityCritical || canary.Status != "open" ||
		canary.Evidence["key_id"] != "key_1" || canary.Evidence["actor_id"] != "mallory" || canary.Evidence["audit_event_id"] != "e1" || canary.Description == "" {
		t.Fatalf("canary finding: %+v", canary)
	}
	if bySignal["tsig_2"].Severity != severityWarning {
		t.Fatalf("medium signal not mapped to warning: %+v", bySignal["tsig_2"])
	}
	if n := bus.count("audit.posture.threat_finding_raised"); n != 2 {
		t.Fatalf("threat_finding_raised events: %d (%v)", n, bus.subjects)
	}

	if err := svc.UpdateFindingStatus(ctx, "t1", canary.ID, "resolved"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RunScanTenant(ctx, "t1", true); err != nil {
		t.Fatal(err)
	}
	if got := threatFindings(t, svc); len(got) != 2 {
		t.Fatalf("rescan duplicated findings: %+v", got)
	}
	f, err := store.GetFinding(ctx, "t1", canary.ID)
	if err != nil || f.Status != "resolved" {
		t.Fatalf("resolved threat finding reopened: %+v %v", f, err)
	}
	if n := bus.count("audit.posture.threat_finding_raised"); n != 2 {
		t.Fatalf("rescan re-audited: %d", n)
	}
}
