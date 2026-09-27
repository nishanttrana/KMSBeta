package main

import (
	"context"
	"testing"
	"time"

	"vecta-kms/pkg/clusterstate"
)

func threatAuditEvent(id, severity string) map[string]interface{} {
	return map[string]interface{}{
		"id": id, "action": threatSignalAction, "service": "keycore", "target_id": "key_1",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"details": map[string]interface{}{
			"signal_id": "tsig_" + id, "signal_type": "new_actor", "key_id": "key_1",
			"severity": severity, "description": "Actor mallory used key_1 for the first time",
		},
	}
}

// The scheduled sync raises critical and high threat signals as alerts with
// the signal's description, for every tenant reporting knows and root; a
// medium signal stays a posture finding only.
func TestThreatSignalsBecomeAlertsOnScheduledSync(t *testing.T) {
	svc, store, audit, _, _, pub := newReportingService(t)
	ctx := context.Background()
	if err := store.UpsertChannel(ctx, NotificationChannel{TenantID: "t2", Name: "screen", Enabled: true, Config: map[string]interface{}{}}); err != nil {
		t.Fatal(err)
	}
	audit.events["root"] = []map[string]interface{}{threatAuditEvent("r1", "critical")}
	audit.events["t2"] = []map[string]interface{}{threatAuditEvent("a1", "high"), threatAuditEvent("a2", "medium")}

	svc.SyncAlertsAllTenants(ctx)

	root, _ := store.ListAlerts(ctx, "root", AlertQuery{Limit: 10})
	if len(root) != 1 || root[0].Severity != severityCritical || root[0].Description != "Actor mallory used key_1 for the first time" {
		t.Fatalf("root alerts: %+v", root)
	}
	t2, _ := store.ListAlerts(ctx, "t2", AlertQuery{Limit: 10})
	if len(t2) != 1 || t2[0].Severity != severityHigh || t2[0].AuditEventID != "a1" {
		t.Fatalf("t2 alerts: %+v", t2)
	}
	unread, _ := svc.CountUnread(ctx, "t2")
	if unread[severityHigh] != 1 {
		t.Fatalf("header unread count: %v", unread)
	}
	if pub.Count("audit.reporting.alert_created") != 2 {
		t.Fatalf("alert_created events: %v", pub.subjects)
	}
}

// A cluster member serves replicated alerts and never creates them.
func TestListAlertsDoesNotSyncOnMember(t *testing.T) {
	clusterstate.SetDefault(clusterstate.Static(clusterstate.State{NodeID: "n2", Role: clusterstate.RoleFollower, PrimaryURL: "https://primary:8443", ForwardCredential: "cred"}))
	t.Cleanup(func() { clusterstate.SetDefault(nil) })
	svc, _, audit, _, _, _ := newReportingService(t)
	audit.events["root"] = []map[string]interface{}{threatAuditEvent("r1", "critical")}
	items, err := svc.ListAlerts(context.Background(), "root", AlertQuery{Limit: 10})
	if err != nil || len(items) != 0 {
		t.Fatalf("member created alerts: %+v %v", items, err)
	}
}
