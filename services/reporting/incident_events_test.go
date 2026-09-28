package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"vecta-kms/pkg/route"
)

// A new incident is announced once, as audit.reporting.incident_opened
// (compliance playbooks respond to it); alerts joining it are not.
func TestIncidentOpenedEmittedOnce(t *testing.T) {
	_, svc, rec := newAuditedReportingHandler(t)
	svc.events = rec
	ctx := context.Background()
	id, err := svc.attachIncident(ctx, "tenant-a", "Brute Force Attack from 10.0.0.9", severityCritical, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ev := rec.Last(t)
	if ev.Action != "incident_opened" || ev.Event.TargetType != "incident" || ev.Event.TargetID != id || ev.Event.TenantID != "tenant-a" || ev.Event.Details["severity"] != severityCritical {
		t.Fatalf("incident_opened: %+v", ev)
	}
	n := len(rec.Events())
	if again, _ := svc.attachIncident(ctx, "tenant-a", "Brute Force Attack from 10.0.0.9", severityCritical, time.Now().UTC()); again != id || len(rec.Events()) != n {
		t.Fatalf("second alert opened a new incident or announced again: %s %d", again, len(rec.Events()))
	}
}

// Incident updates accept only real states and report a missing incident
// (a playbook step must not succeed on nothing).
func TestIncidentUpdatesValidated(t *testing.T) {
	h, svc, rec := newAuditedReportingHandler(t)
	id, err := svc.attachIncident(context.Background(), "tenant-a", "Cluster Quorum Risk", severityCritical, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	admin := adminOf("tenant-a")
	for _, tc := range []struct {
		path, body string
		want       int
	}{
		{"/incidents/" + id + "/status", `{"status":"deleted"}`, http.StatusBadRequest},
		{"/incidents/inc_missing/status", `{"status":"resolved"}`, http.StatusNotFound},
		{"/incidents/inc_missing/assign", `{"assigned_to":"u1"}`, http.StatusNotFound},
		{"/incidents/" + id + "/status", `{"status":"investigating","notes":"playbook"}`, http.StatusOK},
		{"/incidents/" + id + "/assign", `{"assigned_to":"u-oncall"}`, http.StatusOK},
	} {
		if rr := serve(h, admin, http.MethodPut, tc.path, tc.body); rr.Code != tc.want {
			t.Fatalf("PUT %s %s: %d, want %d (%s)", tc.path, tc.body, rr.Code, tc.want, rr.Body.String())
		}
		ev := rec.Last(t)
		if (tc.want == http.StatusOK) != (ev.Event.Result == route.ResultSuccess) {
			t.Fatalf("%s audited %s", tc.path, ev.Event.Result)
		}
	}
	inc, _, err := svc.GetIncident(context.Background(), "tenant-a", id)
	if err != nil || inc.Status != "investigating" || inc.AssignedTo != "u-oncall" {
		t.Fatalf("incident %+v %v", inc, err)
	}
}

// alert_created names the alert and the event behind it, which playbook
// filters and templates use ({{event.target_id}}, details.source_actor_id).
func TestAlertCreatedNamesAlertAndSource(t *testing.T) {
	_, svc, rec := newAuditedReportingHandler(t)
	svc.events = rec
	alert, err := svc.ingestAuditEvent(context.Background(), "tenant-a", map[string]interface{}{
		"id": "e1", "action": "auth.login_failed", "source_ip": "10.0.0.1", "service": "auth",
		"target_id": "u1", "actor_id": "mallory", "timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil || alert.ID == "" {
		t.Fatalf("alert: %+v %v", alert, err)
	}
	ev := rec.Last(t)
	if ev.Action != "alert_created" || ev.Event.TargetType != "alert" || ev.Event.TargetID != alert.ID ||
		ev.Event.Details["severity"] != alert.Severity || ev.Event.Details["source_actor_id"] != "mallory" || ev.Event.Details["source_target_id"] != "u1" {
		t.Fatalf("alert_created: %+v", ev.Event)
	}
}
