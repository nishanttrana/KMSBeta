package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestStoreAlertAndIncidentOps(t *testing.T) {
	_, store, _, _, _ := newReportingService(t)
	tenantID := "tenant-s"

	alert := Alert{
		ID:           "a1",
		TenantID:     tenantID,
		AuditEventID: "ev1",
		AuditAction:  "key.created",
		Severity:     severityInfo,
		Category:     "crypto",
		Title:        "Key Created",
		Status:       "new",
		DedupCount:   1,
	}
	if err := store.CreateAlert(context.Background(), alert); err != nil {
		t.Fatalf("create alert: %v", err)
	}
	got, err := store.GetAlert(context.Background(), tenantID, alert.ID)
	if err != nil {
		t.Fatalf("get alert: %v", err)
	}
	if got.AuditAction != alert.AuditAction {
		t.Fatalf("unexpected alert: %+v", got)
	}

	if err := store.EscalateAlert(context.Background(), tenantID, alert.ID, severityHigh); err != nil {
		t.Fatalf("escalate alert: %v", err)
	}
	got, _ = store.GetAlert(context.Background(), tenantID, alert.ID)
	if got.Severity != severityHigh {
		t.Fatalf("expected high severity got %s", got.Severity)
	}

	if err := store.UpdateAlertStatus(context.Background(), tenantID, alert.ID, "resolved", "analyst", "done"); err != nil {
		t.Fatalf("resolve alert: %v", err)
	}
	got, _ = store.GetAlert(context.Background(), tenantID, alert.ID)
	if got.Status != "resolved" {
		t.Fatalf("expected resolved status got %s", got.Status)
	}

	incident := Incident{
		ID:           "inc1",
		TenantID:     tenantID,
		Title:        "Incident 1",
		Severity:     severityHigh,
		Status:       "open",
		AlertCount:   1,
		FirstAlertAt: time.Now().UTC(),
		LastAlertAt:  time.Now().UTC(),
	}
	if err := store.CreateIncident(context.Background(), incident); err != nil {
		t.Fatalf("create incident: %v", err)
	}
	if err := store.AssignIncident(context.Background(), tenantID, incident.ID, "user1"); err != nil {
		t.Fatalf("assign incident: %v", err)
	}
	if err := store.UpdateIncidentStatus(context.Background(), tenantID, incident.ID, "investigating", "triage"); err != nil {
		t.Fatalf("update incident status: %v", err)
	}
	inc, err := store.GetIncident(context.Background(), tenantID, incident.ID)
	if err != nil {
		t.Fatalf("get incident: %v", err)
	}
	if inc.AssignedTo != "user1" {
		t.Fatalf("unexpected incident assignment: %+v", inc)
	}
}

func TestStoreRulesChannelsAndReports(t *testing.T) {
	_, store, _, _, _ := newReportingService(t)
	tenantID := "tenant-rules"

	rule := AlertRule{
		ID:           "rule1",
		TenantID:     tenantID,
		Name:         "rule-name",
		Condition:    "count(auth.login_failed) >= 3",
		Severity:     severityCritical,
		EventPattern: "auth.login_failed",
		Threshold:    3,
		WindowSecond: 300,
		Channels:     []string{"screen", "email"},
		Enabled:      true,
	}
	if err := store.CreateRule(context.Background(), rule); err != nil {
		t.Fatalf("create rule: %v", err)
	}
	rules, err := store.ListRules(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected one rule got %d", len(rules))
	}

	if err := store.UpsertSeverityOverride(context.Background(), SeverityOverride{
		TenantID: tenantID, AuditAction: "key.created", Severity: severityWarning,
	}); err != nil {
		t.Fatalf("upsert severity override: %v", err)
	}
	overrides, err := store.ListSeverityOverrides(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("list severity overrides: %v", err)
	}
	if len(overrides) != 1 {
		t.Fatalf("expected one override got %d", len(overrides))
	}

	if err := store.UpsertChannel(context.Background(), NotificationChannel{
		TenantID: tenantID, Name: "email", Enabled: true, Config: map[string]interface{}{"severity_filter": []string{"critical", "high"}},
	}); err != nil {
		t.Fatalf("upsert channel: %v", err)
	}
	channels, err := store.ListChannels(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("list channels: %v", err)
	}
	if len(channels) != 1 {
		t.Fatalf("expected one channel got %d", len(channels))
	}

	job := ReportJob{
		ID:         "job1",
		TenantID:   tenantID,
		TemplateID: "alert_summary",
		Format:     "json",
		Status:     "queued",
		Filters:    map[string]interface{}{"a": "b"},
	}
	if err := store.CreateReportJob(context.Background(), job); err != nil {
		t.Fatalf("create report job: %v", err)
	}
	job.Status = "completed"
	job.ResultContent = "{}"
	job.ResultContentType = "application/json"
	job.CompletedAt = time.Now().UTC()
	if err := store.UpdateReportJob(context.Background(), job); err != nil {
		t.Fatalf("update report job: %v", err)
	}
	gotJob, err := store.GetReportJob(context.Background(), tenantID, job.ID)
	if err != nil {
		t.Fatalf("get report job: %v", err)
	}
	if gotJob.Status != "completed" {
		t.Fatalf("expected completed report job got %s", gotJob.Status)
	}
	if err := store.DeleteReportJob(context.Background(), tenantID, job.ID); err != nil {
		t.Fatalf("delete report job: %v", err)
	}
	if _, err := store.GetReportJob(context.Background(), tenantID, job.ID); !errors.Is(err, errNotFound) {
		t.Fatalf("expected deleted report job to be not found, err=%v", err)
	}

	sched := ScheduledReport{
		ID:         "s1",
		TenantID:   tenantID,
		Name:       "daily",
		TemplateID: "alert_summary",
		Format:     "pdf",
		Schedule:   "daily",
		Recipients: []string{"a@example.com"},
		Enabled:    true,
		NextRunAt:  time.Now().UTC().Add(-time.Minute),
	}
	if err := store.CreateScheduledReport(context.Background(), sched); err != nil {
		t.Fatalf("create scheduled report: %v", err)
	}
	due, err := store.ListDueScheduledReports(context.Background(), time.Now().UTC(), 10)
	if err != nil {
		t.Fatalf("list due scheduled reports: %v", err)
	}
	if len(due) != 1 {
		t.Fatalf("expected one due schedule got %d", len(due))
	}
}

func TestStoreErrorTelemetryOps(t *testing.T) {
	_, store, _, _, _ := newReportingService(t)
	tenantID := "tenant-telemetry"
	now := time.Now().UTC()

	event := ErrorTelemetryEvent{
		ID:          "tel1",
		TenantID:    tenantID,
		Source:      "frontend",
		Service:     "dashboard",
		Component:   "window.onerror",
		Level:       "error",
		Message:     "Tab failed to render",
		StackTrace:  "Error: Tab failed",
		Context:     map[string]interface{}{"tab": "dashboard"},
		Fingerprint: "fp_abc",
		RequestID:   "req_1",
		ReleaseTag:  "dashboard",
		BuildVer:    "v1",
		CreatedAt:   now,
	}
	if err := store.CreateErrorTelemetry(context.Background(), event); err != nil {
		t.Fatalf("create telemetry event: %v", err)
	}

	items, err := store.ListErrorTelemetry(context.Background(), tenantID, ErrorTelemetryQuery{
		Service: "dashboard",
		Limit:   10,
	})
	if err != nil {
		t.Fatalf("list telemetry events: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one telemetry event got %d", len(items))
	}
	if items[0].Message != event.Message {
		t.Fatalf("unexpected telemetry message: %s", items[0].Message)
	}

	affected, err := store.PurgeErrorTelemetryBefore(context.Background(), now.Add(time.Minute), 100)
	if err != nil {
		t.Fatalf("purge telemetry events: %v", err)
	}
	if affected != 1 {
		t.Fatalf("expected 1 purged row got %d", affected)
	}
}
