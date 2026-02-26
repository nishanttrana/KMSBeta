package main

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestServiceSyncAlertsAndEscalation(t *testing.T) {
	svc, _, audit, _, pub := newReportingService(t)
	tenantID := "tenant-a"
	audit.events[tenantID] = []map[string]interface{}{
		{"id": "e1", "action": "auth.login_failed", "source_ip": "10.0.0.1", "service": "auth", "target_id": "u1", "timestamp": time.Now().UTC().Format(time.RFC3339)},
		{"id": "e2", "action": "auth.login_failed", "source_ip": "10.0.0.1", "service": "auth", "target_id": "u1", "timestamp": time.Now().UTC().Format(time.RFC3339)},
		{"id": "e3", "action": "auth.login_failed", "source_ip": "10.0.0.1", "service": "auth", "target_id": "u1", "timestamp": time.Now().UTC().Format(time.RFC3339)},
	}
	if err := svc.SyncAlertsFromAudit(context.Background(), tenantID, 100); err != nil {
		t.Fatalf("sync alerts: %v", err)
	}
	items, err := svc.ListAlerts(context.Background(), tenantID, AlertQuery{Limit: 100})
	if err != nil {
		t.Fatalf("list alerts: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("expected alerts after sync")
	}
	if pub.Count("audit.reporting.alert_created") == 0 {
		t.Fatalf("expected reporting audit publication")
	}
}

func TestServiceReportsAndSchedules(t *testing.T) {
	svc, _, audit, compliance, pub := newReportingService(t)
	tenantID := "tenant-r"
	audit.events[tenantID] = []map[string]interface{}{
		{"id": "e1", "action": "key.created", "service": "keycore", "target_id": "k1", "timestamp": time.Now().UTC().Format(time.RFC3339)},
	}
	compliance.posture[tenantID] = map[string]interface{}{"overall_score": "84"}
	_ = svc.SyncAlertsFromAudit(context.Background(), tenantID, 50)

	job, err := svc.GenerateReport(context.Background(), tenantID, "alert_summary", "json", "tester", map[string]interface{}{"window": "24h"})
	if err != nil {
		t.Fatalf("generate report: %v", err)
	}
	var got ReportJob
	for i := 0; i < 50; i++ {
		got, err = svc.GetReportJob(context.Background(), tenantID, job.ID)
		if err != nil {
			t.Fatalf("get report job: %v", err)
		}
		if got.Status == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got.Status != "completed" {
		t.Fatalf("expected completed report job got %s", got.Status)
	}
	if got.ResultContent == "" {
		t.Fatalf("expected report content")
	}
	if err := svc.DeleteReportJob(context.Background(), tenantID, got.ID, "tester"); err != nil {
		t.Fatalf("delete report job: %v", err)
	}
	if _, err := svc.GetReportJob(context.Background(), tenantID, got.ID); !errors.Is(err, errNotFound) {
		t.Fatalf("expected deleted report job to be not found, err=%v", err)
	}

	pdfJob, err := svc.GenerateReport(context.Background(), tenantID, "key_generation", "pdf", "tester", nil)
	if err != nil {
		t.Fatalf("generate pdf report: %v", err)
	}
	var gotPDF ReportJob
	for i := 0; i < 50; i++ {
		gotPDF, err = svc.GetReportJob(context.Background(), tenantID, pdfJob.ID)
		if err != nil {
			t.Fatalf("get pdf report job: %v", err)
		}
		if gotPDF.Status == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if gotPDF.Status != "completed" {
		t.Fatalf("expected completed pdf report job got %s", gotPDF.Status)
	}
	raw, err := base64.StdEncoding.DecodeString(gotPDF.ResultContent)
	if err != nil {
		t.Fatalf("decode pdf report base64: %v", err)
	}
	if !strings.HasPrefix(string(raw), "%PDF-") {
		t.Fatalf("invalid pdf header")
	}

	sched, err := svc.ScheduleReport(context.Background(), tenantID, "daily-alerts", "alert_summary", "pdf", "daily", []string{"soc@example.com"}, nil)
	if err != nil {
		t.Fatalf("schedule report: %v", err)
	}
	if sched.ID == "" {
		t.Fatalf("expected schedule id")
	}
	if err := svc.RunDueSchedules(context.Background()); err != nil {
		t.Fatalf("run due schedules: %v", err)
	}
	if pub.Count("audit.reporting.report_deleted") == 0 {
		t.Fatalf("expected report deletion audit publication")
	}
}
