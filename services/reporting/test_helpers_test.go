package main

import (
	"context"
	"sync"
	"testing"

	pkgdb "vecta-kms/pkg/db"
)

type nopReportingPublisher struct {
	mu       sync.Mutex
	subjects []string
}

func (p *nopReportingPublisher) Publish(_ context.Context, subject string, _ []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	return nil
}

func (p *nopReportingPublisher) Count(subject string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, s := range p.subjects {
		if s == subject {
			n++
		}
	}
	return n
}

type fakeReportingAudit struct {
	events map[string][]map[string]interface{}
}

func (f *fakeReportingAudit) ListEvents(_ context.Context, tenantID string, _ int) ([]map[string]interface{}, error) {
	items := f.events[tenantID]
	if items == nil {
		return []map[string]interface{}{}, nil
	}
	return items, nil
}

func (f *fakeReportingAudit) GetEvent(_ context.Context, tenantID string, id string) (map[string]interface{}, error) {
	for _, item := range f.events[tenantID] {
		if firstString(item["id"]) == id {
			return item, nil
		}
	}
	return map[string]interface{}{}, nil
}

type fakeReportingCompliance struct {
	posture map[string]map[string]interface{}
}

func (f *fakeReportingCompliance) GetPosture(_ context.Context, tenantID string) (map[string]interface{}, error) {
	item := f.posture[tenantID]
	if item == nil {
		return map[string]interface{}{}, nil
	}
	return item, nil
}

func newReportingService(t *testing.T) (*Service, *SQLStore, *fakeReportingAudit, *fakeReportingCompliance, *nopReportingPublisher) {
	t.Helper()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{
		UseSQLite:  true,
		SQLitePath: ":memory:",
		MaxOpen:    1,
		MaxIdle:    1,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := createReportingSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	audit := &fakeReportingAudit{events: map[string][]map[string]interface{}{}}
	comp := &fakeReportingCompliance{posture: map[string]map[string]interface{}{}}
	pub := &nopReportingPublisher{}
	svc := NewService(store, audit, comp, pub)
	return svc, store, audit, comp, pub
}

func newReportingHandler(t *testing.T) (*Handler, *Service, *fakeReportingAudit, *fakeReportingCompliance, *nopReportingPublisher) {
	t.Helper()
	svc, _, audit, comp, pub := newReportingService(t)
	return NewHandler(svc), svc, audit, comp, pub
}

func createReportingSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE reporting_alerts (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			audit_event_id TEXT NOT NULL DEFAULT '',
			audit_action TEXT NOT NULL,
			severity TEXT NOT NULL,
			category TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			service TEXT NOT NULL DEFAULT '',
			actor_id TEXT NOT NULL DEFAULT '',
			actor_type TEXT NOT NULL DEFAULT '',
			target_type TEXT NOT NULL DEFAULT '',
			target_id TEXT NOT NULL DEFAULT '',
			source_ip TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'new',
			acknowledged_by TEXT NOT NULL DEFAULT '',
			acknowledged_at TIMESTAMP,
			resolved_by TEXT NOT NULL DEFAULT '',
			resolved_at TIMESTAMP,
			resolution_note TEXT NOT NULL DEFAULT '',
			incident_id TEXT NOT NULL DEFAULT '',
			correlation_id TEXT NOT NULL DEFAULT '',
			rule_id TEXT NOT NULL DEFAULT '',
			is_escalated BOOLEAN NOT NULL DEFAULT FALSE,
			escalated_from TEXT NOT NULL DEFAULT '',
			dedup_count INTEGER NOT NULL DEFAULT 1,
			channels_sent_json TEXT NOT NULL DEFAULT '[]',
			channel_status_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE reporting_incidents (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			title TEXT NOT NULL,
			severity TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'open',
			alert_count INTEGER NOT NULL DEFAULT 0,
			first_alert_at TIMESTAMP,
			last_alert_at TIMESTAMP,
			assigned_to TEXT NOT NULL DEFAULT '',
			notes TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE reporting_alert_rules (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			name TEXT NOT NULL,
			condition TEXT NOT NULL DEFAULT '',
			severity TEXT NOT NULL DEFAULT 'warning',
			event_pattern TEXT NOT NULL DEFAULT '',
			threshold INTEGER NOT NULL DEFAULT 0,
			window_seconds INTEGER NOT NULL DEFAULT 0,
			channels_json TEXT NOT NULL DEFAULT '[]',
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE reporting_severity_overrides (
			tenant_id TEXT NOT NULL,
			audit_action TEXT NOT NULL,
			severity TEXT NOT NULL,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, audit_action)
		);`,
		`CREATE TABLE reporting_notification_channels (
			tenant_id TEXT NOT NULL,
			name TEXT NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			config_json TEXT NOT NULL DEFAULT '{}',
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, name)
		);`,
		`CREATE TABLE reporting_report_jobs (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			template_id TEXT NOT NULL,
			format TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'queued',
			filters_json TEXT NOT NULL DEFAULT '{}',
			result_content TEXT NOT NULL DEFAULT '',
			result_content_type TEXT NOT NULL DEFAULT '',
			requested_by TEXT NOT NULL DEFAULT '',
			error TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			completed_at TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE reporting_scheduled_reports (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			name TEXT NOT NULL,
			template_id TEXT NOT NULL,
			format TEXT NOT NULL,
			schedule TEXT NOT NULL,
			filters_json TEXT NOT NULL DEFAULT '{}',
			recipients_json TEXT NOT NULL DEFAULT '[]',
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			last_run_at TIMESTAMP,
			next_run_at TIMESTAMP,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
	}
	for _, stmt := range stmts {
		if _, err := conn.SQL().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}
