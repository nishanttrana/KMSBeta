package main

import (
	"context"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

func newAuditStore(t *testing.T) *SQLStore {
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
	if err := createAuditSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return NewSQLStore(conn)
}

func createAuditSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE audit_events (
			id TEXT NOT NULL, tenant_id TEXT NOT NULL, sequence INTEGER NOT NULL, chain_hash TEXT NOT NULL, previous_hash TEXT NOT NULL,
			timestamp TEXT NOT NULL, service TEXT NOT NULL, action TEXT NOT NULL, actor_id TEXT NOT NULL, actor_type TEXT NOT NULL,
			target_type TEXT, target_id TEXT, method TEXT, endpoint TEXT, source_ip TEXT, user_agent TEXT, request_hash TEXT,
			correlation_id TEXT, parent_event_id TEXT, session_id TEXT, result TEXT NOT NULL, status_code INTEGER, error_message TEXT,
			duration_ms REAL, fips_compliant INTEGER, approval_id TEXT, risk_score INTEGER, tags TEXT, node_id TEXT, details TEXT,
			created_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE alerts (
			id TEXT NOT NULL, tenant_id TEXT NOT NULL, audit_event_id TEXT NOT NULL, severity TEXT NOT NULL, category TEXT NOT NULL,
			title TEXT NOT NULL, description TEXT, source_service TEXT NOT NULL, actor_id TEXT, target_id TEXT, risk_score INTEGER DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'open', acknowledged_by TEXT, acknowledged_at TEXT, resolved_by TEXT, resolved_at TEXT,
			resolution_note TEXT, dispatched_channels TEXT, dispatch_status TEXT, dedup_key TEXT, occurrence_count INTEGER DEFAULT 1,
			escalated_from TEXT, escalated_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE alert_rules (
			id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL, condition_expr TEXT NOT NULL,
			severity TEXT NOT NULL, title TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT DEFAULT CURRENT_TIMESTAMP
		);`,
	}
	for _, s := range stmts {
		if _, err := conn.SQL().Exec(s); err != nil {
			return err
		}
	}
	return nil
}

func TestPersistEventCreatesAlert(t *testing.T) {
	s := newAuditStore(t)
	ctx := context.Background()

	event := AuditEvent{
		TenantID:  "t1",
		Timestamp: time.Now().UTC(),
		Service:   "key",
		Action:    "audit.key.exported",
		ActorID:   "u1",
		ActorType: "human",
		Result:    "success",
		Details:   map[string]interface{}{"k": "v"},
	}
	alert := Alert{
		Severity:      "HIGH",
		Category:      "key",
		Title:         "Key exported",
		SourceService: "key",
		ActorID:       "u1",
	}
	ev, al, err := s.PersistEventAndAlert(ctx, event, alert, 60, 5, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Sequence != 1 || ev.ChainHash == "" || ev.PreviousHash == "" {
		t.Fatalf("invalid chain fields: %+v", ev)
	}
	if al.ID == "" || al.AuditEventID != ev.ID {
		t.Fatalf("invalid alert: %+v", al)
	}
}

func TestDedupAndEscalation(t *testing.T) {
	s := newAuditStore(t)
	ctx := context.Background()
	base := time.Now().UTC()
	for i := 0; i < 5; i++ {
		_, _, err := s.PersistEventAndAlert(ctx, AuditEvent{
			TenantID:  "t1",
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Service:   "auth",
			Action:    "audit.auth.login_failed",
			ActorID:   "u1",
			ActorType: "human",
			SourceIP:  "1.1.1.1",
			Result:    "failure",
		}, Alert{
			Severity:      "HIGH",
			Category:      "auth",
			Title:         "Login failed",
			SourceService: "auth",
		}, 60, 5, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
	}
	items, err := s.QueryAlerts(ctx, "t1", AlertQuery{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatal("expected alerts")
	}
	foundCritical := false
	for _, it := range items {
		if it.Severity == "CRITICAL" || it.EscalatedFrom == "HIGH" {
			foundCritical = true
		}
	}
	if !foundCritical {
		t.Fatal("expected escalation to CRITICAL")
	}
}

func TestVerifyChain(t *testing.T) {
	s := newAuditStore(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, _, err := s.PersistEventAndAlert(ctx, AuditEvent{
			TenantID:  "t2",
			Timestamp: time.Now().UTC().Add(time.Duration(i) * time.Second),
			Service:   "key",
			Action:    "audit.key.encrypt",
			ActorID:   "u1",
			ActorType: "human",
			Result:    "success",
		}, Alert{
			Severity:      "LOW",
			Category:      "key",
			Title:         "encrypt",
			SourceService: "key",
		}, 60, 5, 10*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
	}
	ok, breaks, err := s.VerifyChain(ctx, "t2")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(breaks) != 0 {
		t.Fatalf("chain should be valid: ok=%v breaks=%v", ok, breaks)
	}
}
