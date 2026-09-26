package main

import (
	"context"
	"os"
	"strconv"
	"strings"
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
		// hmac_sig + category_group were added by migration 004
		// (services/audit/migrations/004_tamper_evidence.sql). country_code is
		// inserted via the geoip enrichment path. The test harness builds the
		// schema directly so it must include every column the production
		// INSERT path references; otherwise the SQLite driver returns "no
		// such column" at runtime.
		`CREATE TABLE audit_events (
			id TEXT NOT NULL, tenant_id TEXT NOT NULL, sequence INTEGER NOT NULL, chain_hash TEXT NOT NULL, previous_hash TEXT NOT NULL,
			timestamp TEXT NOT NULL, service TEXT NOT NULL, action TEXT NOT NULL, actor_id TEXT NOT NULL, actor_type TEXT NOT NULL,
			target_type TEXT, target_id TEXT, method TEXT, endpoint TEXT, source_ip TEXT, user_agent TEXT, request_hash TEXT,
			correlation_id TEXT, parent_event_id TEXT, session_id TEXT, result TEXT NOT NULL, status_code INTEGER, error_message TEXT,
			duration_ms REAL, fips_compliant INTEGER, approval_id TEXT, risk_score INTEGER, tags TEXT, node_id TEXT, details TEXT,
			hmac_sig TEXT, category_group TEXT, country_code TEXT,
			chain_node TEXT NOT NULL DEFAULT '', hmac_key_id TEXT,
			created_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE audit_relay_cursor (tenant_id TEXT NOT NULL, chain_node TEXT NOT NULL, last_sequence INTEGER NOT NULL, PRIMARY KEY (tenant_id, chain_node));`,
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
	base := time.Unix((time.Now().UTC().Unix()/60)*60+5, 0).UTC()
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

func TestPersistEventNormalizesSourceIP(t *testing.T) {
	s := newAuditStore(t)
	ctx := context.Background()

	_, _, err := s.PersistEventAndAlert(ctx, AuditEvent{
		TenantID:  "t3",
		Timestamp: time.Now().UTC(),
		Service:   "auth",
		Action:    "audit.auth.login_failed",
		ActorID:   "u1",
		ActorType: "human",
		SourceIP:  "172.18.0.4:55712",
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

	events, err := s.QueryEvents(ctx, "t3", EventQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one event, got %d", len(events))
	}
	if events[0].SourceIP != "172.18.0.4" {
		t.Fatalf("expected normalized source ip, got %q", events[0].SourceIP)
	}
}

func TestNormalizeSourceIPInvalidReturnsEmpty(t *testing.T) {
	got := normalizeSourceIP("not-an-ip:443")
	if got != "" {
		t.Fatalf("expected empty source ip, got %q", got)
	}
}

// HSM activity: events are selected by action prefix, with "_" taken
// literally (audit.key.hsm_ must not match audit.key.hsmx...).
func TestQueryEventsByActionPrefix(t *testing.T) {
	checkActionPrefix(t, newAuditStore(t), "t-hsm")
}

// The same on real Postgres (CI integration-postgres): LIKE ... ESCAPE.
func TestQueryEventsByActionPrefixPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	checkActionPrefix(t, NewSQLStore(conn), "t-hsm-pg-"+strconv.FormatInt(time.Now().UnixNano(), 36))
}

func checkActionPrefix(t *testing.T, s *SQLStore, tenant string) {
	t.Helper()
	ctx := context.Background()
	for _, a := range []string{"audit.hsm.encrypt", "audit.hsm.key_generated", "audit.key.hsm_refused", "audit.key.hsmx_other", "audit.key.create"} {
		if _, _, err := s.PersistEventAndAlert(ctx, AuditEvent{TenantID: tenant, Timestamp: time.Now().UTC(), Service: "hsm",
			Action: a, ActorID: "kms-keycore", ActorType: "service", Result: "success"}, Alert{}, 60, 5, 10*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	events, err := s.QueryEvents(ctx, tenant, EventQuery{Limit: 50, ActionPrefixes: []string{"audit.hsm.", "audit.key.hsm_"}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, e := range events {
		got[e.Action] = true
	}
	if len(events) != 3 || !got["audit.hsm.encrypt"] || !got["audit.hsm.key_generated"] || !got["audit.key.hsm_refused"] {
		t.Fatalf("prefix query returned %v", got)
	}
	if all, _ := s.QueryEvents(ctx, tenant, EventQuery{Limit: 50}); len(all) != 5 {
		t.Fatalf("no prefix: %d events", len(all))
	}
}
