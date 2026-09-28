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

// Approval-notice URLs on real Postgres (CI integration-postgres):
// migration 016, the legacy-URL query, and clearing the plaintext column
// once a connection replaces it.
func TestNotifyConnectionsPostgres(t *testing.T) {
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
	store := NewSQLStore(conn)
	tenant := "t-gov-pg-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if _, err := conn.SQL().Exec(`INSERT INTO governance_settings (tenant_id, notify_slack, slack_webhook_url) VALUES ($1, TRUE, 'https://hooks.slack.com/services/T/B/pg')`, tenant); err != nil {
		t.Fatal(err)
	}
	svc := NewService(store, nil, &mockEmailSender{}, &mockCallbackExecutor{}, "https://localhost")
	conns := &testNotifyConns{conns: map[string][2]string{}}
	svc.conns = conns
	if _, err := svc.migrateNotifyURLs(ctx, func(context.Context) bool { return true }); err != nil {
		t.Fatal(err)
	}
	var url, connID string
	if err := conn.SQL().QueryRow(`SELECT COALESCE(slack_webhook_url,''), slack_connection_id FROM governance_settings WHERE tenant_id=$1`, tenant).Scan(&url, &connID); err != nil {
		t.Fatal(err)
	}
	if url != "" || connID != "pbconn_governance_slack" {
		t.Fatalf("after migration: url=%q connection=%q", url, connID)
	}
	got, err := svc.GetSettings(ctx, tenant)
	if err != nil || !got.NotifySlack || got.SlackConnectionID != connID {
		t.Fatalf("settings %+v %v", got, err)
	}
	legacy, _ := store.ListLegacyNotifyURLs(ctx)
	for _, g := range legacy {
		if g.TenantID == tenant {
			t.Fatal("tenant still listed with a plaintext URL")
		}
	}
}
