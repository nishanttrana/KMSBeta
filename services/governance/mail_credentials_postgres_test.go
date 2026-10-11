package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// The mail relay setting on real Postgres (CI integration-postgres):
// migration 017 (re-runnable), and a plaintext relay cleared to NULL when it
// moves into the credential store.
func TestMailRelaySettingPostgres(t *testing.T) {
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
	for i := 0; i < 2; i++ {
		if err := conn.RunMigrations(ctx, "migrations"); err != nil {
			t.Fatalf("migrations (pass %d): %v", i+1, err)
		}
	}
	tenant := "t-mail-" + time.Now().UTC().Format("150405.000000")
	t.Cleanup(func() { _, _ = conn.SQL().Exec(`DELETE FROM governance_settings WHERE tenant_id=$1`, tenant) })
	store := NewSQLStore(conn)
	if err := store.UpsertSettings(ctx, GovernanceSettings{TenantID: tenant, SMTPHost: "smtp.old.test", SMTPPort: "587", SMTPUsername: "kms", SMTPPassword: "plaintext",
		ApprovalExpiryMinutes: 60, ExpiryCheckIntervalSeconds: 60, ApprovalDeliveryMode: "notify", DeliveryWebhookTimeoutSec: 5}); err != nil {
		t.Fatal(err)
	}
	pending, err := store.ListLegacySMTP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range pending {
		if g.TenantID == tenant {
			found = g.SMTPHost == "smtp.old.test" && g.SMTPPassword == "plaintext"
		}
	}
	if !found {
		t.Fatalf("legacy relay not listed: %+v", pending)
	}
	if err := store.SetSMTPConnection(ctx, tenant, "pbconn_governance_governance_smtp"); err != nil {
		t.Fatal(err)
	}
	var nulls int
	if err := conn.SQL().QueryRow(`SELECT COUNT(*) FROM governance_settings WHERE tenant_id=$1 AND smtp_host IS NULL AND smtp_password IS NULL AND smtp_username IS NULL`, tenant).Scan(&nulls); err != nil || nulls != 1 {
		t.Fatalf("smtp columns after the move: %d (%v)", nulls, err)
	}
	got, err := store.GetSettings(ctx, tenant)
	if err != nil || got.SMTPConnectionID != "pbconn_governance_governance_smtp" || got.SMTPHost != "" || got.SMTPPassword != "" {
		t.Fatalf("settings after the move: %+v %v", got, err)
	}
	after, _ := store.ListLegacySMTP(ctx)
	for _, g := range after {
		if g.TenantID == tenant {
			t.Fatal("a moved relay is still listed as legacy")
		}
	}
}
