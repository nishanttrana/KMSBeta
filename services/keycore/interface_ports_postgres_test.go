package main

import (
	"context"
	"os"
	"strings"
	"testing"

	pkgdb "vecta-kms/pkg/db"
)

// Migration 032 drops key_interface_ports and key_interface_tls_defaults on
// real Postgres, from a fresh schema and from one that still has them.
func TestInterfacePortTablesDroppedPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 2, MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	gone := func(when string) {
		t.Helper()
		var n int
		if err := conn.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_name IN ('key_interface_ports','key_interface_tls_defaults')`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: interface tables still exist: n=%d err=%v", when, n, err)
		}
	}
	gone("fresh schema")
	// A database migrated before 6.8.0-beta still has them (004, 006, 007).
	for _, stmt := range []string{
		`CREATE TABLE key_interface_ports (tenant_id TEXT NOT NULL, interface_name TEXT NOT NULL, bind_address TEXT NOT NULL DEFAULT '0.0.0.0', port INTEGER NOT NULL, PRIMARY KEY (tenant_id, interface_name))`,
		`ALTER TABLE key_interface_ports ENABLE ROW LEVEL SECURITY`,
		`CREATE POLICY tenant_isolation_key_interface_ports ON key_interface_ports USING (tenant_id = current_setting('app.tenant_id', true))`,
		`CREATE TABLE key_interface_tls_defaults (tenant_id TEXT PRIMARY KEY, certificate_source TEXT NOT NULL DEFAULT 'internal_ca')`,
	} {
		if _, err := conn.SQL().ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	drop, err := os.ReadFile("migrations/032_drop_interface_ports.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.SQL().ExecContext(ctx, string(drop)); err != nil {
		t.Fatalf("032 on an upgraded database: %v", err)
	}
	gone("upgraded schema")
}
