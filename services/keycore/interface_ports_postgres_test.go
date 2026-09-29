package main

import (
	"context"
	"os"
	"strings"
	"testing"

	pkgdb "vecta-kms/pkg/db"
)

// Migration 031 drops key_interface_ports.pqc_mode on real Postgres, from a
// fresh schema and from one that still has it, and an interface still round-trips through the store without it.
func TestInterfacePQCModeDroppedPostgres(t *testing.T) {
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
	// A database migrated before 6.4.0-beta still has the column (008).
	if _, err := conn.SQL().ExecContext(ctx, `ALTER TABLE key_interface_ports ADD COLUMN IF NOT EXISTS pqc_mode TEXT NOT NULL DEFAULT 'inherit'`); err != nil {
		t.Fatal(err)
	}
	drop, err := os.ReadFile("migrations/031_drop_interface_pqc_mode.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.SQL().ExecContext(ctx, string(drop)); err != nil {
		t.Fatalf("031 on an upgraded database: %v", err)
	}
	var n int
	if err := conn.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'key_interface_ports' AND column_name = 'pqc_mode'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("pqc_mode column still exists: n=%d err=%v", n, err)
	}
	store := NewSQLStore(conn)
	tenant := "t-pg-ifpqc-" + strings.ToLower(newID("x")[2:8])
	in := KeyInterfacePort{TenantID: tenant, InterfaceName: "kmip", BindAddress: "0.0.0.0", Port: 5696, Protocol: "mtls", CertSource: "internal_ca", Enabled: true, UpdatedBy: "it"}
	if _, err := store.UpsertKeyInterfacePort(ctx, in); err != nil {
		t.Fatal(err)
	}
	got, err := store.ListKeyInterfacePorts(ctx, tenant)
	if err != nil || len(got) != 1 || got[0].Protocol != "mtls" || got[0].Port != 5696 {
		t.Fatalf("round trip: %+v %v", got, err)
	}
}
