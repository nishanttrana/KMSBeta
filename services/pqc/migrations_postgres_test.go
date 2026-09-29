package main

import (
	"context"
	"os"
	"strings"
	"testing"

	pkgdb "vecta-kms/pkg/db"
)

// Migration 003 drops the policy table and the readiness score column, and a
// scan still round-trips on real Postgres.
func TestPolicyAndScoreDroppedPostgres(t *testing.T) {
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
		t.Fatal(err)
	}
	var n int
	if err := conn.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'pqc_policies'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("pqc_policies still exists: n=%d err=%v", n, err)
	}
	if err := conn.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'pqc_readiness_scans' AND column_name = 'readiness_score'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("readiness_score column still exists: n=%d err=%v", n, err)
	}
	store := NewSQLStore(conn)
	scan := ReadinessScan{ID: newID("scan"), TenantID: "t-pg-pqc", Status: "completed", TotalAssets: 3, PQCReadyAssets: 1, HybridAssets: 1, ClassicalAssets: 1}
	if err := store.CreateReadinessScan(ctx, scan); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetReadinessScan(ctx, scan.TenantID, scan.ID)
	if err != nil || got.TotalAssets != 3 || got.PQCReadyAssets != 1 || got.ClassicalAssets != 1 {
		t.Fatalf("round trip: %+v %v", got, err)
	}
}
