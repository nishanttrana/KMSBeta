package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// The release history keeps whether a key was released and the recipient
// binding, on real Postgres (migrations 001-003).
func TestReleaseRecordRoundTripPostgres(t *testing.T) {
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
	store := NewSQLStore(conn)
	rec := AttestedReleaseRecord{ID: newID("rel"), TenantID: "t-pg", KeyID: "k1", Provider: "aws_nitro_enclaves",
		Decision: "allow", Allowed: true, Released: true, RecipientKeyBinding: "abc-binding", CreatedAt: time.Now().UTC()}
	if err := store.InsertReleaseRecord(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetReleaseRecord(ctx, "t-pg", rec.ID)
	if err != nil || !got.Released || got.RecipientKeyBinding != "abc-binding" {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	list, err := store.ListReleaseRecords(ctx, "t-pg", 10)
	if err != nil || len(list) == 0 || !list[0].Released {
		t.Fatalf("list: %v %v", list, err)
	}
}
