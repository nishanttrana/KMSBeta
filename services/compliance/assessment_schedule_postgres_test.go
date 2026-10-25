package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// Migration 011 on real Postgres: the schedule keeps its authority and last
// result, and a paused one is not due.
func TestAssessmentScheduleStorePostgres(t *testing.T) {
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
	store := NewSQLStore(conn)
	tenant := "t-assess-" + time.Now().UTC().Format("150405.000000")
	item := AssessmentSchedule{TenantID: tenant, Enabled: true, Frequency: "daily", AuthorizedBy: "alice",
		LastResult: "assessed", LastAssessmentID: "as-1", NextRunAt: time.Now().UTC().Add(-time.Minute)}
	if err := store.UpsertAssessmentSchedule(ctx, item); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetAssessmentSchedule(ctx, tenant)
	if err != nil || got.AuthorizedBy != "alice" || got.LastAssessmentID != "as-1" {
		t.Fatalf("get: %+v %v", got, err)
	}
	due := func() int {
		items, err := store.ListDueAssessmentSchedules(ctx, time.Now().UTC(), 500)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, it := range items {
			if it.TenantID == tenant {
				n++
			}
		}
		return n
	}
	if due() != 1 {
		t.Fatal("due schedule not listed")
	}
	got.PausedReason = "alice no longer holds compliance.assessment.write"
	if err := store.UpsertAssessmentSchedule(ctx, got); err != nil {
		t.Fatal(err)
	}
	if due() != 0 {
		t.Fatal("paused schedule listed as due")
	}
}
