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

// Migration 005 on real Postgres: a schedule keeps its authority and last
// run, and a paused one is not due.
func TestScheduledReportStorePostgres(t *testing.T) {
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
	tenant := "t-sched-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	item := ScheduledReport{ID: "sched-1", TenantID: tenant, Name: "weekly", TemplateID: "alert_summary", Format: "pdf", Schedule: "weekly",
		Enabled: true, AuthorizedBy: "alice", NextRunAt: time.Now().UTC().Add(-time.Minute)}
	if err := store.CreateScheduledReport(ctx, item); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetScheduledReport(ctx, tenant, "sched-1")
	if err != nil || got.AuthorizedBy != "alice" {
		t.Fatalf("get: %+v %v", got, err)
	}
	got.LastResult, got.LastJobID, got.LastRunAt = "requested", "rjob-1", time.Now().UTC()
	if err := store.SaveScheduledReport(ctx, got); err != nil {
		t.Fatal(err)
	}
	due := func() int {
		items, err := store.ListDueScheduledReports(ctx, time.Now().UTC(), 500)
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
	got.PausedReason = "alice is no longer an active user"
	if err := store.SaveScheduledReport(ctx, got); err != nil {
		t.Fatal(err)
	}
	if due() != 0 {
		t.Fatal("paused schedule listed as due")
	}
	if again, _ := store.GetScheduledReport(ctx, tenant, "sched-1"); again.LastJobID != "rjob-1" || again.LastResult != "requested" {
		t.Fatalf("last run not stored: %+v", again)
	}
	if err := store.DeleteScheduledReport(ctx, tenant, "sched-1"); err != nil {
		t.Fatal(err)
	}
}
