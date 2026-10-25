package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pkgcache "vecta-kms/pkg/cache"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/metering"
)

// Migration 039 and the schedule stores on real Postgres: integrity
// schedules round-trip, a paused one is not due, and a rotation policy keeps
// its authorizer and pause.
func TestSchedulingStoresPostgres(t *testing.T) {
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
	_ = NewService(store, NewKeyCache(pkgcache.NewMemory(time.Minute), time.Minute), nopPublisher{}, metering.NewMeter(0, time.Hour), []byte("0123456789ABCDEF0123456789ABCDEF"), nil, false)
	tenant := "t-sched-pg-" + strings.ToLower(newID("x")[2:10])
	past := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	now := time.Now().UTC().Truncate(time.Microsecond)
	sch := IntegritySchedule{ID: "kis-1", TenantID: tenant, Name: "all", TargetFilter: "*", IntervalHrs: 24, Enabled: true,
		AuthorizedBy: "alice", NextRunAt: &past, LastResult: "failed", LastChecked: 3, LastFailed: 1, LastNotAssessed: 1, CreatedAt: now, UpdatedAt: now}
	if err := store.PutIntegritySchedule(ctx, sch); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetIntegritySchedule(ctx, tenant, "kis-1")
	if err != nil || got.AuthorizedBy != "alice" || got.LastFailed != 1 || got.NextRunAt == nil || !got.NextRunAt.Equal(past) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	due := func() int {
		items, err := store.ListDueIntegritySchedules(ctx, time.Now().UTC(), 500)
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
	got.PausedReason = "alice no longer holds key.integrity.verify"
	if err := store.PutIntegritySchedule(ctx, got); err != nil {
		t.Fatal(err)
	}
	if due() != 0 {
		t.Fatal("paused schedule listed as due")
	}
	if err := store.DeleteIntegritySchedule(ctx, tenant, "kis-1"); err != nil {
		t.Fatal(err)
	}

	p, err := store.CreateRotationPolicy(ctx, RotationPolicy{ID: newID("rp"), TenantID: tenant, Name: "pg", TargetType: "key", TargetFilter: "*",
		IntervalDays: 7, AutoRotate: true, Enabled: true, Status: "active", NextRotationAt: &past, AuthorizedBy: "alice"})
	if err != nil || p.AuthorizedBy != "alice" {
		t.Fatalf("create policy: %+v %v", p, err)
	}
	if err := store.HoldRotationPolicy(ctx, tenant, p.ID, now.Add(time.Hour), "alice is no longer an active user"); err != nil {
		t.Fatal(err)
	}
	p, _ = store.GetRotationPolicy(ctx, tenant, p.ID)
	if p.PausedReason == "" {
		t.Fatalf("hold not stored: %+v", p)
	}
	items, _ := store.ListDueRotationPolicies(ctx, now.Add(2*time.Hour), 500)
	for _, it := range items {
		if it.ID == p.ID {
			t.Fatal("paused policy listed as due")
		}
	}
	var gone int
	if err := conn.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_tables WHERE tablename = 'key_scheduling_jobs'`).Scan(&gone); err != nil || gone != 0 {
		t.Fatalf("key_scheduling_jobs still exists: %d %v", gone, err)
	}
}
