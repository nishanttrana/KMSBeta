package main

import (
	"context"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	pkgcache "vecta-kms/pkg/cache"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/metering"
)

// Rotation policy storage on real Postgres: migrations (025 closes the old
// fake 'running' rows), the cross-tenant due query, outcome recording and
// per-key runs written by a scheduled run (CI integration-postgres).
func TestRotationSchedulerPostgres(t *testing.T) {
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
	svc := NewService(NewSQLStore(conn), NewKeyCache(pkgcache.NewMemory(time.Minute), time.Minute), nopPublisher{},
		metering.NewMeter(0, time.Hour), []byte("0123456789ABCDEF0123456789ABCDEF"), nil, false)
	tenant := "t-rot-pg-" + strings.ToLower(newID("x")[2:10])
	key, err := svc.CreateKey(adminCtx(), CreateKeyRequest{TenantID: tenant, Name: "pg-app-1", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "it", Tags: []string{"pci"}})
	if err != nil {
		t.Fatal(err)
	}
	due := time.Now().UTC().Add(-time.Minute)
	pid := newID("rp")
	if _, err := svc.store.CreateRotationPolicy(ctx, RotationPolicy{ID: pid, TenantID: tenant, Name: "pg", TargetType: "key", TargetFilter: "tag:pci",
		IntervalDays: 7, AutoRotate: true, Enabled: true, Status: "active", NextRotationAt: &due}); err != nil {
		t.Fatal(err)
	}
	sched := NewRotationScheduler(svc, nil, log.Default())
	sched.primary = func(context.Context) bool { return true }
	sched.Tick(ctx)

	k, err := svc.store.GetKey(ctx, tenant, key.ID)
	if err != nil || k.CurrentVersion != 2 {
		t.Fatalf("key not rotated: %v %d", err, k.CurrentVersion)
	}
	p, err := svc.store.GetRotationPolicy(ctx, tenant, pid)
	if err != nil || p.TotalRotations != 1 || p.Status != "active" || p.NextRotationAt == nil || p.NextRotationAt.Before(time.Now().Add(6*24*time.Hour)) {
		t.Fatalf("policy after run: %v %+v", err, p)
	}
	runs, err := svc.store.ListRotationRuns(ctx, tenant, pid)
	if err != nil || len(runs) != 1 || runs[0].Status != "success" || runs[0].CompletedAt == nil || runs[0].TriggeredBy != "schedule" {
		t.Fatalf("runs: %v %+v", err, runs)
	}
	stillDue, err := svc.store.ListDueRotationPolicies(ctx, time.Now().UTC(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range stillDue {
		if d.ID == pid {
			t.Fatal("policy still due after its run")
		}
	}
}
