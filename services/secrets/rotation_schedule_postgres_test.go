package main

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"vecta-kms/pkg/authority"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/route/routetest"
)

// Migration 009 on real Postgres: a generated key's schedule joins its
// secret (JSONB labels give the path), runs from the tick, and goes when
// the secret is destroyed.
func TestRotationSchedulesPostgres(t *testing.T) {
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
	tenant := "t-rot-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	svc := NewService(NewSQLStore(conn), []byte("0123456789ABCDEF0123456789ABCDEF"))
	h := NewHandler(svc, &routetest.Recorder{}, nil, nil)
	h.authority = stubAuthority{answer: authority.Answer{Active: true, Role: "tenant-admin"}}
	key, _, err := svc.GenerateSSHKey(ctx, GenerateSSHKeyRequest{TenantID: tenant, Name: "deploy", Labels: map[string]string{"folder": "ops"}, CreatedBy: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().UTC().Add(-time.Minute)
	now := time.Now().UTC()
	if err := svc.store.PutRotationSchedule(ctx, SecretRotationSchedule{TenantID: tenant, SecretID: key.ID, IntervalHours: 24, Enabled: true,
		AuthorizedBy: "alice", NextRunAt: &past, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	items, err := svc.store.ListRotationSchedules(ctx, tenant)
	if err != nil || len(items) != 1 || items[0].SecretPath != key.Path || items[0].SecretName != "deploy" {
		t.Fatalf("list: %+v %v (path %q)", items, err, key.Path)
	}
	h.rotateDue(ctx, time.Now().UTC())
	got, err := svc.store.GetRotationSchedule(ctx, tenant, key.ID)
	if err != nil || got.LastResult != "rotated" || got.LastVersion != 2 || got.NextRunAt == nil || !got.NextRunAt.After(time.Now().UTC()) {
		t.Fatalf("after run: %+v %v", got, err)
	}
	if err := svc.DestroySecret(ctx, tenant, key.ID, "alice"); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := conn.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM secret_rotation_schedules WHERE tenant_id=$1`, tenant).Scan(&left); err != nil || left != 0 {
		t.Fatalf("schedule left after destroy: %d %v", left, err)
	}
}
