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

// GET /keys/due-for-lifecycle on real Postgres: an active key past its
// operator expiry is due for rotation; a compromised or long-deactivated key
// is not returned at all (destroy is never automatic).
func TestDueForLifecyclePostgres(t *testing.T) {
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
	svc.SetCryptoperiodPolicy(NewCryptoperiodPolicy())
	tenant := "t-life-pg-" + strings.ToLower(newID("x")[2:10])
	create := func(name string) Key {
		k, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: tenant, Name: name, Algorithm: "AES-256",
			KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "alice"})
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	expired, compromised, deactivated := create("expired"), create("compromised"), create("deactivated")
	longAgo := time.Now().UTC().Add(-90 * 24 * time.Hour)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE keys SET expiry_date = $1 WHERE tenant_id = $2 AND id = $3`, []any{time.Now().UTC().Add(-time.Hour), tenant, expired.ID}},
		{`UPDATE keys SET status = 'compromised', updated_at = $1 WHERE tenant_id = $2 AND id = $3`, []any{longAgo, tenant, compromised.ID}},
		{`UPDATE keys SET status = 'deactivated', updated_at = $1 WHERE tenant_id = $2 AND id = $3`, []any{longAgo, tenant, deactivated.ID}},
	} {
		if _, err := conn.SQL().ExecContext(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	items, err := svc.dueForLifecycle(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, it := range items {
		if it.TenantID == tenant {
			got[it.KeyID] = it.Action
		}
	}
	if got[expired.ID] != "rotate" || len(got) != 1 {
		t.Fatalf("due items for the tenant: %v (want only %s: rotate)", got, expired.ID)
	}

	// The tenant's own cryptoperiod (30 days for encryption keys) makes a
	// 60-day-old key due; the built-in 2 years would not.
	aged := create("aged")
	if _, err := conn.SQL().ExecContext(ctx, `UPDATE keys SET created_at = $1, updated_at = $1 WHERE tenant_id = $2 AND id = $3`, time.Now().UTC().Add(-60*24*time.Hour), tenant, aged.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.SetCryptoperiodOverride(ctx, tenant, "symmetric_encrypt", 30, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := svc.store.SetCryptoperiodOverride(ctx, tenant, "symmetric_encrypt", 31, "alice"); err != nil { // upsert
		t.Fatal(err)
	}
	items, err = svc.dueForLifecycle(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	due := false
	for _, it := range items {
		due = due || (it.TenantID == tenant && it.KeyID == aged.ID && it.Action == "rotate")
	}
	if !due {
		t.Fatal("a 60-day-old key was not due under the tenant's 31-day cryptoperiod")
	}
}
