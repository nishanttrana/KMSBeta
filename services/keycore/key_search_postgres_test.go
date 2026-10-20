package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pkgcache "vecta-kms/pkg/cache"
	"vecta-kms/pkg/metering"
	pkgdb "vecta-kms/pkg/db"
)

// Key search on Postgres: case-insensitive, LIKE wildcards literal (the
// ESCAPE clause), restricted to a scope (13.25.0-beta).
func TestKeySearchPostgres(t *testing.T) {
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
	tenant := "t-search-pg-" + strings.ToLower(newID("x")[2:10])
	for _, k := range []struct{ name, by string }{{"Payments_DB", "alice"}, {"paymentsXdb", "alice"}, {"payments_api", "bob"}, {"100%_key", "alice"}} {
		if _, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: tenant, Name: k.name, Algorithm: "AES-256",
			KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: k.by}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(scope *KeyScope, q string) int {
		t.Helper()
		keys, err := svc.store.SearchKeys(ctx, tenant, scope, q, 50)
		if err != nil {
			t.Fatal(err)
		}
		return len(keys)
	}
	if n := count(nil, "payments"); n != 3 {
		t.Fatalf("case-insensitive: %d", n)
	}
	if n := count(nil, "payments_"); n != 2 {
		t.Fatalf("_ literal: %d", n)
	}
	if n := count(nil, "0%_"); n != 1 {
		t.Fatalf("%% literal: %d", n)
	}
	if n := count(&KeyScope{CreatedBy: []string{"bob"}}, "payments"); n != 1 {
		t.Fatalf("scoped: %d", n)
	}
}
