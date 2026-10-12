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

// The description column on real Postgres: migration 035 applies, a key
// created without one reads as "", and the stored text is untouched by the
// metadata update and replaced by its own.
func TestKeyDescriptionPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := adminCtx()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	store := NewSQLStore(conn)
	svc := NewService(store, NewKeyCache(pkgcache.NewMemory(time.Minute), time.Minute), nopPublisher{},
		metering.NewMeter(0, time.Hour), []byte("0123456789ABCDEF0123456789ABCDEF"), nil, false)
	tenant := "t-desc-pg-" + strings.ToLower(newID("x")[2:10])

	plain, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: tenant, Name: "no-description", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	described, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: tenant, Name: "described", Description: "Ledger envelope key — owner: payments", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	read := func(id string) string {
		t.Helper()
		k, err := store.GetKey(ctx, tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		return k.Description
	}
	if got := read(plain.ID); got != "" {
		t.Fatalf("a key without a description reads %q", got)
	}
	if got := read(described.ID); got != "Ledger envelope key — owner: payments" {
		t.Fatalf("description = %q", got)
	}
	listed, err := store.ListKeys(ctx, tenant, 10, 0)
	if err != nil || len(listed) != 2 {
		t.Fatalf("list: %d keys, %v", len(listed), err)
	}

	// The metadata update leaves it; the dedicated update replaces and clears it.
	if err := svc.UpdateKey(ctx, tenant, described.ID, UpdateKeyRequest{Name: "described", Purpose: "encrypt"}); err != nil {
		t.Fatal(err)
	}
	if got := read(described.ID); got != "Ledger envelope key — owner: payments" {
		t.Fatalf("a metadata update changed the description to %q", got)
	}
	for _, text := range []string{"Retired", ""} {
		if err := store.SetKeyDescription(ctx, tenant, described.ID, text); err != nil {
			t.Fatal(err)
		}
		if got := read(described.ID); got != text {
			t.Fatalf("description = %q, want %q", got, text)
		}
	}
	if err := store.SetKeyDescription(ctx, tenant, "key_missing", "x"); err != errStoreNotFound {
		t.Fatalf("a missing key: %v", err)
	}
}
