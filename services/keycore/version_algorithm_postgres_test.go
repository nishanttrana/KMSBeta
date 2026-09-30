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

// Algorithm change by rotation on real Postgres: migration 034 adds
// key_versions.algorithm and drops agility_migration_plans; the rotation pins
// the old version's algorithm, and the old version still decrypts.
func TestVersionAlgorithmPostgres(t *testing.T) {
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
	var plans int
	if err := conn.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_name='agility_migration_plans'`).Scan(&plans); err != nil || plans != 0 {
		t.Fatalf("agility_migration_plans not dropped: %v %d", err, plans)
	}
	svc := NewService(NewSQLStore(conn), NewKeyCache(pkgcache.NewMemory(time.Minute), time.Minute), nopPublisher{},
		metering.NewMeter(0, time.Hour), []byte("0123456789ABCDEF0123456789ABCDEF"), nil, false)
	tenant := "t-valg-pg-" + strings.ToLower(newID("x")[2:10])
	key, err := svc.CreateKey(adminCtx(), CreateKeyRequest{TenantID: tenant, Name: "pg-agile", Algorithm: "AES-128", KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "it"})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := svc.Encrypt(adminCtx(), key.ID, EncryptRequest{TenantID: tenant, PlaintextB64: "c2VjcmV0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RotateKeyTo(adminCtx(), tenant, key.ID, "agility", "", "AES-256"); err != nil {
		t.Fatal(err)
	}
	v1, err := svc.store.GetVersion(ctx, tenant, key.ID, 1)
	if err != nil || v1.Algorithm != "AES-128" || v1.Status != "deactivated" {
		t.Fatalf("v1 %v %+v", err, v1)
	}
	if k, _ := svc.store.GetKey(ctx, tenant, key.ID); k.Algorithm != "AES-256" {
		t.Fatalf("key algorithm %q", k.Algorithm)
	}
	dec, err := svc.Decrypt(adminCtx(), key.ID, DecryptRequest{TenantID: tenant, CiphertextB64: enc.CipherB64, IVB64: enc.IVB64, Version: 1})
	if err != nil || dec.PlainB64 != "c2VjcmV0" {
		t.Fatalf("decrypt v1 on Postgres: %v %+v", err, dec)
	}
}
