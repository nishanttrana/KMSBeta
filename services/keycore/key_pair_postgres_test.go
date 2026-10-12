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

// A pair's rotation on real Postgres: both keys get their version in one
// transaction, and when the public key's version cannot be written the
// private key's is rolled back with it.
func TestPairRotationPostgres(t *testing.T) {
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
	tenant := "t-pair-pg-" + strings.ToLower(newID("x")[2:10])
	private, public := newPair(t, svc, tenant, "signer", "ECDSA-P256")

	if _, err := svc.RotateKey(ctx, tenant, private.ID, "scheduled", "deactivate"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if !inStep(t, svc, tenant, private, public) {
		t.Fatal("the public key did not follow its private key")
	}
	versions := func() (int, int) {
		t.Helper()
		a, err := store.GetKey(ctx, tenant, private.ID)
		if err != nil {
			t.Fatal(err)
		}
		b, err := store.GetKey(ctx, tenant, public.ID)
		if err != nil {
			t.Fatal(err)
		}
		return a.CurrentVersion, b.CurrentVersion
	}
	if a, b := versions(); a != 2 || b != 2 {
		t.Fatalf("versions after the rotation: private %d, public %d", a, b)
	}

	// The public key's version reuses an id that exists: its insert fails.
	privVer, privRaw := currentMaterial(t, svc, tenant, private.ID)
	pubVer, _ := currentMaterial(t, svc, tenant, public.ID)
	nextPriv := KeyVersion{ID: newID("kv"), TenantID: tenant, KeyID: private.ID, Version: 3, KCV: privVer.KCV, RotatedFrom: 2, Status: "active"}
	if err := svc.protectMaterial(ctx, &nextPriv, privRaw); err != nil {
		t.Fatal(err)
	}
	nextPub := KeyVersion{ID: pubVer.ID, TenantID: tenant, KeyID: public.ID, Version: 3, KCV: pubVer.KCV, RotatedFrom: 2, Status: "active",
		EncryptedMaterial: pubVer.EncryptedMaterial, MaterialIV: pubVer.MaterialIV, WrappedDEK: pubVer.WrappedDEK}
	if err := store.RotatePairVersions(ctx, tenant, private.ID, nextPriv, public.ID, nextPub, "broken", "deactivate"); err == nil {
		t.Fatal("a pair rotation whose public version cannot be written succeeded")
	}
	if a, b := versions(); a != 2 || b != 2 {
		t.Fatalf("a failed pair rotation left private at %d and public at %d", a, b)
	}
	if v, err := svc.GetVersion(ctx, tenant, private.ID, 2); err != nil || v.Status != "active" {
		t.Fatalf("the private key's current version was changed by the failed rotation: %+v %v", v.Status, err)
	}
	if !inStep(t, svc, tenant, private, public) {
		t.Fatal("the pair is out of step after a failed rotation")
	}
}
