package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pkgcache "vecta-kms/pkg/cache"
	pkgcrypto "vecta-kms/pkg/crypto"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/fips/fipstest"
	"vecta-kms/pkg/metering"
)

// The relabel job reads keys across tenants and updates them on real Postgres
// (row-level security and the real schema), not only SQLite.
func TestCorrectKeyAlgorithmLabelsPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	fipstest.SkipIfStrict(t, "fixtures store non-approved algorithm names")
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	pub := &captureKeycorePublisher{}
	svc := NewService(NewSQLStore(conn), NewKeyCache(pkgcache.NewMemory(time.Minute), time.Minute), pub,
		metering.NewMeter(0, time.Hour), []byte("0123456789ABCDEF0123456789ABCDEF"), nil, false)
	random32, _ := pkgcrypto.RandomBytes(32)
	p256, _ := generateMaterialForCreate("ECDSA-P256", "asymmetric-private")
	want := map[string]string{}
	for i, f := range []struct {
		alg      string
		material []byte
		actual   string
	}{{"XMSS-SHA256-H10", random32, invalidKeyMaterial}, {"ECDSA-Brainpool-P256r1", p256, "ECDSA-P256"}} {
		tenant := "t-relabel-" + strings.ToLower(newID("x")[2:8]) + string(rune('a'+i))
		k, err := svc.createKeyFromMaterial(ctx, CreateKeyRequest{TenantID: tenant, Name: f.alg, Algorithm: f.alg, KeyType: "asymmetric-private", Purpose: "sign-verify", Owner: "ops", CreatedBy: "it"}, f.material, "", "key.create", "audit.key.create")
		if err != nil {
			t.Fatalf("fixture %s: %v", f.alg, err)
		}
		want[tenant+"/"+k.ID] = f.actual
	}
	if _, err := svc.CorrectKeyAlgorithmLabels(ctx); err != nil {
		t.Fatal(err)
	}
	for ref, alg := range want {
		parts := strings.SplitN(ref, "/", 2)
		k, err := svc.GetKey(ctx, parts[0], parts[1])
		if err != nil || k.Algorithm != alg {
			t.Fatalf("%s: %q, want %q (%v)", ref, k.Algorithm, alg, err)
		}
	}
}
