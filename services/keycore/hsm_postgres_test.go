package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pkgcache "vecta-kms/pkg/cache"
	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/hsmconnector/softhsmtest"
	"vecta-kms/pkg/metering"
)

// HSM key storage on real Postgres (migration 021): the protection columns,
// empty material for an HSM-resident version, the settings upsert, and both
// kinds of key working end to end with SoftHSM2 (CI integration-postgres).
func TestHSMStoragePostgres(t *testing.T) {
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
	tenant := "t-hsm-pg-" + strings.ToLower(newID("x")[2:10])
	srv := softhsmtest.Start(t, "kms-keycore", tenant)
	svc := NewService(NewSQLStore(conn), NewKeyCache(pkgcache.NewMemory(time.Minute), time.Minute), nopPublisher{},
		metering.NewMeter(0, time.Hour), []byte("0123456789ABCDEF0123456789ABCDEF"), nil, false)
	svc.SetHSMBackend(hsm.New(srv.URL))
	actx := adminCtx()

	if _, err := svc.UpdateHSMSettings(actx, HSMSettings{TenantID: tenant, TenantKeyEnabled: true, HSMKeysEnabled: true, UpdatedBy: "it"}); err != nil {
		t.Fatal(err)
	}
	// The upsert updates in place.
	st, err := svc.UpdateHSMSettings(actx, HSMSettings{TenantID: tenant, TenantKeyEnabled: true, HSMKeysEnabled: true, UpdatedBy: "it2"})
	if err != nil || st.UpdatedBy != "it2" || st.TenantKeyLabel != hsm.TenantKeyLabel(tenant) {
		t.Fatalf("settings: %v %+v", err, st)
	}

	for _, tc := range []struct {
		inHSM bool
		want  string
	}{{true, protectionHSMResident}, {false, protectionTenantHSM}} {
		key, err := svc.CreateKey(actx, CreateKeyRequest{TenantID: tenant, Name: tc.want, Algorithm: "AES-256", Purpose: "encrypt", Owner: "ops", HSM: tc.inHSM})
		if err != nil {
			t.Fatal(err)
		}
		v, err := svc.store.GetVersion(ctx, tenant, key.ID, 1)
		if err != nil {
			t.Fatal(err)
		}
		if v.Protection != tc.want || v.HSMLabel == "" {
			t.Fatalf("%s: stored %q %q", tc.want, v.Protection, v.HSMLabel)
		}
		if tc.inHSM && (len(v.EncryptedMaterial) != 0 || len(v.WrappedDEK) != 0) {
			t.Fatal("Postgres holds material for an HSM-resident key")
		}
		enc, err := svc.Encrypt(actx, key.ID, EncryptRequest{TenantID: tenant, PlaintextB64: b64([]byte("pg"))})
		if err != nil {
			t.Fatalf("%s encrypt: %v", tc.want, err)
		}
		dec, err := svc.Decrypt(actx, key.ID, DecryptRequest{TenantID: tenant, CiphertextB64: enc.CipherB64, IVB64: enc.IVB64})
		if err != nil || dec.PlainB64 != b64([]byte("pg")) {
			t.Fatalf("%s decrypt: %v", tc.want, err)
		}
		vs, err := svc.store.ListVersions(ctx, tenant, key.ID)
		if err != nil || len(vs) != 1 || vs[0].Protection != tc.want {
			t.Fatalf("list versions: %v %+v", err, vs)
		}
	}
}
