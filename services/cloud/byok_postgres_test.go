package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// BYOK storage on real Postgres (CI integration-postgres): migration 004 is
// re-runnable, settings and steps round-trip as JSON, nullable expiry and
// revocation times survive, and materials update in place.
func TestBYOKStorePostgres(t *testing.T) {
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
	for i := 0; i < 2; i++ {
		if err := conn.RunMigrations(ctx, "migrations"); err != nil {
			t.Fatalf("migrations (pass %d): %v", i+1, err)
		}
	}
	tenant := "t-byok-" + time.Now().UTC().Format("150405.000000")
	t.Cleanup(func() {
		for _, tbl := range []string{"cloud_byok_keys", "cloud_byok_materials", "cloud_byok_runs"} {
			_, _ = conn.SQL().Exec(`DELETE FROM `+tbl+` WHERE tenant_id=$1`, tenant)
		}
	})
	store := NewSQLStore(conn)
	exp := time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Second)
	k := BYOKKey{ID: "byok_1", TenantID: tenant, AccountID: "ca", Provider: ProviderSalesforce, KeyID: "key-1", Source: SourceHSM,
		Origin: OriginBYOK, KeySpec: SpecAES256, Usage: "encrypt", MaterialState: MaterialPending, CreatedBy: "alice",
		Settings: map[string]string{"certificate_name": "BYOK_Cert", "secret_type": "Data"}}
	if err := store.CreateBYOKKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	k.MaterialState, k.CurrentMatID, k.ExpiresAt = MaterialCurrent, "0Ax001", &exp
	if err := store.UpdateBYOKKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetBYOKKey(ctx, tenant, "byok_1")
	if err != nil || got.Settings["certificate_name"] != "BYOK_Cert" || got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) || got.MaterialState != MaterialCurrent {
		t.Fatalf("key round trip: %+v %v", got, err)
	}
	m := BYOKMaterial{ID: "bmat_1", TenantID: tenant, BYOKID: "byok_1", KMSVersion: 1, KCV: "ABCDEF", CloudMaterialID: "0Ax001",
		State: MaterialCurrent, Scheme: "rsa-oaep-sha1", Source: SourceHSM, ImportedAt: time.Now().UTC()}
	if err := store.PutBYOKMaterial(ctx, m); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	m.State, m.RevokedAt = MaterialRevoked, &now
	if err := store.PutBYOKMaterial(ctx, m); err != nil {
		t.Fatal(err)
	}
	mats, err := store.ListBYOKMaterials(ctx, tenant, "byok_1")
	if err != nil || len(mats) != 1 || mats[0].State != MaterialRevoked || mats[0].RevokedAt == nil || mats[0].ExpiresAt != nil {
		t.Fatalf("material update in place: %+v %v", mats, err)
	}
	run := BYOKRun{ID: "brun_1", TenantID: tenant, BYOKID: "byok_1", Operation: OpCreate, Status: "succeeded", Actor: "alice",
		Steps: []BYOKStep{{Name: "Wrap", Status: "succeeded", CLI: "aws kms ..."}}, StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC()}
	if err := store.PutBYOKRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	runs, err := store.ListBYOKRuns(ctx, tenant, "", 10)
	if err != nil || len(runs) != 1 || len(runs[0].Steps) != 1 || runs[0].Steps[0].CLI != "aws kms ..." {
		t.Fatalf("runs: %+v %v", runs, err)
	}
}
