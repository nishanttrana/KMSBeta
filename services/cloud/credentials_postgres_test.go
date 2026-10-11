package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// Cloud accounts on real Postgres (CI integration-postgres): migration 003
// (re-runnable) lets an account hold no credentials of its own, and moving a
// legacy account onto a credential clears its sealed columns to NULL, which
// pkg/mek then skips.
func TestAccountCredentialsPostgres(t *testing.T) {
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
	tenant := "t-cloud-" + time.Now().UTC().Format("150405.000000")
	t.Cleanup(func() { _, _ = conn.SQL().Exec(`DELETE FROM cloud_accounts WHERE tenant_id=$1`, tenant) })
	store := NewSQLStore(conn)

	fresh := CloudAccount{ID: "ca-new", TenantID: tenant, Provider: ProviderAWS, Name: "new", Status: "configured", ConnectionID: "pbconn_1"}
	if err := store.CreateAccount(ctx, fresh); err != nil {
		t.Fatalf("an account without sealed credentials: %v", err)
	}
	legacy := CloudAccount{ID: "ca-old", TenantID: tenant, Provider: ProviderAzure, Name: "old", Status: "configured",
		CredentialsWrappedDEK: []byte("w"), CredentialsWrappedDEKIV: []byte("v"), CredentialsCiphertext: []byte("c"), CredentialsDataIV: []byte("i")}
	if err := store.CreateAccount(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetAccount(ctx, tenant, "ca-new")
	if err != nil || got.ConnectionID != "pbconn_1" || len(got.CredentialsCiphertext) != 0 {
		t.Fatalf("new account: %+v %v", got, err)
	}
	pending, err := store.ListLegacyCredentialAccounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mine := 0
	for _, a := range pending {
		if a.TenantID == tenant {
			mine++
			if a.ID != "ca-old" || string(a.CredentialsCiphertext) != "c" {
				t.Fatalf("legacy listing: %+v", a)
			}
		}
	}
	if mine != 1 {
		t.Fatalf("legacy accounts for the tenant: %d", mine)
	}
	if err := store.SetAccountConnection(ctx, tenant, "ca-old", "pbconn_cloud_ca-old"); err != nil {
		t.Fatal(err)
	}
	var nulls int
	if err := conn.SQL().QueryRow(`SELECT COUNT(*) FROM cloud_accounts WHERE tenant_id=$1 AND creds_wrapped_dek IS NULL AND creds_ciphertext IS NULL AND creds_data_iv IS NULL AND creds_wrapped_dek_iv IS NULL`, tenant).Scan(&nulls); err != nil || nulls != 2 {
		t.Fatalf("sealed columns after the move: %d NULL rows (%v)", nulls, err)
	}
	if got, _ := store.GetAccount(ctx, tenant, "ca-old"); got.ConnectionID != "pbconn_cloud_ca-old" {
		t.Fatalf("moved account: %+v", got)
	}
	if err := store.SetAccountConnection(ctx, tenant, "ca-none", "x"); err != errNotFound {
		t.Fatalf("unknown account: %v", err)
	}
}
