package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// Azure EKM vaults on real Postgres (CI integration-postgres): migrations
// 008 and 009 (re-runnable), a vault naming a credential, and a plaintext
// client secret emptied when it moves into the credential store.
func TestAzureCredentialsPostgres(t *testing.T) {
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
	tenant := "t-ekm-" + time.Now().UTC().Format("150405.000000")
	t.Cleanup(func() { _, _ = conn.SQL().Exec(`DELETE FROM ekm_azure_configs WHERE tenant_id=$1`, tenant) })
	store := NewSQLStore(conn)

	if err := store.CreateAzureEKMConfig(ctx, AzureEKMConfig{ID: "az-new", TenantID: tenant, AzureTenantID: "entra", VaultName: "kv", VaultURL: "https://kv.vault.azure.net",
		ClientID: "app", ConnectionID: "pbconn_1", AuthMode: "client_secret", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAzureEKMConfig(ctx, AzureEKMConfig{ID: "az-old", TenantID: tenant, AzureTenantID: "entra", VaultName: "kv-old", VaultURL: "https://kv-old.vault.azure.net",
		ClientID: "app", ClientSecret: "plaintext", AuthMode: "client_secret", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	pending, err := store.ListLegacyAzureSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mine := 0
	for _, c := range pending {
		if c.TenantID == tenant {
			mine++
			if c.ID != "az-old" || c.ClientSecret != "plaintext" {
				t.Fatalf("legacy listing: %+v", c)
			}
		}
	}
	if mine != 1 {
		t.Fatalf("legacy vaults for the tenant: %d", mine)
	}
	if err := store.SetAzureConfigConnection(ctx, tenant, "az-old", "pbconn_ekm_az-old"); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetAzureEKMConfig(ctx, tenant, "az-old")
	if err != nil || got.ClientSecret != "" || got.ConnectionID != "pbconn_ekm_az-old" {
		t.Fatalf("moved vault: %+v %v", got, err)
	}
	// An update changes the credential and never writes a secret.
	got.ConnectionID, got.ClientSecret = "pbconn_2", "must-not-be-stored"
	if err := store.UpdateAzureEKMConfig(ctx, got); err != nil {
		t.Fatal(err)
	}
	var secret, connID string
	if err := conn.SQL().QueryRow(`SELECT client_secret, connection_id FROM ekm_azure_configs WHERE tenant_id=$1 AND id='az-old'`, tenant).Scan(&secret, &connID); err != nil || secret != "" || connID != "pbconn_2" {
		t.Fatalf("after update: secret %q connection %q (%v)", secret, connID, err)
	}
}
