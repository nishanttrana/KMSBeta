package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

// Tokens are stored in the KMS. The external database vault only ever
// stored a database's address and labelled the vault "external"; nothing
// connected to it. Asking for it is refused and audited, by any of its
// fields, and nothing is created.
func TestExternalTokenVaultIsRefused(t *testing.T) {
	svc, _, pub := newDataProtectService(t)
	ctx := context.Background()
	base := TokenVault{Name: "cards", TokenType: "credit_card", Format: "deterministic", KeyID: "key-1"}
	asks := map[string]func(*TokenVault){
		"storage_type":  func(v *TokenVault) { v.StorageType = "external" },
		"a provider":    func(v *TokenVault) { v.ExternalProvider = "postgres" },
		"a config":      func(v *TokenVault) { v.ExternalConfig = map[string]string{"host": "db.example.com", "password_ref": "secret/db"} },
		"a schema":      func(v *TokenVault) { v.ExternalSchemaVersion = "v1" },
		"another label": func(v *TokenVault) { v.StorageType = "remote" },
	}
	n := 0
	for name, ask := range asks {
		in := base
		ask(&in)
		_, err := svc.CreateTokenVault(ctx, "t1", in)
		var se serviceError
		if !errors.As(err, &se) || se.HTTPStatus != http.StatusBadRequest || se.Code != reasonExternalVaultRemoved {
			t.Fatalf("%s: %v", name, err)
		}
		if n++; pub.Count("audit.dataprotect.token_vault_refused") != n {
			t.Fatalf("%s: refusal not audited", name)
		}
	}
	if pub.Count("audit.dataprotect.token_vault_created") != 0 {
		t.Fatal("a refused vault was audited as created")
	}
	if vaults, _ := svc.ListTokenVaults(ctx, "t1", 10, 0); len(vaults) != 0 {
		t.Fatalf("a refused vault was stored: %+v", vaults)
	}

	// A vault says where its tokens are.
	for _, st := range []string{"", "internal"} {
		in := base
		in.Name, in.StorageType = "cards-"+st, st
		v, err := svc.CreateTokenVault(ctx, "t1", in)
		if err != nil || v.StorageType != "internal" || v.ExternalProvider != "" || len(v.ExternalConfig) != 0 {
			t.Fatalf("storage %q: %+v %v", st, v, err)
		}
	}
}

// A vault an earlier release stored as "external" is read as what it is:
// internal, with none of the unused settings.
func TestStoredExternalVaultReadsAsInternal(t *testing.T) {
	_, store, _ := newDataProtectService(t)
	ctx := context.Background()
	if _, err := store.db.SQL().Exec(`INSERT INTO token_vaults (tenant_id, id, name, mode, storage_type, external_provider, external_config_json, external_schema_version, token_type, format, custom_token_format, key_id, custom_regex)
VALUES ('t1','vault_old','old','vault','external','postgres','{"host":"db.example.com","password_ref":"secret/db"}','v1','credit_card','deterministic','','key-1','')`); err != nil {
		t.Fatal(err)
	}
	v, err := store.GetTokenVault(ctx, "t1", "vault_old")
	if err != nil || v.StorageType != "internal" || v.ExternalProvider != "" || len(v.ExternalConfig) != 0 || v.ExternalSchemaVersion != "" {
		t.Fatalf("%+v %v", v, err)
	}
	// And the migration clears the stored label and settings.
	raw, err := os.ReadFile("migrations/012_token_vaults_internal_only.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.SQL().Exec(string(raw)); err != nil {
		t.Fatalf("migration 012: %v", err)
	}
	var storage, provider, config string
	_ = store.db.SQL().QueryRow(`SELECT storage_type, external_provider, external_config_json FROM token_vaults WHERE id='vault_old'`).Scan(&storage, &provider, &config)
	if storage != "internal" || provider != "" || strings.Contains(config, "password_ref") {
		t.Fatalf("after migration 012: %s %s %s", storage, provider, config)
	}
}

// Migration 012 on real Postgres (CI integration-postgres): it runs, and it
// clears the label and settings of a vault stored as external.
func TestTokenVaultsInternalOnlyPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 2, MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	id := "vault_pg_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	if _, err := conn.SQL().Exec(`INSERT INTO token_vaults (tenant_id, id, name, mode, storage_type, external_provider, external_config_json, external_schema_version, token_type, format, custom_token_format, key_id, custom_regex)
VALUES ('t-pg',$1,$1,'vault','external','postgres','{"host":"db.example.com","password_ref":"secret/db"}','v1','credit_card','deterministic','','key-1','')`, id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.SQL().Exec(`DELETE FROM token_vaults WHERE id=$1`, id) })
	raw, err := os.ReadFile("migrations/012_token_vaults_internal_only.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.SQL().Exec(string(raw)); err != nil {
		t.Fatalf("migration 012: %v", err)
	}
	var storage, provider, config string
	if err := conn.SQL().QueryRow(`SELECT storage_type, external_provider, external_config_json FROM token_vaults WHERE id=$1`, id).Scan(&storage, &provider, &config); err != nil {
		t.Fatal(err)
	}
	if storage != "internal" || provider != "" || config != "{}" {
		t.Fatalf("after migration 012: %s %s %s", storage, provider, config)
	}
	v, err := NewSQLStore(conn).GetTokenVault(ctx, "t-pg", id)
	if err != nil || v.StorageType != "internal" {
		t.Fatalf("read: %+v %v", v, err)
	}
}
