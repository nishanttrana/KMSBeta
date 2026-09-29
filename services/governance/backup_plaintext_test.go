package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// A catalogued table still holding plaintext secret material (workload
// signing keys before 6.11.0-beta) never goes into a new backup. A restore
// of an older backup may carry it; the owning service seals it and records
// it as exposed.
func TestBackupRefusesPlaintextSigningKeys(t *testing.T) {
	tables := func(caKey string) map[string]json.RawMessage {
		row, _ := json.Marshal([]map[string]interface{}{{"tenant_id": "t1", "local_ca_key_pem": caKey, "jwt_signer_private_pem": ""}})
		return map[string]json.RawMessage{"workload_identity_settings": row}
	}
	_, err := reprotectTables(context.Background(), passThroughRewrapper{}, tables("-----BEGIN PRIVATE KEY-----"), false)
	if err == nil || !strings.Contains(err.Error(), "kms-workload-identity") {
		t.Fatalf("capture with plaintext signing keys: %v", err)
	}
	if _, err := reprotectTables(context.Background(), passThroughRewrapper{}, tables("-----BEGIN PRIVATE KEY-----"), true); err != nil {
		t.Fatalf("restore refused: %v", err)
	}
	if _, err := reprotectTables(context.Background(), passThroughRewrapper{}, tables(""), false); err != nil {
		t.Fatalf("capture of sealed rows refused: %v", err)
	}
}

// On real Postgres: CreateBackup refuses, audits backup_create_refused, and
// goes ahead once the row is sealed.
func TestBackupRefusesPlaintextSigningKeysPostgres(t *testing.T) {
	svc, pub := newIntegrationGovernance(t)
	db := svc.store.(*SQLStore).db.SQL()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS workload_identity_settings (
		tenant_id TEXT PRIMARY KEY, trust_domain TEXT NOT NULL,
		local_ca_key_pem TEXT NOT NULL DEFAULT '', jwt_signer_private_pem TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	const tenant = "t-gov-plaintext-signing"
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM workload_identity_settings WHERE tenant_id = $1`, tenant) })
	if _, err := db.Exec(`INSERT INTO workload_identity_settings (tenant_id, trust_domain, local_ca_key_pem) VALUES ($1, 'x', 'PLAINTEXT-PEM')
		ON CONFLICT (tenant_id) DO UPDATE SET local_ca_key_pem = 'PLAINTEXT-PEM'`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.CreateBackup(context.Background(), systemBackup()); err == nil {
		t.Fatal("backup captured plaintext signing keys")
	}
	if len(pub.events["audit.governance.backup_create_refused"]) != 1 {
		t.Fatal("backup_create_refused not audited")
	}
	if _, err := db.Exec(`UPDATE workload_identity_settings SET local_ca_key_pem = '' WHERE tenant_id = $1`, tenant); err != nil {
		t.Fatal(err)
	}
	takeBackup(t, svc, systemBackup())
}
