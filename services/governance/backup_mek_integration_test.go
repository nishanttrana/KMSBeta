package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"testing"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/mek"
)

// keyRewrapper stands in for a service's POST /mek/rewrap-legacy: it moves
// entries from the public dev key to the current key.
type keyRewrapper struct {
	dev, cur  []byte
	restoring []bool
}

func (k *keyRewrapper) Rewrap(_ context.Context, _ string, req mek.RewrapRequest) ([]mek.RewrapResult, error) {
	k.restoring = append(k.restoring, req.Restoring)
	out := make([]mek.RewrapResult, len(req.Entries))
	for i, e := range req.Entries {
		out[i] = mek.RewrapResult{IV: e.IV, DEK: e.DEK, Status: "unknown"}
		env := &pkgcrypto.EnvelopeCiphertext{}
		env.WrappedDEKIV, _ = unb64(e.IV)
		env.WrappedDEK, _ = unb64(e.DEK)
		switch {
		case pkgcrypto.EnvelopeWrappedUnder(k.cur, env):
			out[i].Status = "current"
		case pkgcrypto.EnvelopeWrappedUnder(k.dev, env):
			moved, err := pkgcrypto.RewrapEnvelope(k.dev, k.cur, env)
			if err != nil {
				return nil, err
			}
			out[i] = mek.RewrapResult{IV: b64(moved.WrappedDEKIV), DEK: b64(moved.WrappedDEK), Status: "rewrapped", Source: "dev_mek"}
		}
	}
	return out, nil
}

func secretRowUnder(t *testing.T, db *sql.DB, key []byte) bool {
	t.Helper()
	var env pkgcrypto.EnvelopeCiphertext
	if err := db.QueryRow(`SELECT wrapped_dek_iv, wrapped_dek FROM secret_values WHERE tenant_id='root' AND secret_id='sec_backup'`).Scan(&env.WrappedDEKIV, &env.WrappedDEK); err != nil {
		t.Fatal(err)
	}
	return pkgcrypto.EnvelopeWrappedUnder(key, &env)
}

// A backup holding a secret under the public dev key is re-protected in
// place (re-wrapped by the service, re-sealed under a new backup key), and a
// copy downloaded before that is re-wrapped on restore before any row lands.
func TestBackupReprotectPostgres(t *testing.T) {
	svc, pub := newIntegrationGovernance(t)
	ctx := context.Background()
	db := svc.store.(*SQLStore).db.SQL()
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS secret_values (
			tenant_id TEXT NOT NULL, secret_id TEXT NOT NULL, version INTEGER NOT NULL,
			wrapped_dek BYTEA NOT NULL, wrapped_dek_iv BYTEA NOT NULL, ciphertext BYTEA NOT NULL,
			data_iv BYTEA NOT NULL, value_hash BYTEA NOT NULL, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, secret_id, version))`,
		`DELETE FROM secret_values`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	dev := mek.Catalog["secrets"].LegacyKeysFromEnv()[0].Key
	cur, _ := pkgcrypto.RandomBytes(32)
	env, err := pkgcrypto.EncryptEnvelope(dev, []byte("backed-up secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO secret_values (tenant_id, secret_id, version, wrapped_dek, wrapped_dek_iv, ciphertext, data_iv, value_hash)
		VALUES ('root','sec_backup',1,$1,$2,$3,$4,'\x00')`, env.WrappedDEK, env.WrappedDEKIV, env.Ciphertext, env.DataIV); err != nil {
		t.Fatal(err)
	}
	rw := &keyRewrapper{dev: dev, cur: cur}
	svc.rewrapper = rw

	noHSM := false
	job, err := svc.CreateBackup(ctx, CreateBackupInput{TenantID: "root", Scope: "system", CreatedBy: "it", BindToHSM: &noHSM})
	if err != nil {
		t.Fatal(err)
	}
	before := downloadBackup(t, svc, "root", job.ID)

	if n, err := svc.ReprotectStoredBackups(ctx); err != nil || n < 1 {
		t.Fatalf("re-protect: %d %v", n, err)
	}
	if len(pub.events["audit.governance.backup_reprotected"]) == 0 {
		t.Fatal("backup_reprotected not audited")
	}
	after := downloadBackup(t, svc, "root", job.ID)
	if after.artifactB64 == before.artifactB64 || after.keyB64 == before.keyB64 {
		t.Fatal("the stored backup was not re-sealed")
	}
	// The key package downloaded before no longer opens the stored artifact.
	stale := backupFiles{artifactName: after.artifactName, artifactB64: after.artifactB64, keyName: before.keyName, keyB64: before.keyB64}
	if _, err := stale.restore(svc, "root"); err == nil {
		t.Fatal("the old key package still opens the re-protected backup")
	}
	// Nothing left to do on the next run.
	if pending, _ := svc.store.(*SQLStore).listUnreprotectedBackups(ctx); len(pending) != 0 {
		t.Fatalf("still pending: %v", pending)
	}

	// Restoring the re-protected backup brings the row back under the service key.
	if _, err := db.Exec(`DELETE FROM secret_values`); err != nil {
		t.Fatal(err)
	}
	if _, err := after.restore(svc, "root"); err != nil {
		t.Fatalf("restore re-protected backup: %v", err)
	}
	if !secretRowUnder(t, db, cur) {
		t.Fatal("restored row is not under the service key")
	}

	// A copy downloaded before re-protection: re-wrapped before it lands,
	// and sent as a restore so the service records the exposure.
	rw.restoring = nil
	if _, err := before.restore(svc, "root"); err != nil {
		t.Fatalf("restore old copy: %v", err)
	}
	if !secretRowUnder(t, db, cur) || secretRowUnder(t, db, dev) {
		t.Fatal("old copy restored a row under the public dev key")
	}
	sawRestoring := false
	for _, r := range rw.restoring {
		sawRestoring = sawRestoring || r
	}
	if !sawRestoring {
		t.Fatal("restore did not ask the service to record exposure")
	}
}

func unb64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
func b64(b []byte) string            { return base64.StdEncoding.EncodeToString(b) }
