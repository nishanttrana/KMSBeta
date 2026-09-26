package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
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

// A secret row under the public dev key is re-wrapped by its service before
// it goes into a new backup. A backup that still holds such a row (a copy
// made before the upgrade) is re-wrapped on restore before any row lands.
func TestBackupReprotectPostgres(t *testing.T) {
	svc, pub := newIntegrationGovernance(t)
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

	// A copy taken as before the upgrade: the row went in as it was.
	_, old := takeBackup(t, svc, systemBackup())

	// With the service down, no backup is taken of a row under a public key,
	// and the refusal is audited.
	svc.rewrapper = downRewrapper{}
	if _, _, err := svc.CreateBackup(context.Background(), systemBackup()); err == nil {
		t.Fatal("backup of a row under a public key went ahead without the service")
	}
	if len(pub.events["audit.governance.backup_create_refused"]) != 1 {
		t.Fatal("backup_create_refused not audited")
	}

	// A new backup: the service re-wraps the row before it is captured.
	rw := &keyRewrapper{dev: dev, cur: cur}
	svc.rewrapper = rw
	_, fresh := takeBackup(t, svc, systemBackup())
	if len(rw.restoring) == 0 || rw.restoring[0] {
		t.Fatalf("capture did not ask the service to re-wrap (as a non-restore): %v", rw.restoring)
	}

	// Restoring the new backup brings the row back under the service key,
	// even with every service down: it holds nothing under a public key.
	svc.rewrapper = downRewrapper{}
	if _, err := db.Exec(`DELETE FROM secret_values`); err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.restore(svc, "root"); err != nil {
		t.Fatalf("restore new backup: %v", err)
	}
	if !secretRowUnder(t, db, cur) {
		t.Fatal("new backup held the row under the public dev key")
	}

	// The old copy with a service down is refused, and nothing lands.
	if _, err := db.Exec(`DELETE FROM secret_values`); err != nil {
		t.Fatal(err)
	}
	if _, err := old.restore(svc, "root"); err == nil {
		t.Fatal("restore of rows under a public key went ahead without the service")
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM secret_values`).Scan(&n)
	if n != 0 {
		t.Fatal("a refused restore wrote rows")
	}

	// The old copy with the service up: re-wrapped before it lands, and sent
	// as a restore so the service records the exposure.
	rw.restoring = nil
	svc.rewrapper = rw
	if _, err := old.restore(svc, "root"); err != nil {
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

type downRewrapper struct{}

func (downRewrapper) Rewrap(context.Context, string, mek.RewrapRequest) ([]mek.RewrapResult, error) {
	return nil, errors.New("connection refused")
}

func unb64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
func b64(b []byte) string            { return base64.StdEncoding.EncodeToString(b) }
