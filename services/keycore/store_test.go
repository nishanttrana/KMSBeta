package main

import (
	"context"
	"errors"
	"testing"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

func newStoreForTest(t *testing.T) *SQLStore {
	t.Helper()
	conn, err := pkgdb.Open(context.Background(), pkgdb.Config{
		UseSQLite:  true,
		SQLitePath: ":memory:",
		MaxOpen:    1,
		MaxIdle:    1,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := createSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return NewSQLStore(conn)
}

func createSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE keys (
			id TEXT NOT NULL, tenant_id TEXT NOT NULL, name TEXT NOT NULL, algorithm TEXT NOT NULL, key_type TEXT NOT NULL,
			purpose TEXT NOT NULL, status TEXT NOT NULL, current_version INTEGER NOT NULL, kcv BLOB, kcv_algorithm TEXT,
			iv_mode TEXT, owner TEXT NOT NULL, cloud TEXT, region TEXT, compliance BLOB, labels BLOB,
			tags BLOB, export_allowed BOOLEAN NOT NULL DEFAULT 0,
			activation_date TIMESTAMP, expiry_date TIMESTAMP,
			destroy_date TIMESTAMP,
			ops_total INTEGER DEFAULT 0, ops_encrypt INTEGER DEFAULT 0, ops_decrypt INTEGER DEFAULT 0, ops_sign INTEGER DEFAULT 0,
			ops_limit INTEGER DEFAULT 0, ops_limit_window TEXT, ops_last_reset TIMESTAMP, approval_required BOOLEAN DEFAULT 0,
			approval_policy_id TEXT, created_by TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE key_versions (
			id TEXT NOT NULL, tenant_id TEXT NOT NULL, key_id TEXT NOT NULL, version INTEGER NOT NULL,
			encrypted_material BLOB NOT NULL, material_iv BLOB NOT NULL, wrapped_dek BLOB NOT NULL, public_key BLOB, kcv BLOB,
			rotated_from INTEGER, rotation_reason TEXT, status TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE key_iv_log (
			id TEXT NOT NULL, tenant_id TEXT NOT NULL, key_id TEXT NOT NULL, key_version INTEGER NOT NULL,
			iv BLOB NOT NULL, operation TEXT NOT NULL, reference_id TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE key_tags (
			tenant_id TEXT NOT NULL, name TEXT NOT NULL, color TEXT NOT NULL, is_system BOOLEAN NOT NULL DEFAULT 0,
			created_by TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, name)
		);`,
		`CREATE TABLE key_access_grants (
			tenant_id TEXT NOT NULL, key_id TEXT NOT NULL, subject_type TEXT NOT NULL, subject_id TEXT NOT NULL,
			operations BLOB, created_by TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			not_before TIMESTAMP, expires_at TIMESTAMP, justification TEXT, ticket_id TEXT,
			PRIMARY KEY (tenant_id, key_id, subject_type, subject_id)
		);`,
	}
	for _, s := range stmts {
		if _, err := conn.SQL().Exec(s); err != nil {
			return err
		}
	}
	return nil
}

func TestStoreCreateAndGetKey(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	k := Key{
		ID: "k1", TenantID: "t1", Name: "key1", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Status: "active", CurrentVersion: 1, KCV: []byte{0x01, 0x02, 0x03}, KCVAlgorithm: "aes-ecb-zero", IVMode: "internal",
		Owner: "ops", Labels: map[string]string{"env": "dev"}, CreatedBy: "tester",
	}
	v := KeyVersion{
		ID: "kv1", TenantID: "t1", KeyID: "k1", Version: 1, EncryptedMaterial: []byte("enc"),
		MaterialIV: []byte("123456789012"), WrappedDEK: []byte("1234567890123456wrapped"), KCV: []byte{0x01, 0x02, 0x03}, Status: "active",
	}
	if err := s.CreateKeyWithVersion(ctx, k, v); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetKey(ctx, "t1", "k1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "key1" || got.Algorithm != "AES-256" {
		t.Fatalf("unexpected key: %+v", got)
	}
}

func TestStoreRunCryptoTxOpsLimit(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	k := Key{
		ID: "k2", TenantID: "t1", Name: "key2", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Status: "active", CurrentVersion: 1, KCV: []byte{0x01, 0x02, 0x03}, KCVAlgorithm: "aes-ecb-zero", IVMode: "internal",
		Owner: "ops", CreatedBy: "tester", OpsLimit: 2, OpsLimitWindow: "total", OpsLastReset: time.Now().UTC(),
	}
	v := KeyVersion{
		ID: "kv2", TenantID: "t1", KeyID: "k2", Version: 1, EncryptedMaterial: []byte("enc"),
		MaterialIV: []byte("123456789012"), WrappedDEK: []byte("1234567890123456wrapped"), KCV: []byte{0x01, 0x02, 0x03}, Status: "active",
	}
	if err := s.CreateKeyWithVersion(ctx, k, v); err != nil {
		t.Fatal(err)
	}
	cb := func(_ Key, _ KeyVersion) (CryptoTxResult, error) {
		return CryptoTxResult{Payload: []byte("ok"), IV: []byte("123456789012"), StoreIV: true}, nil
	}
	if _, err := s.RunCryptoTx(ctx, "t1", "k2", "encrypt", cb); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunCryptoTx(ctx, "t1", "k2", "encrypt", cb); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RunCryptoTx(ctx, "t1", "k2", "encrypt", cb); !errors.Is(err, errOpsLimit) {
		t.Fatalf("expected errOpsLimit, got %v", err)
	}
	usage, err := s.GetUsage(ctx, "t1", "k2")
	if err != nil {
		t.Fatal(err)
	}
	if usage.OpsTotal != 2 || usage.OpsEncrypt != 2 {
		t.Fatalf("unexpected usage: %+v", usage)
	}
}

func TestStoreScheduleDestroyAndPurge(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	k := Key{
		ID: "k3", TenantID: "t1", Name: "key3", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Status: "active", CurrentVersion: 1, KCV: []byte{0x01, 0x02, 0x03}, KCVAlgorithm: "aes-ecb-zero", IVMode: "internal",
		Owner: "ops", CreatedBy: "tester",
	}
	v := KeyVersion{
		ID: "kv3", TenantID: "t1", KeyID: "k3", Version: 1, EncryptedMaterial: []byte("enc"),
		MaterialIV: []byte("123456789012"), WrappedDEK: []byte("1234567890123456wrapped"), KCV: []byte{0x01, 0x02, 0x03}, Status: "active",
	}
	if err := s.CreateKeyWithVersion(ctx, k, v); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_access_grants (tenant_id, key_id, subject_type, subject_id, operations, created_by)
VALUES ('t1','k3','user','u1','["encrypt"]','tester')
`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_iv_log (id, tenant_id, key_id, key_version, iv, operation, reference_id)
VALUES ('iv1','t1','k3',1,?, 'encrypt', 'ref-1')
`, []byte("123456789012")); err != nil {
		t.Fatal(err)
	}
	if err := s.ScheduleDestroy(ctx, "t1", "k3", time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	deleted, err := s.PurgeDueDestroyed(ctx, "t1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 1 || deleted[0].KeyID != "k3" {
		t.Fatalf("unexpected deleted keys: %+v", deleted)
	}
	if deleted[0].DeletedVersionCount != 1 || deleted[0].DeletedIVLogCount != 1 || deleted[0].DeletedAccessGrants != 1 {
		t.Fatalf("unexpected deleted artifact counts: %+v", deleted[0])
	}
	got, err := s.GetKey(ctx, "t1", "k3")
	if err != nil {
		t.Fatalf("expected key metadata to remain, got err=%v", err)
	}
	if got.Status != "deleted" {
		t.Fatalf("expected status deleted, got %s", got.Status)
	}
	if got.CurrentVersion != 0 {
		t.Fatalf("expected current_version=0, got %d", got.CurrentVersion)
	}
	if got.Purpose != "deleted" || got.Owner != "deleted" {
		t.Fatalf("expected scrubbed tombstone purpose/owner, got purpose=%q owner=%q", got.Purpose, got.Owner)
	}
	if got.ExportAllowed || got.ApprovalRequired || got.ApprovalPolicyID != "" {
		t.Fatalf("expected export/approval metadata reset, got export=%v approval_required=%v policy=%q", got.ExportAllowed, got.ApprovalRequired, got.ApprovalPolicyID)
	}
	if len(got.Tags) != 0 || len(got.Compliance) != 0 || len(got.Labels) != 0 {
		t.Fatalf("expected tags/compliance/labels scrubbed, got tags=%v compliance=%v labels=%v", got.Tags, got.Compliance, got.Labels)
	}
	versions, err := s.ListVersions(ctx, "t1", "k3")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 0 {
		t.Fatalf("expected versions to be removed, found %d", len(versions))
	}
	var grants int
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(1) FROM key_access_grants WHERE tenant_id='t1' AND key_id='k3'`).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 0 {
		t.Fatalf("expected key access grants to be removed, found %d", grants)
	}
}

func TestStoreHardDeleteKey(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	k := Key{
		ID: "k4", TenantID: "t1", Name: "key4", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Status: "active", CurrentVersion: 1, KCV: []byte{0x01, 0x02, 0x03}, KCVAlgorithm: "aes-ecb-zero", IVMode: "internal",
		Owner: "ops", CreatedBy: "tester",
	}
	v := KeyVersion{
		ID: "kv4", TenantID: "t1", KeyID: "k4", Version: 1, EncryptedMaterial: []byte("enc"),
		MaterialIV: []byte("123456789012"), WrappedDEK: []byte("1234567890123456wrapped"), KCV: []byte{0x01, 0x02, 0x03}, Status: "active",
	}
	if err := s.CreateKeyWithVersion(ctx, k, v); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_access_grants (tenant_id, key_id, subject_type, subject_id, operations, created_by)
VALUES ('t1','k4','user','u2','["encrypt"]','tester')
`); err != nil {
		t.Fatal(err)
	}
	if err := s.HardDeleteKey(ctx, "t1", "k4"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetKey(ctx, "t1", "k4"); !errors.Is(err, errStoreNotFound) {
		t.Fatalf("expected key to be removed, got err=%v", err)
	}
	versions, err := s.ListVersions(ctx, "t1", "k4")
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 0 {
		t.Fatalf("expected versions to be removed, found %d", len(versions))
	}
	var grants int
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(1) FROM key_access_grants WHERE tenant_id='t1' AND key_id='k4'`).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 0 {
		t.Fatalf("expected key access grants to be removed, found %d", grants)
	}
}

func TestStoreActivateDueKeys(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	when := time.Now().UTC().Add(-5 * time.Minute)
	k := Key{
		ID: "k5", TenantID: "t1", Name: "key5", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Status: "pre-active", ActivationDate: &when, CurrentVersion: 1, KCV: []byte{0x0a, 0x0b, 0x0c}, KCVAlgorithm: "aes-ecb-zero", IVMode: "internal",
		Owner: "ops", CreatedBy: "tester",
	}
	v := KeyVersion{
		ID: "kv5", TenantID: "t1", KeyID: "k5", Version: 1, EncryptedMaterial: []byte("enc"),
		MaterialIV: []byte("123456789012"), WrappedDEK: []byte("1234567890123456wrapped"), KCV: []byte{0x0a, 0x0b, 0x0c}, Status: "pre-active",
	}
	if err := s.CreateKeyWithVersion(ctx, k, v); err != nil {
		t.Fatal(err)
	}
	ids, err := s.ActivateDueKeys(ctx, "t1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "k5" {
		t.Fatalf("unexpected activated IDs: %+v", ids)
	}
	got, err := s.GetKey(ctx, "t1", "k5")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "active" {
		t.Fatalf("expected active status, got %s", got.Status)
	}
	if got.ActivationDate != nil {
		t.Fatalf("expected activation_date cleared, got %v", got.ActivationDate)
	}
}
