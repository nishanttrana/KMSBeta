package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	pkgdb "vecta-kms/pkg/db"
)

type nopPublisher struct{}

func (nopPublisher) Publish(_ context.Context, _ string, _ []byte) error { return nil }

func newSecretsService(t *testing.T) (*Service, *SQLStore) {
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
	if err := createSecretsSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	mek := []byte("0123456789ABCDEF0123456789ABCDEF")
	return NewService(store, nopPublisher{}, mek), store
}

func createSecretsSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE secrets (
			id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			name TEXT NOT NULL,
			secret_type TEXT NOT NULL,
			description TEXT,
			labels TEXT NOT NULL DEFAULT '{}',
			metadata TEXT NOT NULL DEFAULT '{}',
			status TEXT NOT NULL DEFAULT 'active',
			lease_ttl_seconds INTEGER NOT NULL DEFAULT 0,
			expires_at TIMESTAMP,
			current_version INTEGER NOT NULL DEFAULT 1,
			created_by TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id),
			UNIQUE (tenant_id, name)
		);`,
		`CREATE TABLE secret_values (
			tenant_id TEXT NOT NULL,
			secret_id TEXT NOT NULL,
			version INTEGER NOT NULL,
			wrapped_dek BLOB NOT NULL,
			wrapped_dek_iv BLOB NOT NULL,
			ciphertext BLOB NOT NULL,
			data_iv BLOB NOT NULL,
			value_hash BLOB NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, secret_id, version)
		);`,
	}
	for _, stmt := range stmts {
		if _, err := conn.SQL().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func TestEnvelopeEncryptionAtRestRoundTrip(t *testing.T) {
	svc, store := newSecretsService(t)
	ctx := context.Background()
	created, err := svc.CreateSecret(ctx, CreateSecretRequest{
		TenantID:   "t1",
		Name:       "db-password",
		SecretType: "password",
		Value:      "super-secret-value",
		CreatedBy:  "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, encrypted, err := store.GetSecretWithValue(ctx, "t1", created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encrypted.Ciphertext), "super-secret-value") {
		t.Fatalf("ciphertext should not contain plaintext")
	}
	out, err := svc.GetSecretValue(ctx, "t1", created.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	if out.Value != "super-secret-value" {
		t.Fatalf("unexpected round-trip value %q", out.Value)
	}
}

func TestListSecretExcludesValue(t *testing.T) {
	svc, _ := newSecretsService(t)
	ctx := context.Background()
	_, err := svc.CreateSecret(ctx, CreateSecretRequest{
		TenantID:   "t2",
		Name:       "api-token",
		SecretType: "api_key",
		Value:      "abcd",
		CreatedBy:  "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	items, err := svc.ListSecrets(ctx, "t2", "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(items)
	if strings.Contains(string(raw), "\"value\"") {
		t.Fatalf("list response must not include secret value")
	}
}

func TestTTLExpiryReturnsGoneError(t *testing.T) {
	svc, store := newSecretsService(t)
	ctx := context.Background()
	created, err := svc.CreateSecret(ctx, CreateSecretRequest{
		TenantID:        "t3",
		Name:            "short-lease",
		SecretType:      "token",
		Value:           "token-123",
		LeaseTTLSeconds: 30,
		CreatedBy:       "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.db.SQL().ExecContext(ctx, `UPDATE secrets SET expires_at = DATETIME('now', '-1 minute') WHERE tenant_id = 't3' AND id = ?`, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.GetSecretValue(ctx, "t3", created.ID, "")
	if !errors.Is(err, errExpired) {
		t.Fatalf("expected errExpired, got %v", err)
	}
}

func TestFormatConversions(t *testing.T) {
	svc, _ := newSecretsService(t)
	ctx := context.Background()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	_, err = svc.CreateSecret(ctx, CreateSecretRequest{
		TenantID:   "t4",
		Name:       "ssh-key",
		SecretType: "ssh_private_key",
		Value:      string(privPEM),
		CreatedBy:  "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	items, err := svc.ListSecrets(ctx, "t4", "ssh_private_key", 10, 0)
	if err != nil || len(items) != 1 {
		t.Fatalf("list ssh: len=%d err=%v", len(items), err)
	}
	sshID := items[0].ID

	ppk, err := svc.GetSecretValue(ctx, "t4", sshID, "ppk")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ppk.Value, "PuTTY-User-Key-File-2") {
		t.Fatalf("expected PPK content, got %q", ppk.Value)
	}
	openSSH, err := svc.GetSecretValue(ctx, "t4", sshID, "openssh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(openSSH.Value, "ssh-ed25519") {
		t.Fatalf("expected ssh-ed25519, got %q", openSSH.Value)
	}
	_ = pub

	pgp, err := svc.CreateSecret(ctx, CreateSecretRequest{
		TenantID:   "t4",
		Name:       "pgp-key",
		SecretType: "pgp_private_key",
		Value:      "pgp-binary",
		CreatedBy:  "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	armored, err := svc.GetSecretValue(ctx, "t4", pgp.ID, "armored")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(armored.Value, "BEGIN PGP PRIVATE KEY BLOCK") {
		t.Fatalf("expected armored pgp")
	}

	p12, err := svc.CreateSecret(ctx, CreateSecretRequest{
		TenantID:   "t4",
		Name:       "bundle",
		SecretType: "pkcs12",
		Value:      "binary-data",
		CreatedBy:  "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	extract, err := svc.GetSecretValue(ctx, "t4", p12.ID, "extract")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(extract.Value, "raw_base64") {
		t.Fatalf("expected pkcs12 extract payload")
	}
}

func TestGenerateSSHKey(t *testing.T) {
	svc, _ := newSecretsService(t)
	ctx := context.Background()
	secret, pub, err := svc.GenerateSSHKey(ctx, GenerateSSHKeyRequest{
		TenantID:  "t5",
		Name:      "generated-key",
		CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(pub, "ssh-ed25519") {
		t.Fatalf("expected ssh-ed25519 public key, got %q", pub)
	}
	val, err := svc.GetSecretValue(ctx, "t5", secret.ID, "pem")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(val.Value, "BEGIN PRIVATE KEY") {
		t.Fatalf("expected PEM private key")
	}
}

func TestSupportedTypesAtLeast17(t *testing.T) {
	if len(supportedSecretTypes) < 17 {
		t.Fatalf("expected at least 17 secret types, got %d", len(supportedSecretTypes))
	}
}
