package main

import (
	"context"
	"sync"
	"testing"

	pkgdb "vecta-kms/pkg/db"
)

type nopDataProtectPublisher struct {
	mu       sync.Mutex
	subjects []string
}

func (p *nopDataProtectPublisher) Publish(_ context.Context, subject string, _ []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.subjects = append(p.subjects, subject)
	return nil
}

func (p *nopDataProtectPublisher) Count(subject string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, s := range p.subjects {
		if s == subject {
			n++
		}
	}
	return n
}

type fakeDataProtectKeyCore struct {
	items map[string]map[string]interface{}
}

func (f *fakeDataProtectKeyCore) GetKey(_ context.Context, _ string, keyID string) (map[string]interface{}, error) {
	if item, ok := f.items[keyID]; ok {
		return item, nil
	}
	return map[string]interface{}{"id": keyID, "kcv": "ABCD12"}, nil
}

func newDataProtectService(t *testing.T) (*Service, *SQLStore, *nopDataProtectPublisher) {
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
	if err := createDataProtectSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	pub := &nopDataProtectPublisher{}
	svc := NewService(store, &fakeDataProtectKeyCore{items: map[string]map[string]interface{}{
		"key-1":   {"id": "key-1", "kcv": "AAAA01", "algorithm": "AES-256", "key_type": "symmetric", "purpose": "encrypt-decrypt", "status": "active"},
		"key-2":   {"id": "key-2", "kcv": "BBBB02", "algorithm": "AES-256", "key_type": "symmetric", "purpose": "encrypt-decrypt", "status": "active"},
		"key-rsa": {"id": "key-rsa", "kcv": "CCCC03", "algorithm": "RSA-2048", "key_type": "asymmetric", "purpose": "sign-verify", "status": "active"},
	}}, pub)
	return svc, store, pub
}

func newDataProtectHandler(t *testing.T) (*Handler, *Service, *nopDataProtectPublisher) {
	t.Helper()
	svc, _, pub := newDataProtectService(t)
	return NewHandler(svc), svc, pub
}

func createDataProtectSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE token_vaults (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			name TEXT NOT NULL,
			mode TEXT NOT NULL DEFAULT 'vault',
			token_type TEXT NOT NULL,
			format TEXT NOT NULL,
			key_id TEXT NOT NULL,
			custom_regex TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE tokens (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			vault_id TEXT NOT NULL,
			token TEXT NOT NULL,
			original_enc BLOB NOT NULL,
			original_hash TEXT NOT NULL DEFAULT '',
			format_metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE masking_policies (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			name TEXT NOT NULL,
			target_type TEXT NOT NULL,
			field_path TEXT NOT NULL,
			mask_pattern TEXT NOT NULL,
			roles_full_json TEXT NOT NULL DEFAULT '[]',
			roles_partial_json TEXT NOT NULL DEFAULT '[]',
			roles_redacted_json TEXT NOT NULL DEFAULT '[]',
			consistent BOOLEAN NOT NULL DEFAULT TRUE,
			key_id TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE redaction_policies (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			name TEXT NOT NULL,
			patterns_json TEXT NOT NULL DEFAULT '[]',
			scope TEXT NOT NULL DEFAULT 'all',
			action TEXT NOT NULL DEFAULT 'replace_placeholder',
			placeholder TEXT NOT NULL DEFAULT '[REDACTED]',
			applies_to_json TEXT NOT NULL DEFAULT '[]',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE fle_metadata (
			tenant_id TEXT NOT NULL,
			id TEXT NOT NULL,
			document_id TEXT NOT NULL,
			field_path TEXT NOT NULL,
			key_id TEXT NOT NULL,
			key_version INTEGER NOT NULL DEFAULT 1,
			algorithm TEXT NOT NULL,
			iv BLOB,
			searchable BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id)
		);`,
	}
	for _, stmt := range stmts {
		if _, err := conn.SQL().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}
