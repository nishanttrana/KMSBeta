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

func (f *fakeDataProtectKeyCore) MeterUsage(_ context.Context, _ string, _ string, _ string) error {
	return nil
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
			use_count INTEGER NOT NULL DEFAULT 0,
			use_limit INTEGER NOT NULL DEFAULT 0,
			renew_count INTEGER NOT NULL DEFAULT 0,
			metadata_tags_json TEXT NOT NULL DEFAULT '{}',
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
		`CREATE TABLE data_protection_policy (
			tenant_id TEXT PRIMARY KEY,
			allowed_data_algorithms_json TEXT NOT NULL DEFAULT '["AES-GCM","AES-SIV","CHACHA20-POLY1305"]',
			require_aad_for_aead BOOLEAN NOT NULL DEFAULT FALSE,
			max_fields_per_operation INTEGER NOT NULL DEFAULT 64,
			max_document_bytes INTEGER NOT NULL DEFAULT 262144,
			allow_vaultless_tokenization BOOLEAN NOT NULL DEFAULT TRUE,
			tokenization_mode_policy_json TEXT NOT NULL DEFAULT '{}',
			token_format_policy_json TEXT NOT NULL DEFAULT '{}',
			require_token_ttl BOOLEAN NOT NULL DEFAULT FALSE,
			max_token_ttl_hours INTEGER NOT NULL DEFAULT 0,
			allow_token_renewal BOOLEAN NOT NULL DEFAULT TRUE,
			max_token_renewals INTEGER NOT NULL DEFAULT 3,
			allow_one_time_tokens BOOLEAN NOT NULL DEFAULT TRUE,
			detokenize_allowed_purposes_json TEXT NOT NULL DEFAULT '[]',
			detokenize_allowed_workflows_json TEXT NOT NULL DEFAULT '[]',
			require_detokenize_justification BOOLEAN NOT NULL DEFAULT FALSE,
			allow_bulk_tokenize BOOLEAN NOT NULL DEFAULT TRUE,
			allow_bulk_detokenize BOOLEAN NOT NULL DEFAULT TRUE,
			allow_redaction_detect_only BOOLEAN NOT NULL DEFAULT TRUE,
			allowed_redaction_detectors_json TEXT NOT NULL DEFAULT '["EMAIL","PHONE","SSN","PAN","IBAN","NAME","CUSTOM"]',
			allowed_redaction_actions_json TEXT NOT NULL DEFAULT '["replace_placeholder","remove","hash"]',
			allow_custom_regex_tokens BOOLEAN NOT NULL DEFAULT TRUE,
			max_custom_regex_length INTEGER NOT NULL DEFAULT 512,
			max_custom_regex_groups INTEGER NOT NULL DEFAULT 16,
			max_token_batch INTEGER NOT NULL DEFAULT 10000,
			max_detokenize_batch INTEGER NOT NULL DEFAULT 10000,
			require_token_context_tags BOOLEAN NOT NULL DEFAULT FALSE,
			required_token_context_keys_json TEXT NOT NULL DEFAULT '[]',
			masking_role_policy_json TEXT NOT NULL DEFAULT '{}',
			token_metadata_retention_days INTEGER NOT NULL DEFAULT 365,
			redaction_event_retention_days INTEGER NOT NULL DEFAULT 365,
			updated_by TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
	}
	for _, stmt := range stmts {
		if _, err := conn.SQL().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}
