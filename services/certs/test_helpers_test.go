package main

import (
	"context"
	"testing"

	pkgdb "vecta-kms/pkg/db"
)

type nopCertPublisher struct{}

func (nopCertPublisher) Publish(_ context.Context, _ string, _ []byte) error { return nil }

func newCertsService(t *testing.T) (*Service, *SQLStore) {
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
	if err := createCertsSchemaForTest(conn); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	store := NewSQLStore(conn)
	mek := []byte("0123456789ABCDEF0123456789ABCDEF")
	svc := NewService(store, nopCertPublisher{}, NoopKeyCoreSigner{}, mek, false, false)
	return svc, store
}

func createCertsSchemaForTest(conn *pkgdb.DB) error {
	stmts := []string{
		`CREATE TABLE cert_cas (
			id TEXT NOT NULL, tenant_id TEXT NOT NULL, name TEXT NOT NULL, parent_ca_id TEXT,
			ca_level TEXT NOT NULL, algorithm TEXT NOT NULL, ca_type TEXT NOT NULL, key_backend TEXT NOT NULL,
			key_ref TEXT NOT NULL DEFAULT '', cert_pem TEXT NOT NULL, subject TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'active', ots_current INTEGER NOT NULL DEFAULT 0, ots_max INTEGER NOT NULL DEFAULT 0,
			ots_alert_threshold INTEGER NOT NULL DEFAULT 0, signer_wrapped_dek BLOB NOT NULL, signer_wrapped_dek_iv BLOB NOT NULL,
			signer_ciphertext BLOB NOT NULL, signer_data_iv BLOB NOT NULL, signer_kek_version TEXT NOT NULL DEFAULT 'legacy-v1',
			signer_fingerprint_sha256 TEXT NOT NULL DEFAULT '', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (tenant_id, id), UNIQUE (tenant_id, name)
		);`,
		`CREATE TABLE cert_profiles (
			id TEXT NOT NULL, tenant_id TEXT NOT NULL, name TEXT NOT NULL, cert_type TEXT NOT NULL, algorithm TEXT NOT NULL,
			cert_class TEXT NOT NULL, profile_json TEXT NOT NULL DEFAULT '{}', is_default INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (tenant_id, id), UNIQUE (tenant_id, name)
		);`,
		`CREATE TABLE cert_certificates (
			id TEXT NOT NULL, tenant_id TEXT NOT NULL, ca_id TEXT NOT NULL, serial_number TEXT NOT NULL, subject_cn TEXT NOT NULL,
			sans_json TEXT NOT NULL DEFAULT '[]', cert_type TEXT NOT NULL, algorithm TEXT NOT NULL, profile_id TEXT NOT NULL DEFAULT '',
			protocol TEXT NOT NULL DEFAULT 'rest', cert_class TEXT NOT NULL DEFAULT 'classical', cert_pem TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active', not_before TIMESTAMP NOT NULL, not_after TIMESTAMP NOT NULL, revoked_at TIMESTAMP,
			revocation_reason TEXT NOT NULL DEFAULT '', key_ref TEXT NOT NULL DEFAULT '', created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (tenant_id, id), UNIQUE (tenant_id, serial_number)
		);`,
		`CREATE TABLE cert_revocations (
			tenant_id TEXT NOT NULL, cert_id TEXT NOT NULL, ca_id TEXT NOT NULL, serial_number TEXT NOT NULL,
			reason TEXT NOT NULL DEFAULT 'unspecified', revoked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, cert_id)
		);`,
		`CREATE TABLE cert_deleted_refs (
			tenant_id TEXT NOT NULL, cert_id TEXT NOT NULL, ca_id TEXT NOT NULL, serial_number TEXT NOT NULL,
			subject_cn TEXT NOT NULL, deleted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, cert_id)
		);`,
		`CREATE TABLE cert_acme_accounts (
			id TEXT NOT NULL, tenant_id TEXT NOT NULL, email TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'valid',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE cert_acme_orders (
			id TEXT NOT NULL, tenant_id TEXT NOT NULL, account_id TEXT NOT NULL DEFAULT '', ca_id TEXT NOT NULL,
			subject_cn TEXT NOT NULL, sans_json TEXT NOT NULL DEFAULT '[]', challenge_id TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending', csr_pem TEXT NOT NULL DEFAULT '', cert_id TEXT, created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (tenant_id, id)
		);`,
		`CREATE TABLE cert_protocol_configs (
			tenant_id TEXT NOT NULL, protocol TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, config_json TEXT NOT NULL DEFAULT '{}',
			updated_by TEXT NOT NULL DEFAULT '', updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, protocol)
		);`,
		`CREATE TABLE cert_expiry_alert_policies (
			tenant_id TEXT NOT NULL,
			days_before INTEGER NOT NULL DEFAULT 30,
			include_external INTEGER NOT NULL DEFAULT 1,
			updated_by TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id)
		);`,
		`CREATE TABLE cert_expiry_alert_state (
			tenant_id TEXT NOT NULL,
			cert_id TEXT NOT NULL,
			last_days_left INTEGER NOT NULL,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, cert_id)
		);`,
		`CREATE TABLE cert_renewal_intelligence (
			tenant_id TEXT NOT NULL,
			cert_id TEXT NOT NULL,
			ari_id TEXT NOT NULL,
			ca_id TEXT NOT NULL DEFAULT '',
			ca_name TEXT NOT NULL DEFAULT '',
			subject_cn TEXT NOT NULL DEFAULT '',
			protocol TEXT NOT NULL DEFAULT 'rest',
			not_after TIMESTAMP NOT NULL,
			window_start TIMESTAMP,
			window_end TIMESTAMP,
			scheduled_renewal_at TIMESTAMP,
			explanation_url TEXT NOT NULL DEFAULT '',
			retry_after_seconds INTEGER NOT NULL DEFAULT 86400,
			next_poll_at TIMESTAMP,
			renewal_state TEXT NOT NULL DEFAULT 'scheduled',
			risk_level TEXT NOT NULL DEFAULT 'low',
			missed_window_at TIMESTAMP,
			emergency_rotation_at TIMESTAMP,
			mass_renewal_bucket TEXT NOT NULL DEFAULT '',
			window_source TEXT NOT NULL DEFAULT 'rfc9773_ari',
			metadata_json TEXT NOT NULL DEFAULT '{}',
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, cert_id),
			UNIQUE (tenant_id, ari_id)
		);`,
		`CREATE TABLE cert_acme_star_subscriptions (
			id TEXT NOT NULL,
			tenant_id TEXT NOT NULL,
			name TEXT NOT NULL,
			account_id TEXT NOT NULL DEFAULT '',
			ca_id TEXT NOT NULL,
			profile_id TEXT,
			subject_cn TEXT NOT NULL,
			sans_json TEXT NOT NULL DEFAULT '[]',
			cert_type TEXT NOT NULL DEFAULT 'tls-server',
			cert_class TEXT NOT NULL DEFAULT 'star',
			algorithm TEXT NOT NULL DEFAULT 'ECDSA-P256',
			validity_hours INTEGER NOT NULL DEFAULT 24,
			renew_before_minutes INTEGER NOT NULL DEFAULT 240,
			auto_renew INTEGER NOT NULL DEFAULT 1,
			allow_delegation INTEGER NOT NULL DEFAULT 1,
			delegated_subscriber TEXT,
			latest_cert_id TEXT,
			issuance_count INTEGER NOT NULL DEFAULT 0,
			status TEXT NOT NULL DEFAULT 'active',
			rollout_group TEXT,
			last_issued_at TIMESTAMP,
			next_renewal_at TIMESTAMP,
			last_error TEXT,
			created_by TEXT NOT NULL DEFAULT '',
			metadata_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (tenant_id, id),
			UNIQUE (tenant_id, name)
		);`,
	}
	for _, stmt := range stmts {
		if _, err := conn.SQL().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}
