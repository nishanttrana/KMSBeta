package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	pkgcrypto "vecta-kms/pkg/crypto"

	pkgdb "vecta-kms/pkg/db"
)

type nopCertPublisher struct{}

func (nopCertPublisher) Publish(_ context.Context, _ string, _ []byte) error { return nil }

// subjectRecorder counts published audit subjects.
type subjectRecorder struct {
	mu       sync.Mutex
	subjects map[string]int
}

func (r *subjectRecorder) Publish(_ context.Context, subject string, _ []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.subjects == nil {
		r.subjects = map[string]int{}
	}
	r.subjects[subject]++
	return nil
}

func (r *subjectRecorder) count(subject string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.subjects[subject]
}

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
	// Service mTLS tables straight from the migration, so the tests run the
	// schema production runs.
	raw, err := os.ReadFile("migrations/013_internal_mtls_policy.sql")
	if err != nil {
		return err
	}
	var sqlOnly []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			sqlOnly = append(sqlOnly, line)
		}
	}
	for _, stmt := range strings.Split(strings.Join(sqlOnly, "\n"), ";") {
		if strings.Contains(stmt, "CREATE TABLE") {
			stmts = append(stmts, stmt)
		}
	}
	for _, stmt := range stmts {
		if _, err := conn.SQL().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// postgresTestDB opens VECTA_TEST_POSTGRES_DSN in a schema of its own with
// the certs migrations applied, and drops the schema afterwards. Other
// packages' Postgres tests share the database (governance's backup test
// restores every public table while others run). Skips without a DSN.
func postgresTestDB(t *testing.T) *pkgdb.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	admin, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 1, MaxIdle: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	suffix, err := pkgcrypto.RandomBytes(4)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("certs_test_%x", suffix)
	if _, err := admin.SQL().ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.SQL().ExecContext(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn + sep + "search_path=" + schema, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return conn
}
