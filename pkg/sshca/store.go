package sshca

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Store defines the persistence interface for SSH CA operations.
type Store interface {
	RecordCert(ctx context.Context, cert *IssuedCert) error
	GetCert(ctx context.Context, certID string) (*IssuedCert, error)
	ListCerts(ctx context.Context, tenantID string) ([]*IssuedCert, error)
	RevokeCert(ctx context.Context, certID string) error
	GetPolicy(ctx context.Context, tenantID string) (*CertPolicy, error)
	SetPolicy(ctx context.Context, policy *CertPolicy) error
}

// SQLStore implements Store using a SQL database (Postgres or SQLite).
type SQLStore struct {
	db *sql.DB
}

// NewSQLStore creates a SQL-backed store and runs schema migrations.
func NewSQLStore(db *sql.DB) (*SQLStore, error) {
	s := &SQLStore{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("sshca/store: migration failed: %w", err)
	}
	return s, nil
}

func (s *SQLStore) migrate() error {
	ddl := `
CREATE TABLE IF NOT EXISTS ssh_ca_issued_certs (
	id           TEXT PRIMARY KEY,
	tenant_id    TEXT NOT NULL,
	cert_type    TEXT NOT NULL,
	key_id       TEXT NOT NULL,
	principals   TEXT NOT NULL DEFAULT '',
	serial       BIGINT NOT NULL,
	valid_after  TIMESTAMP NOT NULL,
	valid_before TIMESTAMP NOT NULL,
	fingerprint  TEXT NOT NULL,
	revoked      BOOLEAN NOT NULL DEFAULT FALSE,
	created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sshca_tenant ON ssh_ca_issued_certs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sshca_serial ON ssh_ca_issued_certs(serial);

CREATE TABLE IF NOT EXISTS ssh_ca_policies (
	tenant_id                TEXT PRIMARY KEY,
	max_ttl_seconds          BIGINT NOT NULL DEFAULT 86400,
	allowed_principals       TEXT NOT NULL DEFAULT '',
	allowed_extensions       TEXT NOT NULL DEFAULT '',
	allowed_source_addresses TEXT NOT NULL DEFAULT '',
	require_source_address   BOOLEAN NOT NULL DEFAULT FALSE,
	updated_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`
	_, err := s.db.Exec(ddl)
	return err
}

func (s *SQLStore) RecordCert(ctx context.Context, cert *IssuedCert) error {
	principals := strings.Join(cert.Principals, ",")
	query := `
INSERT INTO ssh_ca_issued_certs (id, tenant_id, cert_type, key_id, principals, serial, valid_after, valid_before, fingerprint, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	_, err := s.db.ExecContext(ctx, query,
		cert.ID, cert.TenantID, cert.CertType, cert.KeyID, principals,
		cert.Serial, cert.ValidAfter, cert.ValidBefore, cert.Fingerprint, cert.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert cert: %w", err)
	}
	return nil
}

func (s *SQLStore) GetCert(ctx context.Context, certID string) (*IssuedCert, error) {
	query := `
SELECT id, tenant_id, cert_type, key_id, principals, serial, valid_after, valid_before, fingerprint, created_at
FROM ssh_ca_issued_certs WHERE id = $1`
	row := s.db.QueryRowContext(ctx, query, certID)
	return scanCert(row)
}

func (s *SQLStore) ListCerts(ctx context.Context, tenantID string) ([]*IssuedCert, error) {
	query := `
SELECT id, tenant_id, cert_type, key_id, principals, serial, valid_after, valid_before, fingerprint, created_at
FROM ssh_ca_issued_certs WHERE tenant_id = $1 ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list certs: %w", err)
	}
	defer rows.Close()

	var certs []*IssuedCert
	for rows.Next() {
		c, err := scanCertRow(rows)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, rows.Err()
}

func (s *SQLStore) RevokeCert(ctx context.Context, certID string) error {
	query := `UPDATE ssh_ca_issued_certs SET revoked = TRUE WHERE id = $1`
	res, err := s.db.ExecContext(ctx, query, certID)
	if err != nil {
		return fmt.Errorf("revoke cert: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("cert %q not found", certID)
	}
	return nil
}

func (s *SQLStore) GetPolicy(ctx context.Context, tenantID string) (*CertPolicy, error) {
	query := `
SELECT tenant_id, max_ttl_seconds, allowed_principals, allowed_extensions, allowed_source_addresses, require_source_address
FROM ssh_ca_policies WHERE tenant_id = $1`
	row := s.db.QueryRowContext(ctx, query, tenantID)

	var p CertPolicy
	var maxTTLSec int64
	var principals, extensions, sourceAddrs string
	err := row.Scan(&p.TenantID, &maxTTLSec, &principals, &extensions, &sourceAddrs, &p.RequireSourceAddress)
	if err != nil {
		return nil, fmt.Errorf("get policy: %w", err)
	}

	p.MaxTTL = time.Duration(maxTTLSec) * time.Second
	p.AllowedPrincipals = splitCSV(principals)
	p.AllowedExtensions = splitCSV(extensions)
	p.AllowedSourceAddresses = splitCSV(sourceAddrs)
	return &p, nil
}

func (s *SQLStore) SetPolicy(ctx context.Context, policy *CertPolicy) error {
	query := `
INSERT INTO ssh_ca_policies (tenant_id, max_ttl_seconds, allowed_principals, allowed_extensions, allowed_source_addresses, require_source_address, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (tenant_id) DO UPDATE SET
	max_ttl_seconds = EXCLUDED.max_ttl_seconds,
	allowed_principals = EXCLUDED.allowed_principals,
	allowed_extensions = EXCLUDED.allowed_extensions,
	allowed_source_addresses = EXCLUDED.allowed_source_addresses,
	require_source_address = EXCLUDED.require_source_address,
	updated_at = EXCLUDED.updated_at`
	_, err := s.db.ExecContext(ctx, query,
		policy.TenantID,
		int64(policy.MaxTTL.Seconds()),
		strings.Join(policy.AllowedPrincipals, ","),
		strings.Join(policy.AllowedExtensions, ","),
		strings.Join(policy.AllowedSourceAddresses, ","),
		policy.RequireSourceAddress,
		time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("set policy: %w", err)
	}
	return nil
}

func scanCert(row *sql.Row) (*IssuedCert, error) {
	c := &IssuedCert{}
	var principals string
	err := row.Scan(&c.ID, &c.TenantID, &c.CertType, &c.KeyID, &principals,
		&c.Serial, &c.ValidAfter, &c.ValidBefore, &c.Fingerprint, &c.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("scan cert: %w", err)
	}
	c.Principals = splitCSV(principals)
	return c, nil
}

func scanCertRow(rows *sql.Rows) (*IssuedCert, error) {
	c := &IssuedCert{}
	var principals string
	err := rows.Scan(&c.ID, &c.TenantID, &c.CertType, &c.KeyID, &principals,
		&c.Serial, &c.ValidAfter, &c.ValidBefore, &c.Fingerprint, &c.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("scan cert row: %w", err)
	}
	c.Principals = splitCSV(principals)
	return c, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
