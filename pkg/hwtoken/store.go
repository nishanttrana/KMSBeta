package hwtoken

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const hwtokenMigrationSQL = `
CREATE TABLE IF NOT EXISTS hwtoken_provisioned_tokens (
	serial TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	label TEXT NOT NULL DEFAULT '',
	manufacturer TEXT NOT NULL DEFAULT '',
	model TEXT NOT NULL DEFAULT '',
	firmware_version TEXT NOT NULL DEFAULT '',
	slot_id INTEGER NOT NULL DEFAULT 0,
	provisioned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_hwtoken_tokens_tenant ON hwtoken_provisioned_tokens(tenant_id);

CREATE TABLE IF NOT EXISTS hwtoken_certs (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL DEFAULT '',
	token_serial TEXT NOT NULL,
	cert_type TEXT NOT NULL DEFAULT '',
	subject TEXT NOT NULL DEFAULT '',
	issuer TEXT NOT NULL DEFAULT '',
	serial TEXT NOT NULL DEFAULT '',
	not_before TIMESTAMP,
	not_after TIMESTAMP,
	fingerprint TEXT NOT NULL DEFAULT '',
	slot_id INTEGER NOT NULL DEFAULT 0,
	object_label TEXT NOT NULL DEFAULT '',
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_hwtoken_certs_token ON hwtoken_certs(token_serial);
CREATE INDEX IF NOT EXISTS idx_hwtoken_certs_tenant ON hwtoken_certs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_hwtoken_certs_expiry ON hwtoken_certs(not_after);
`

// SQLStore persists hardware token provisioning data.
type SQLStore struct {
	db *sql.DB
}

// NewSQLStore creates a new hardware token SQL store and runs migrations.
func NewSQLStore(db *sql.DB) (*SQLStore, error) {
	s := &SQLStore{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("hwtoken/store: migration failed: %w", err)
	}
	return s, nil
}

func (s *SQLStore) migrate() error {
	_, err := s.db.Exec(hwtokenMigrationSQL)
	return err
}

// RegisterToken records a provisioned token in the database.
func (s *SQLStore) RegisterToken(ctx context.Context, tenantID string, token *TokenInfo) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO hwtoken_provisioned_tokens (serial, tenant_id, label, manufacturer, model, firmware_version, slot_id, provisioned_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (serial) DO UPDATE SET
			label = $3, manufacturer = $4, model = $5, firmware_version = $6, slot_id = $7`,
		token.Serial, tenantID, token.Label, token.Manufacturer, token.Model,
		token.FirmwareVersion, token.SlotID, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("hwtoken/store: register token: %w", err)
	}
	return nil
}

// GetToken retrieves a provisioned token by serial.
func (s *SQLStore) GetToken(ctx context.Context, serial string) (*TokenInfo, string, error) {
	var token TokenInfo
	var tenantID string
	var provisionedAt time.Time

	err := s.db.QueryRowContext(ctx,
		`SELECT serial, tenant_id, label, manufacturer, model, firmware_version, slot_id, provisioned_at
		 FROM hwtoken_provisioned_tokens WHERE serial = $1`, serial).
		Scan(&token.Serial, &tenantID, &token.Label, &token.Manufacturer, &token.Model,
			&token.FirmwareVersion, &token.SlotID, &provisionedAt)
	if err != nil {
		return nil, "", fmt.Errorf("hwtoken/store: get token: %w", err)
	}
	return &token, tenantID, nil
}

// ListTokensByTenant returns all provisioned tokens for a tenant.
func (s *SQLStore) ListTokensByTenant(ctx context.Context, tenantID string) ([]TokenInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT serial, label, manufacturer, model, firmware_version, slot_id
		 FROM hwtoken_provisioned_tokens WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("hwtoken/store: list tokens: %w", err)
	}
	defer rows.Close()

	var tokens []TokenInfo
	for rows.Next() {
		var t TokenInfo
		if err := rows.Scan(&t.Serial, &t.Label, &t.Manufacturer, &t.Model, &t.FirmwareVersion, &t.SlotID); err != nil {
			return nil, fmt.Errorf("hwtoken/store: scan token: %w", err)
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// CreateTokenCert stores a certificate provisioned onto a token.
func (s *SQLStore) CreateTokenCert(ctx context.Context, cert *TokenCert) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO hwtoken_certs (id, tenant_id, token_serial, cert_type, subject, issuer, serial, not_before, not_after, fingerprint, slot_id, object_label, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		cert.ID, cert.TenantID, cert.TokenSerial, cert.CertType,
		cert.Subject, cert.Issuer, cert.Serial,
		cert.NotBefore, cert.NotAfter, cert.Fingerprint,
		cert.SlotID, cert.ObjectLabel, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("hwtoken/store: create cert: %w", err)
	}
	return nil
}

// ListTokenCerts returns all certificates on a specific token.
func (s *SQLStore) ListTokenCerts(ctx context.Context, tokenSerial string) ([]TokenCert, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, token_serial, cert_type, subject, issuer, serial, not_before, not_after, fingerprint, slot_id, object_label
		 FROM hwtoken_certs WHERE token_serial = $1
		 ORDER BY not_after ASC`, tokenSerial)
	if err != nil {
		return nil, fmt.Errorf("hwtoken/store: list certs: %w", err)
	}
	defer rows.Close()

	var certs []TokenCert
	for rows.Next() {
		var c TokenCert
		if err := rows.Scan(&c.ID, &c.TenantID, &c.TokenSerial, &c.CertType,
			&c.Subject, &c.Issuer, &c.Serial, &c.NotBefore, &c.NotAfter,
			&c.Fingerprint, &c.SlotID, &c.ObjectLabel); err != nil {
			return nil, fmt.Errorf("hwtoken/store: scan cert: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, rows.Err()
}

// ListExpiringCerts returns all token certs expiring within the given duration.
func (s *SQLStore) ListExpiringCerts(ctx context.Context, tenantID string, within time.Duration) ([]TokenCert, error) {
	deadline := time.Now().Add(within)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, token_serial, cert_type, subject, issuer, serial, not_before, not_after, fingerprint, slot_id, object_label
		 FROM hwtoken_certs WHERE tenant_id = $1 AND not_after <= $2 AND not_after > $3
		 ORDER BY not_after ASC`, tenantID, deadline, time.Now())
	if err != nil {
		return nil, fmt.Errorf("hwtoken/store: list expiring certs: %w", err)
	}
	defer rows.Close()

	var certs []TokenCert
	for rows.Next() {
		var c TokenCert
		if err := rows.Scan(&c.ID, &c.TenantID, &c.TokenSerial, &c.CertType,
			&c.Subject, &c.Issuer, &c.Serial, &c.NotBefore, &c.NotAfter,
			&c.Fingerprint, &c.SlotID, &c.ObjectLabel); err != nil {
			return nil, fmt.Errorf("hwtoken/store: scan cert: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, rows.Err()
}

// DeleteTokenCert removes a certificate record.
func (s *SQLStore) DeleteTokenCert(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM hwtoken_certs WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("hwtoken/store: delete cert: %w", err)
	}
	return nil
}
