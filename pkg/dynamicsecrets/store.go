package dynamicsecrets

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// StoredLease is the persisted lease record including provider metadata.
type StoredLease struct {
	ID           string
	CredentialID string
	TenantID     string
	Provider     string
	Username     string
	Endpoint     string
	ExpiresAt    time.Time
	Revoked      bool
	RevokedAt    *time.Time
	CreatedAt    time.Time
}

// Store defines the persistence interface for dynamic secret leases.
type Store interface {
	CreateLease(ctx context.Context, lease *Lease, cred *Credential) error
	GetLease(ctx context.Context, leaseID string) (*StoredLease, error)
	ListLeases(ctx context.Context, tenantID string) ([]*StoredLease, error)
	ListExpiredLeases(ctx context.Context) ([]*StoredLease, error)
	RevokeLease(ctx context.Context, leaseID string) error
	RenewLease(ctx context.Context, leaseID string, newExpiry time.Time) error
}

// SQLStore implements Store using a SQL database (Postgres or SQLite).
type SQLStore struct {
	db *sql.DB
}

// NewSQLStore creates a SQL-backed store and ensures the schema exists.
func NewSQLStore(db *sql.DB) (*SQLStore, error) {
	s := &SQLStore{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("dynamicsecrets/store: migration failed: %w", err)
	}
	return s, nil
}

func (s *SQLStore) migrate() error {
	ddl := `
CREATE TABLE IF NOT EXISTS dynamic_secret_leases (
	id            TEXT PRIMARY KEY,
	credential_id TEXT NOT NULL,
	tenant_id     TEXT NOT NULL,
	provider      TEXT NOT NULL,
	username      TEXT NOT NULL,
	endpoint      TEXT NOT NULL DEFAULT '',
	expires_at    TIMESTAMP NOT NULL,
	revoked       BOOLEAN NOT NULL DEFAULT FALSE,
	revoked_at    TIMESTAMP,
	created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_dsl_tenant ON dynamic_secret_leases(tenant_id);
CREATE INDEX IF NOT EXISTS idx_dsl_expires ON dynamic_secret_leases(expires_at) WHERE revoked = FALSE;
`
	_, err := s.db.Exec(ddl)
	return err
}

func (s *SQLStore) CreateLease(ctx context.Context, lease *Lease, cred *Credential) error {
	query := `
INSERT INTO dynamic_secret_leases (id, credential_id, tenant_id, provider, username, endpoint, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := s.db.ExecContext(ctx, query,
		lease.ID,
		cred.ID,
		lease.TenantID,
		cred.Provider,
		cred.Username,
		cred.Endpoint,
		lease.ExpiresAt,
		time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert lease: %w", err)
	}
	return nil
}

func (s *SQLStore) GetLease(ctx context.Context, leaseID string) (*StoredLease, error) {
	query := `
SELECT id, credential_id, tenant_id, provider, username, endpoint, expires_at, revoked, revoked_at, created_at
FROM dynamic_secret_leases WHERE id = $1`
	row := s.db.QueryRowContext(ctx, query, leaseID)
	return scanLease(row)
}

func (s *SQLStore) ListLeases(ctx context.Context, tenantID string) ([]*StoredLease, error) {
	query := `
SELECT id, credential_id, tenant_id, provider, username, endpoint, expires_at, revoked, revoked_at, created_at
FROM dynamic_secret_leases WHERE tenant_id = $1 ORDER BY created_at DESC`
	rows, err := s.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list leases: %w", err)
	}
	defer rows.Close()
	return scanLeases(rows)
}

func (s *SQLStore) ListExpiredLeases(ctx context.Context) ([]*StoredLease, error) {
	query := `
SELECT id, credential_id, tenant_id, provider, username, endpoint, expires_at, revoked, revoked_at, created_at
FROM dynamic_secret_leases WHERE revoked = FALSE AND expires_at <= $1`
	rows, err := s.db.QueryContext(ctx, query, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("list expired leases: %w", err)
	}
	defer rows.Close()
	return scanLeases(rows)
}

func (s *SQLStore) RevokeLease(ctx context.Context, leaseID string) error {
	query := `UPDATE dynamic_secret_leases SET revoked = TRUE, revoked_at = $1 WHERE id = $2`
	res, err := s.db.ExecContext(ctx, query, time.Now().UTC(), leaseID)
	if err != nil {
		return fmt.Errorf("revoke lease: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("lease %q not found", leaseID)
	}
	return nil
}

func (s *SQLStore) RenewLease(ctx context.Context, leaseID string, newExpiry time.Time) error {
	query := `UPDATE dynamic_secret_leases SET expires_at = $1 WHERE id = $2 AND revoked = FALSE`
	res, err := s.db.ExecContext(ctx, query, newExpiry, leaseID)
	if err != nil {
		return fmt.Errorf("renew lease: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("lease %q not found or already revoked", leaseID)
	}
	return nil
}

func scanLease(row *sql.Row) (*StoredLease, error) {
	l := &StoredLease{}
	err := row.Scan(&l.ID, &l.CredentialID, &l.TenantID, &l.Provider, &l.Username,
		&l.Endpoint, &l.ExpiresAt, &l.Revoked, &l.RevokedAt, &l.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("scan lease: %w", err)
	}
	return l, nil
}

func scanLeases(rows *sql.Rows) ([]*StoredLease, error) {
	var leases []*StoredLease
	for rows.Next() {
		l := &StoredLease{}
		if err := rows.Scan(&l.ID, &l.CredentialID, &l.TenantID, &l.Provider, &l.Username,
			&l.Endpoint, &l.ExpiresAt, &l.Revoked, &l.RevokedAt, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan leases: %w", err)
		}
		leases = append(leases, l)
	}
	return leases, rows.Err()
}
