package cicd

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Lease tracks a single secrets injection event for audit purposes.
type Lease struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Platform       string    `json:"platform"`
	PipelineID     string    `json:"pipeline_id"`
	RunnerIdentity string    `json:"runner_identity"`
	SecretsCount   int       `json:"secrets_count"`
	ExpiresAt      time.Time `json:"expires_at"`
	Revoked        bool      `json:"revoked"`
	CreatedAt      time.Time `json:"created_at"`
}

// LeaseStore manages CI/CD injection lease persistence.
type LeaseStore interface {
	CreateLease(ctx context.Context, lease Lease) error
	GetLease(ctx context.Context, leaseID string) (*Lease, error)
	RevokeLease(ctx context.Context, leaseID string) error
	ListActiveLeases(ctx context.Context, tenantID string) ([]Lease, error)
	ExpireLeases(ctx context.Context) (int64, error)
}

// SQLLeaseStore implements LeaseStore using a SQL database.
type SQLLeaseStore struct {
	db *sql.DB
}

// NewSQLLeaseStore creates a new SQL-backed lease store.
func NewSQLLeaseStore(db *sql.DB) *SQLLeaseStore {
	return &SQLLeaseStore{db: db}
}

// Migrate creates the cicd_injection_leases table if it does not exist.
func (s *SQLLeaseStore) Migrate(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS cicd_injection_leases (
			id              TEXT PRIMARY KEY,
			tenant_id       TEXT NOT NULL,
			platform        TEXT NOT NULL,
			pipeline_id     TEXT NOT NULL,
			runner_identity TEXT NOT NULL,
			secrets_count   INTEGER NOT NULL DEFAULT 0,
			expires_at      TIMESTAMP NOT NULL,
			revoked         BOOLEAN NOT NULL DEFAULT FALSE,
			created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`
	_, err := s.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create cicd_injection_leases table: %w", err)
	}

	// Index for active lease lookups by tenant
	_, err = s.db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_cicd_leases_tenant_active
		ON cicd_injection_leases (tenant_id, revoked, expires_at)`)
	if err != nil {
		return fmt.Errorf("failed to create lease index: %w", err)
	}

	return nil
}

// CreateLease inserts a new injection lease record.
func (s *SQLLeaseStore) CreateLease(ctx context.Context, lease Lease) error {
	query := `
		INSERT INTO cicd_injection_leases
			(id, tenant_id, platform, pipeline_id, runner_identity, secrets_count, expires_at, revoked, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := s.db.ExecContext(ctx, query,
		lease.ID, lease.TenantID, lease.Platform, lease.PipelineID,
		lease.RunnerIdentity, lease.SecretsCount, lease.ExpiresAt,
		lease.Revoked, lease.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert lease: %w", err)
	}
	return nil
}

// GetLease retrieves a lease by ID.
func (s *SQLLeaseStore) GetLease(ctx context.Context, leaseID string) (*Lease, error) {
	query := `
		SELECT id, tenant_id, platform, pipeline_id, runner_identity,
		       secrets_count, expires_at, revoked, created_at
		FROM cicd_injection_leases
		WHERE id = $1`

	lease := &Lease{}
	err := s.db.QueryRowContext(ctx, query, leaseID).Scan(
		&lease.ID, &lease.TenantID, &lease.Platform, &lease.PipelineID,
		&lease.RunnerIdentity, &lease.SecretsCount, &lease.ExpiresAt,
		&lease.Revoked, &lease.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("lease %q not found", leaseID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query lease: %w", err)
	}
	return lease, nil
}

// RevokeLease marks a lease as revoked.
func (s *SQLLeaseStore) RevokeLease(ctx context.Context, leaseID string) error {
	query := `UPDATE cicd_injection_leases SET revoked = TRUE WHERE id = $1`
	result, err := s.db.ExecContext(ctx, query, leaseID)
	if err != nil {
		return fmt.Errorf("failed to revoke lease: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("lease %q not found", leaseID)
	}
	return nil
}

// ListActiveLeases returns all non-revoked, non-expired leases for a tenant.
func (s *SQLLeaseStore) ListActiveLeases(ctx context.Context, tenantID string) ([]Lease, error) {
	query := `
		SELECT id, tenant_id, platform, pipeline_id, runner_identity,
		       secrets_count, expires_at, revoked, created_at
		FROM cicd_injection_leases
		WHERE tenant_id = $1 AND revoked = FALSE AND expires_at > $2
		ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, tenantID, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("failed to list active leases: %w", err)
	}
	defer rows.Close()

	var leases []Lease
	for rows.Next() {
		var l Lease
		if err := rows.Scan(
			&l.ID, &l.TenantID, &l.Platform, &l.PipelineID,
			&l.RunnerIdentity, &l.SecretsCount, &l.ExpiresAt,
			&l.Revoked, &l.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan lease row: %w", err)
		}
		leases = append(leases, l)
	}
	return leases, rows.Err()
}

// ExpireLeases marks all expired leases as revoked and returns the count affected.
func (s *SQLLeaseStore) ExpireLeases(ctx context.Context) (int64, error) {
	query := `
		UPDATE cicd_injection_leases
		SET revoked = TRUE
		WHERE revoked = FALSE AND expires_at <= $1`

	result, err := s.db.ExecContext(ctx, query, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("failed to expire leases: %w", err)
	}
	return result.RowsAffected()
}
