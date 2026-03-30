package sprawlscanner

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// FindingsStore persists and queries sprawl scanner findings.
type FindingsStore interface {
	StoreFindings(ctx context.Context, findings []Finding) error
	GetFinding(ctx context.Context, findingID string) (*Finding, error)
	ListFindings(ctx context.Context, tenantID string, limit, offset int) ([]Finding, error)
	ListFindingsBySeverity(ctx context.Context, tenantID string, severity Severity) ([]Finding, error)
	CountByTenant(ctx context.Context, tenantID string) (int, error)
	DeleteOlderThan(ctx context.Context, tenantID string, before time.Time) (int64, error)
}

// SQLFindingsStore implements FindingsStore using a SQL database.
type SQLFindingsStore struct {
	db *sql.DB
}

// NewSQLFindingsStore creates a new SQL-backed findings store.
func NewSQLFindingsStore(db *sql.DB) *SQLFindingsStore {
	return &SQLFindingsStore{db: db}
}

// Migrate creates the sprawl_scanner_findings table if it does not exist.
func (s *SQLFindingsStore) Migrate(ctx context.Context) error {
	query := `
		CREATE TABLE IF NOT EXISTS sprawl_scanner_findings (
			id              TEXT PRIMARY KEY,
			tenant_id       TEXT NOT NULL,
			source_type     TEXT NOT NULL,
			location        TEXT NOT NULL,
			line_number     INTEGER NOT NULL DEFAULT 0,
			matched_pattern TEXT NOT NULL,
			snippet         TEXT NOT NULL DEFAULT '',
			severity        TEXT NOT NULL DEFAULT 'medium',
			secret_type     TEXT NOT NULL DEFAULT 'generic',
			detected_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`
	_, err := s.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create sprawl_scanner_findings table: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_sprawl_findings_tenant
		ON sprawl_scanner_findings (tenant_id, severity, detected_at)`)
	if err != nil {
		return fmt.Errorf("failed to create findings index: %w", err)
	}

	return nil
}

// StoreFindings inserts multiple findings in a single transaction.
func (s *SQLFindingsStore) StoreFindings(ctx context.Context, findings []Finding) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO sprawl_scanner_findings
			(id, tenant_id, source_type, location, line_number, matched_pattern, snippet, severity, secret_type, detected_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, f := range findings {
		_, err := stmt.ExecContext(ctx,
			f.ID, f.TenantID, f.SourceType, f.Location,
			f.LineNumber, f.MatchedPattern, f.Snippet,
			string(f.Severity), string(f.SecretType), f.DetectedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert finding %s: %w", f.ID, err)
		}
	}

	return tx.Commit()
}

// GetFinding retrieves a single finding by ID.
func (s *SQLFindingsStore) GetFinding(ctx context.Context, findingID string) (*Finding, error) {
	query := `
		SELECT id, tenant_id, source_type, location, line_number,
		       matched_pattern, snippet, severity, secret_type, detected_at
		FROM sprawl_scanner_findings
		WHERE id = $1`

	f := &Finding{}
	var sev, st string
	err := s.db.QueryRowContext(ctx, query, findingID).Scan(
		&f.ID, &f.TenantID, &f.SourceType, &f.Location, &f.LineNumber,
		&f.MatchedPattern, &f.Snippet, &sev, &st, &f.DetectedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("finding %q not found", findingID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query finding: %w", err)
	}
	f.Severity = Severity(sev)
	f.SecretType = SecretType(st)
	return f, nil
}

// ListFindings returns findings for a tenant with pagination.
func (s *SQLFindingsStore) ListFindings(ctx context.Context, tenantID string, limit, offset int) ([]Finding, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `
		SELECT id, tenant_id, source_type, location, line_number,
		       matched_pattern, snippet, severity, secret_type, detected_at
		FROM sprawl_scanner_findings
		WHERE tenant_id = $1
		ORDER BY detected_at DESC
		LIMIT $2 OFFSET $3`

	return s.queryFindings(ctx, query, tenantID, limit, offset)
}

// ListFindingsBySeverity returns findings filtered by severity.
func (s *SQLFindingsStore) ListFindingsBySeverity(ctx context.Context, tenantID string, severity Severity) ([]Finding, error) {
	query := `
		SELECT id, tenant_id, source_type, location, line_number,
		       matched_pattern, snippet, severity, secret_type, detected_at
		FROM sprawl_scanner_findings
		WHERE tenant_id = $1 AND severity = $2
		ORDER BY detected_at DESC`

	return s.queryFindings(ctx, query, tenantID, string(severity))
}

// CountByTenant returns the total number of findings for a tenant.
func (s *SQLFindingsStore) CountByTenant(ctx context.Context, tenantID string) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sprawl_scanner_findings WHERE tenant_id = $1`, tenantID).Scan(&count)
	return count, err
}

// DeleteOlderThan removes findings detected before the given time.
func (s *SQLFindingsStore) DeleteOlderThan(ctx context.Context, tenantID string, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM sprawl_scanner_findings WHERE tenant_id = $1 AND detected_at < $2`,
		tenantID, before)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// queryFindings is a helper that scans rows from a findings query.
func (s *SQLFindingsStore) queryFindings(ctx context.Context, query string, args ...interface{}) ([]Finding, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	var findings []Finding
	for rows.Next() {
		var f Finding
		var sev, st string
		if err := rows.Scan(
			&f.ID, &f.TenantID, &f.SourceType, &f.Location, &f.LineNumber,
			&f.MatchedPattern, &f.Snippet, &sev, &st, &f.DetectedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan finding row: %w", err)
		}
		f.Severity = Severity(sev)
		f.SecretType = SecretType(st)
		findings = append(findings, f)
	}
	return findings, rows.Err()
}
