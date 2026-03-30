package evidence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"vecta-kms/pkg/db"
)

const evidenceMigration = `
CREATE TABLE IF NOT EXISTS evidence_packages (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	framework TEXT NOT NULL,
	generated_at TIMESTAMPTZ NOT NULL,
	period TEXT NOT NULL,
	format TEXT NOT NULL DEFAULT 'json',
	controls_json TEXT NOT NULL DEFAULT '[]',
	summary_json TEXT NOT NULL DEFAULT '{}',
	attestation_json TEXT,
	hash TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_evidence_tenant ON evidence_packages(tenant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_framework ON evidence_packages(tenant_id, framework);
CREATE INDEX IF NOT EXISTS idx_evidence_generated ON evidence_packages(generated_at DESC);
`

// Store persists evidence packages in SQL.
type Store struct {
	database *db.DB
}

// NewStore creates a new evidence Store.
func NewStore(database *db.DB) *Store {
	return &Store{database: database}
}

// Migrate creates the required tables and indexes.
func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.database.SQL().ExecContext(ctx, evidenceMigration)
	if err != nil {
		return fmt.Errorf("evidence: migrate: %w", err)
	}
	return nil
}

// SavePackage inserts or updates an evidence package.
func (s *Store) SavePackage(ctx context.Context, pkg *EvidencePackage) error {
	controlsJSON, err := json.Marshal(pkg.Controls)
	if err != nil {
		return fmt.Errorf("evidence: marshal controls: %w", err)
	}

	summaryJSON, err := json.Marshal(pkg.Summary)
	if err != nil {
		return fmt.Errorf("evidence: marshal summary: %w", err)
	}

	var attestationJSON *string
	if pkg.Attestation != nil {
		b, err := json.Marshal(pkg.Attestation)
		if err != nil {
			return fmt.Errorf("evidence: marshal attestation: %w", err)
		}
		s := string(b)
		attestationJSON = &s
	}

	const query = `
		INSERT INTO evidence_packages
			(id, tenant_id, framework, generated_at, period, format, controls_json, summary_json, attestation_json, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET
			controls_json = EXCLUDED.controls_json,
			summary_json = EXCLUDED.summary_json,
			attestation_json = EXCLUDED.attestation_json,
			hash = EXCLUDED.hash
	`
	_, err = s.database.SQL().ExecContext(ctx, query,
		pkg.ID, pkg.TenantID, pkg.Framework, pkg.GeneratedAt,
		pkg.Period, pkg.Format, string(controlsJSON), string(summaryJSON),
		attestationJSON, pkg.Hash,
	)
	if err != nil {
		return fmt.Errorf("evidence: save package: %w", err)
	}
	return nil
}

// GetPackage retrieves an evidence package by ID.
func (s *Store) GetPackage(ctx context.Context, id string) (*EvidencePackage, error) {
	const query = `
		SELECT id, tenant_id, framework, generated_at, period, format,
			   controls_json, summary_json, attestation_json, hash
		FROM evidence_packages WHERE id = $1
	`
	return s.scanPackage(s.database.SQL().QueryRowContext(ctx, query, id))
}

// ListPackages returns evidence packages for a tenant, optionally filtered by framework.
func (s *Store) ListPackages(ctx context.Context, tenantID string, framework string, limit int) ([]*EvidencePackage, error) {
	if limit <= 0 {
		limit = 50
	}

	var rows *sql.Rows
	var err error

	if framework != "" {
		const query = `
			SELECT id, tenant_id, framework, generated_at, period, format,
				   controls_json, summary_json, attestation_json, hash
			FROM evidence_packages
			WHERE tenant_id = $1 AND framework = $2
			ORDER BY generated_at DESC LIMIT $3
		`
		rows, err = s.database.SQL().QueryContext(ctx, query, tenantID, framework, limit)
	} else {
		const query = `
			SELECT id, tenant_id, framework, generated_at, period, format,
				   controls_json, summary_json, attestation_json, hash
			FROM evidence_packages
			WHERE tenant_id = $1
			ORDER BY generated_at DESC LIMIT $2
		`
		rows, err = s.database.SQL().QueryContext(ctx, query, tenantID, limit)
	}

	if err != nil {
		return nil, fmt.Errorf("evidence: list packages: %w", err)
	}
	defer rows.Close()

	var packages []*EvidencePackage
	for rows.Next() {
		pkg, err := s.scanPackageFromRow(rows)
		if err != nil {
			return nil, err
		}
		packages = append(packages, pkg)
	}
	return packages, rows.Err()
}

// DeletePackage removes an evidence package.
func (s *Store) DeletePackage(ctx context.Context, id string) error {
	const query = `DELETE FROM evidence_packages WHERE id = $1`
	result, err := s.database.SQL().ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("evidence: delete package: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("evidence: package %q not found", id)
	}
	return nil
}

// ListPackagesByPeriod returns packages for a tenant within a specific period.
func (s *Store) ListPackagesByPeriod(ctx context.Context, tenantID, period string) ([]*EvidencePackage, error) {
	const query = `
		SELECT id, tenant_id, framework, generated_at, period, format,
			   controls_json, summary_json, attestation_json, hash
		FROM evidence_packages
		WHERE tenant_id = $1 AND period = $2
		ORDER BY generated_at DESC
	`
	rows, err := s.database.SQL().QueryContext(ctx, query, tenantID, period)
	if err != nil {
		return nil, fmt.Errorf("evidence: list by period: %w", err)
	}
	defer rows.Close()

	var packages []*EvidencePackage
	for rows.Next() {
		pkg, err := s.scanPackageFromRow(rows)
		if err != nil {
			return nil, err
		}
		packages = append(packages, pkg)
	}
	return packages, rows.Err()
}

func (s *Store) scanPackage(row *sql.Row) (*EvidencePackage, error) {
	pkg := &EvidencePackage{}
	var controlsJSON, summaryJSON string
	var attestationJSON sql.NullString

	if err := row.Scan(
		&pkg.ID, &pkg.TenantID, &pkg.Framework, &pkg.GeneratedAt,
		&pkg.Period, &pkg.Format, &controlsJSON, &summaryJSON,
		&attestationJSON, &pkg.Hash,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("evidence: package not found")
		}
		return nil, fmt.Errorf("evidence: scan package: %w", err)
	}

	if err := json.Unmarshal([]byte(controlsJSON), &pkg.Controls); err != nil {
		return nil, fmt.Errorf("evidence: unmarshal controls: %w", err)
	}
	if err := json.Unmarshal([]byte(summaryJSON), &pkg.Summary); err != nil {
		return nil, fmt.Errorf("evidence: unmarshal summary: %w", err)
	}
	if attestationJSON.Valid {
		pkg.Attestation = &Attestation{}
		if err := json.Unmarshal([]byte(attestationJSON.String), pkg.Attestation); err != nil {
			return nil, fmt.Errorf("evidence: unmarshal attestation: %w", err)
		}
	}

	return pkg, nil
}

// scanPackageFromRow scans a package from sql.Rows (used in list queries).
func (s *Store) scanPackageFromRow(rows *sql.Rows) (*EvidencePackage, error) {
	pkg := &EvidencePackage{}
	var controlsJSON, summaryJSON string
	var attestationJSON sql.NullString

	if err := rows.Scan(
		&pkg.ID, &pkg.TenantID, &pkg.Framework, &pkg.GeneratedAt,
		&pkg.Period, &pkg.Format, &controlsJSON, &summaryJSON,
		&attestationJSON, &pkg.Hash,
	); err != nil {
		return nil, fmt.Errorf("evidence: scan package row: %w", err)
	}

	if err := json.Unmarshal([]byte(controlsJSON), &pkg.Controls); err != nil {
		return nil, fmt.Errorf("evidence: unmarshal controls: %w", err)
	}
	if err := json.Unmarshal([]byte(summaryJSON), &pkg.Summary); err != nil {
		return nil, fmt.Errorf("evidence: unmarshal summary: %w", err)
	}
	if attestationJSON.Valid {
		pkg.Attestation = &Attestation{}
		if err := json.Unmarshal([]byte(attestationJSON.String), pkg.Attestation); err != nil {
			return nil, fmt.Errorf("evidence: unmarshal attestation: %w", err)
		}
	}

	return pkg, nil
}

// CountByFramework returns the count of evidence packages per framework for a tenant.
func (s *Store) CountByFramework(ctx context.Context, tenantID string) (map[string]int, error) {
	const query = `
		SELECT framework, COUNT(*) as cnt
		FROM evidence_packages
		WHERE tenant_id = $1
		GROUP BY framework
	`
	rows, err := s.database.SQL().QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("evidence: count by framework: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var framework string
		var count int
		if err := rows.Scan(&framework, &count); err != nil {
			return nil, fmt.Errorf("evidence: scan count: %w", err)
		}
		counts[framework] = count
	}
	return counts, rows.Err()
}

// LatestPackage returns the most recently generated package for a tenant and framework.
func (s *Store) LatestPackage(ctx context.Context, tenantID, framework string) (*EvidencePackage, error) {
	const query = `
		SELECT id, tenant_id, framework, generated_at, period, format,
			   controls_json, summary_json, attestation_json, hash
		FROM evidence_packages
		WHERE tenant_id = $1 AND framework = $2
		ORDER BY generated_at DESC LIMIT 1
	`
	return s.scanPackage(s.database.SQL().QueryRowContext(ctx, query, tenantID, framework))
}

// PackageExists checks whether a package with the given ID exists.
func (s *Store) PackageExists(ctx context.Context, id string) (bool, error) {
	const query = `SELECT COUNT(*) FROM evidence_packages WHERE id = $1`
	var count int
	err := s.database.SQL().QueryRowContext(ctx, query, id).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("evidence: check exists: %w", err)
	}
	return count > 0, nil
}

// PurgeOlderThan deletes packages generated before the given time.
func (s *Store) PurgeOlderThan(ctx context.Context, tenantID string, before time.Time) (int64, error) {
	const query = `DELETE FROM evidence_packages WHERE tenant_id = $1 AND generated_at < $2`
	result, err := s.database.SQL().ExecContext(ctx, query, tenantID, before)
	if err != nil {
		return 0, fmt.Errorf("evidence: purge: %w", err)
	}
	return result.RowsAffected()
}
