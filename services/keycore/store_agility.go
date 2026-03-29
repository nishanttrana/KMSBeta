package main

import (
	"context"
	"database/sql"
)

// GetAlgorithmDistribution queries the keys table to count keys per algorithm
// for the given tenant.
func (s *SQLStore) GetAlgorithmDistribution(ctx context.Context, tenantID string) ([]AlgorithmUsage, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT algorithm, COUNT(*) AS key_count
FROM keys
WHERE tenant_id = $1
GROUP BY algorithm
ORDER BY key_count DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []AlgorithmUsage
	for rows.Next() {
		var a AlgorithmUsage
		if err := rows.Scan(&a.Algorithm, &a.KeyCount); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if out == nil {
		out = []AlgorithmUsage{}
	}
	return out, rows.Err()
}

// ListKeysByAlgorithm returns all keys for a tenant that use the specified algorithm.
func (s *SQLStore) ListKeysByAlgorithm(ctx context.Context, tenantID, algorithm string) ([]Key, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, algorithm, key_type, purpose, status, destroy_date, current_version,
       kcv, kcv_algorithm, iv_mode, owner, cloud, region, compliance, labels, tags,
       export_allowed, activation_date, expiry_date, ops_total, ops_encrypt, ops_decrypt, ops_sign,
       ops_limit, COALESCE(ops_limit_window,''), ops_last_reset, approval_required,
       COALESCE(approval_policy_id,''), created_by, created_at, updated_at
FROM keys
WHERE tenant_id = $1 AND algorithm = $2
ORDER BY created_at DESC
`, tenantID, algorithm)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	if out == nil {
		out = []Key{}
	}
	return out, rows.Err()
}

// ---- Migration Plans ----

func (s *SQLStore) ListMigrationPlans(ctx context.Context, tenantID string) ([]MigrationPlan, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, from_algorithm, to_algorithm, affected_keys,
       completed_keys, status, created_at, target_date
FROM agility_migration_plans
WHERE tenant_id = $1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []MigrationPlan
	for rows.Next() {
		mp, err := scanMigrationPlanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, mp)
	}
	if out == nil {
		out = []MigrationPlan{}
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateMigrationPlan(ctx context.Context, mp MigrationPlan) (MigrationPlan, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO agility_migration_plans
  (id, tenant_id, name, from_algorithm, to_algorithm, affected_keys, completed_keys, status, created_at, target_date)
VALUES ($1,$2,$3,$4,$5,$6,0,$7,CURRENT_TIMESTAMP,$8)
RETURNING id, tenant_id, name, from_algorithm, to_algorithm, affected_keys,
          completed_keys, status, created_at, target_date
`, mp.ID, mp.TenantID, mp.Name, mp.FromAlgorithm, mp.ToAlgorithm, mp.AffectedKeys,
		mp.Status, nullableTime(mp.TargetDate))

	return scanMigrationPlanSingleRow(row)
}

func (s *SQLStore) UpdateMigrationPlan(ctx context.Context, tenantID, id, status string, completedKeys int) (MigrationPlan, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
UPDATE agility_migration_plans
SET status=$3, completed_keys=$4
WHERE tenant_id=$1 AND id=$2
RETURNING id, tenant_id, name, from_algorithm, to_algorithm, affected_keys,
          completed_keys, status, created_at, target_date
`, tenantID, id, status, completedKeys)

	mp, err := scanMigrationPlanSingleRow(row)
	if err == sql.ErrNoRows {
		return MigrationPlan{}, errStoreNotFound
	}
	return mp, err
}

func scanMigrationPlanRow(rows interface {
	Scan(dest ...any) error
}) (MigrationPlan, error) {
	var mp MigrationPlan
	var targetDate sql.NullTime
	if err := rows.Scan(
		&mp.ID, &mp.TenantID, &mp.Name, &mp.FromAlgorithm, &mp.ToAlgorithm,
		&mp.AffectedKeys, &mp.CompletedKeys, &mp.Status, &mp.CreatedAt, &targetDate,
	); err != nil {
		return MigrationPlan{}, err
	}
	if targetDate.Valid {
		t := targetDate.Time.UTC()
		mp.TargetDate = &t
	}
	return mp, nil
}

func scanMigrationPlanSingleRow(row *sql.Row) (MigrationPlan, error) {
	var mp MigrationPlan
	var targetDate sql.NullTime
	if err := row.Scan(
		&mp.ID, &mp.TenantID, &mp.Name, &mp.FromAlgorithm, &mp.ToAlgorithm,
		&mp.AffectedKeys, &mp.CompletedKeys, &mp.Status, &mp.CreatedAt, &targetDate,
	); err != nil {
		return MigrationPlan{}, err
	}
	if targetDate.Valid {
		t := targetDate.Time.UTC()
		mp.TargetDate = &t
	}
	return mp, nil
}
