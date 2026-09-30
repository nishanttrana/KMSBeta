package main

import (
	"context"
	"database/sql"
)

// GetAlgorithmDistribution counts the tenant's live keys per algorithm.
// Deleted and destroyed keys hold no usable material, so they are excluded.
func (s *SQLStore) GetAlgorithmDistribution(ctx context.Context, tenantID string) ([]AlgorithmUsage, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT algorithm, COUNT(*) AS key_count
FROM keys
WHERE tenant_id = $1 AND status NOT IN ('deleted', 'destroyed')
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

// ---- Customer migration policy ----

const agilityRuleColumns = `id, tenant_id, name, match_kind, match_value, action, effective_date,
       target_algorithm, note, created_by, created_at, updated_at`

func (s *SQLStore) ListAgilityRules(ctx context.Context, tenantID string) ([]AgilityRule, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+agilityRuleColumns+`
FROM agility_policy_rules WHERE tenant_id = $1 ORDER BY effective_date, name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []AgilityRule{}
	for rows.Next() {
		r, err := scanAgilityRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateAgilityRule(ctx context.Context, r AgilityRule) (AgilityRule, error) {
	return scanAgilityRule(s.db.SQL().QueryRowContext(ctx, `
INSERT INTO agility_policy_rules
  (id, tenant_id, name, match_kind, match_value, action, effective_date, target_algorithm, note, created_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
RETURNING `+agilityRuleColumns,
		r.ID, r.TenantID, r.Name, r.MatchKind, r.MatchValue, r.Action, r.EffectiveDate.UTC(), r.TargetAlgorithm, r.Note, r.CreatedBy))
}

func (s *SQLStore) UpdateAgilityRule(ctx context.Context, r AgilityRule) (AgilityRule, error) {
	out, err := scanAgilityRule(s.db.SQL().QueryRowContext(ctx, `
UPDATE agility_policy_rules
SET name=$3, match_kind=$4, match_value=$5, action=$6, effective_date=$7, target_algorithm=$8, note=$9, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$1 AND id=$2
RETURNING `+agilityRuleColumns,
		r.TenantID, r.ID, r.Name, r.MatchKind, r.MatchValue, r.Action, r.EffectiveDate.UTC(), r.TargetAlgorithm, r.Note))
	if err == sql.ErrNoRows {
		return AgilityRule{}, errStoreNotFound
	}
	return out, err
}

func (s *SQLStore) DeleteAgilityRule(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM agility_policy_rules WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func scanAgilityRule(row interface{ Scan(dest ...any) error }) (AgilityRule, error) {
	var r AgilityRule
	err := row.Scan(&r.ID, &r.TenantID, &r.Name, &r.MatchKind, &r.MatchValue, &r.Action, &r.EffectiveDate,
		&r.TargetAlgorithm, &r.Note, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	r.EffectiveDate = r.EffectiveDate.UTC()
	return r, err
}
