package rotation

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"vecta-kms/pkg/db"
)

const rotationMigration = `
CREATE TABLE IF NOT EXISTS rotation_policies (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	key_pattern TEXT NOT NULL,
	interval_ns BIGINT NOT NULL,
	algorithm TEXT NOT NULL DEFAULT '',
	auto_approve BOOLEAN NOT NULL DEFAULT FALSE,
	notify_emails TEXT NOT NULL DEFAULT '',
	max_versions INT NOT NULL DEFAULT 0,
	enabled BOOLEAN NOT NULL DEFAULT TRUE,
	last_run TIMESTAMPTZ,
	next_run TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rotation_policies_tenant ON rotation_policies(tenant_id);

CREATE TABLE IF NOT EXISTS rotation_history (
	id BIGSERIAL PRIMARY KEY,
	policy_id TEXT NOT NULL,
	key_id TEXT NOT NULL,
	old_version TEXT NOT NULL DEFAULT '',
	new_version TEXT NOT NULL DEFAULT '',
	success BOOLEAN NOT NULL,
	error TEXT NOT NULL DEFAULT '',
	duration_ns BIGINT NOT NULL DEFAULT 0,
	executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_rotation_history_policy ON rotation_history(policy_id, executed_at DESC);
`

// PolicyStore abstracts persistence for rotation policies and history.
type PolicyStore interface {
	SavePolicy(ctx context.Context, policy *RotationPolicy) error
	GetPolicy(ctx context.Context, policyID string) (*RotationPolicy, error)
	DeletePolicy(ctx context.Context, policyID string) error
	ListPolicies(ctx context.Context, tenantID string) ([]RotationPolicy, error)
	ListDuePolicies(ctx context.Context, now time.Time) ([]RotationPolicy, error)
	UpdatePolicyTiming(ctx context.Context, policyID string, lastRun, nextRun time.Time) error
	SaveResult(ctx context.Context, result *RotationResult) error
	GetHistory(ctx context.Context, policyID string, limit int) ([]RotationResult, error)
}

// SQLStore implements PolicyStore backed by PostgreSQL or SQLite.
type SQLStore struct {
	db *db.DB
}

// NewSQLStore creates a new SQL-backed rotation store.
func NewSQLStore(database *db.DB) *SQLStore {
	return &SQLStore{db: database}
}

// Migrate creates the required tables and indexes.
func (s *SQLStore) Migrate(ctx context.Context) error {
	_, err := s.db.SQL().ExecContext(ctx, rotationMigration)
	if err != nil {
		return fmt.Errorf("rotation: migrate: %w", err)
	}
	return nil
}

// SavePolicy inserts or updates a rotation policy (upsert).
func (s *SQLStore) SavePolicy(ctx context.Context, policy *RotationPolicy) error {
	emails := strings.Join(policy.NotifyEmails, ",")

	const query = `
		INSERT INTO rotation_policies
			(id, tenant_id, key_pattern, interval_ns, algorithm, auto_approve,
			 notify_emails, max_versions, enabled, last_run, next_run)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET
			tenant_id = $2, key_pattern = $3, interval_ns = $4, algorithm = $5,
			auto_approve = $6, notify_emails = $7, max_versions = $8, enabled = $9,
			last_run = $10, next_run = $11
	`
	var lastRun *time.Time
	if !policy.LastRun.IsZero() {
		lastRun = &policy.LastRun
	}

	_, err := s.db.SQL().ExecContext(ctx, query,
		policy.ID,
		policy.TenantID,
		policy.KeyPattern,
		int64(policy.Interval),
		policy.Algorithm,
		policy.AutoApprove,
		emails,
		policy.MaxVersions,
		policy.Enabled,
		lastRun,
		policy.NextRun,
	)
	if err != nil {
		return fmt.Errorf("rotation: save policy: %w", err)
	}
	return nil
}

// scanPolicy reads a single RotationPolicy from a row scanner.
func scanPolicy(scanner interface {
	Scan(dest ...interface{}) error
}) (*RotationPolicy, error) {
	var p RotationPolicy
	var intervalNS int64
	var emails string
	var lastRun sql.NullTime

	err := scanner.Scan(
		&p.ID, &p.TenantID, &p.KeyPattern, &intervalNS, &p.Algorithm,
		&p.AutoApprove, &emails, &p.MaxVersions, &p.Enabled, &lastRun, &p.NextRun,
	)
	if err != nil {
		return nil, err
	}

	p.Interval = time.Duration(intervalNS)
	if emails != "" {
		p.NotifyEmails = strings.Split(emails, ",")
	}
	if lastRun.Valid {
		p.LastRun = lastRun.Time
	}
	return &p, nil
}

// GetPolicy retrieves a rotation policy by ID.
func (s *SQLStore) GetPolicy(ctx context.Context, policyID string) (*RotationPolicy, error) {
	const query = `
		SELECT id, tenant_id, key_pattern, interval_ns, algorithm,
		       auto_approve, notify_emails, max_versions, enabled, last_run, next_run
		FROM rotation_policies
		WHERE id = $1
	`
	p, err := scanPolicy(s.db.SQL().QueryRowContext(ctx, query, policyID))
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("rotation: policy %q not found", policyID)
	}
	if err != nil {
		return nil, fmt.Errorf("rotation: get policy: %w", err)
	}
	return p, nil
}

// DeletePolicy removes a rotation policy by ID.
func (s *SQLStore) DeletePolicy(ctx context.Context, policyID string) error {
	const query = `DELETE FROM rotation_policies WHERE id = $1`
	result, err := s.db.SQL().ExecContext(ctx, query, policyID)
	if err != nil {
		return fmt.Errorf("rotation: delete policy: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rotation: rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("rotation: policy %q not found", policyID)
	}
	return nil
}

// ListPolicies returns all rotation policies for a tenant.
func (s *SQLStore) ListPolicies(ctx context.Context, tenantID string) ([]RotationPolicy, error) {
	const query = `
		SELECT id, tenant_id, key_pattern, interval_ns, algorithm,
		       auto_approve, notify_emails, max_versions, enabled, last_run, next_run
		FROM rotation_policies
		WHERE tenant_id = $1
		ORDER BY id
	`
	rows, err := s.db.SQL().QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("rotation: list policies: %w", err)
	}
	defer rows.Close()

	var policies []RotationPolicy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("rotation: scan policy: %w", err)
		}
		policies = append(policies, *p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rotation: iterate policies: %w", err)
	}
	return policies, nil
}

// ListDuePolicies returns all enabled policies whose next_run is at or before the given time.
func (s *SQLStore) ListDuePolicies(ctx context.Context, now time.Time) ([]RotationPolicy, error) {
	const query = `
		SELECT id, tenant_id, key_pattern, interval_ns, algorithm,
		       auto_approve, notify_emails, max_versions, enabled, last_run, next_run
		FROM rotation_policies
		WHERE enabled = TRUE AND next_run <= $1
		ORDER BY next_run ASC
	`
	rows, err := s.db.SQL().QueryContext(ctx, query, now)
	if err != nil {
		return nil, fmt.Errorf("rotation: list due policies: %w", err)
	}
	defer rows.Close()

	var policies []RotationPolicy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("rotation: scan policy: %w", err)
		}
		policies = append(policies, *p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rotation: iterate due policies: %w", err)
	}
	return policies, nil
}

// UpdatePolicyTiming updates the last_run and next_run timestamps after a rotation.
func (s *SQLStore) UpdatePolicyTiming(ctx context.Context, policyID string, lastRun, nextRun time.Time) error {
	const query = `UPDATE rotation_policies SET last_run = $1, next_run = $2 WHERE id = $3`
	_, err := s.db.SQL().ExecContext(ctx, query, lastRun, nextRun, policyID)
	if err != nil {
		return fmt.Errorf("rotation: update timing: %w", err)
	}
	return nil
}

// SaveResult inserts a rotation execution result into the history table.
func (s *SQLStore) SaveResult(ctx context.Context, result *RotationResult) error {
	const query = `
		INSERT INTO rotation_history
			(policy_id, key_id, old_version, new_version, success, error, duration_ns, executed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := s.db.SQL().ExecContext(ctx, query,
		result.PolicyID,
		result.KeyID,
		result.OldVersion,
		result.NewVersion,
		result.Success,
		result.Error,
		int64(result.Duration),
		result.Timestamp,
	)
	if err != nil {
		return fmt.Errorf("rotation: save result: %w", err)
	}
	return nil
}

// GetHistory returns the most recent rotation results for a policy, limited by count.
func (s *SQLStore) GetHistory(ctx context.Context, policyID string, limit int) ([]RotationResult, error) {
	if limit <= 0 {
		limit = 50
	}
	const query = `
		SELECT policy_id, key_id, old_version, new_version, success, error, duration_ns, executed_at
		FROM rotation_history
		WHERE policy_id = $1
		ORDER BY executed_at DESC
		LIMIT $2
	`
	rows, err := s.db.ROSQL().QueryContext(ctx, query, policyID, limit)
	if err != nil {
		return nil, fmt.Errorf("rotation: get history: %w", err)
	}
	defer rows.Close()

	var results []RotationResult
	for rows.Next() {
		var r RotationResult
		var durationNS int64
		var errStr string
		if err := rows.Scan(
			&r.PolicyID, &r.KeyID, &r.OldVersion, &r.NewVersion,
			&r.Success, &errStr, &durationNS, &r.Timestamp,
		); err != nil {
			return nil, fmt.Errorf("rotation: scan result: %w", err)
		}
		r.Duration = time.Duration(durationNS)
		r.Error = errStr
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rotation: iterate history: %w", err)
	}
	return results, nil
}
