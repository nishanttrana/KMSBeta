package multicloudsync

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

const migrationSQL = `
CREATE TABLE IF NOT EXISTS multicloud_sync_policies (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	vecta_key_id TEXT NOT NULL,
	target_providers TEXT NOT NULL,
	sync_mode TEXT NOT NULL DEFAULT 'active',
	sync_interval_seconds INTEGER NOT NULL DEFAULT 3600,
	conflict_resolution TEXT NOT NULL DEFAULT 'source_wins',
	enabled BOOLEAN NOT NULL DEFAULT TRUE,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_mcs_policies_tenant ON multicloud_sync_policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_mcs_policies_enabled ON multicloud_sync_policies(enabled);

CREATE TABLE IF NOT EXISTS multicloud_sync_status (
	policy_id TEXT NOT NULL,
	provider TEXT NOT NULL,
	account_id TEXT NOT NULL,
	region TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'pending',
	last_sync TIMESTAMP,
	next_sync TIMESTAMP,
	error_msg TEXT,
	remote_key_version TEXT,
	local_key_version TEXT,
	PRIMARY KEY (policy_id, provider, account_id, region)
);
CREATE INDEX IF NOT EXISTS idx_mcs_status_policy ON multicloud_sync_status(policy_id);
`

// SQLStore persists sync policies and statuses to a SQL database.
type SQLStore struct {
	db *sql.DB
}

// NewSQLStore creates a new SQL store and runs migrations.
func NewSQLStore(db *sql.DB) (*SQLStore, error) {
	s := &SQLStore{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("multicloudsync/store: migration failed: %w", err)
	}
	return s, nil
}

func (s *SQLStore) migrate() error {
	_, err := s.db.Exec(migrationSQL)
	return err
}

// CreatePolicy inserts a new sync policy.
func (s *SQLStore) CreatePolicy(ctx context.Context, policy *SyncPolicy) error {
	targets, err := json.Marshal(policy.TargetProviders)
	if err != nil {
		return fmt.Errorf("multicloudsync/store: marshal targets: %w", err)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO multicloud_sync_policies (id, tenant_id, vecta_key_id, target_providers, sync_mode, sync_interval_seconds, conflict_resolution, enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		policy.ID, policy.TenantID, policy.VectaKeyID, string(targets),
		policy.SyncMode, int(policy.SyncInterval.Seconds()), policy.ConflictResolution,
		policy.Enabled, policy.CreatedAt, policy.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("multicloudsync/store: create policy: %w", err)
	}
	return nil
}

// GetPolicy retrieves a sync policy by ID.
func (s *SQLStore) GetPolicy(ctx context.Context, id string) (*SyncPolicy, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, tenant_id, vecta_key_id, target_providers, sync_mode, sync_interval_seconds, conflict_resolution, enabled, created_at, updated_at
		 FROM multicloud_sync_policies WHERE id = $1`, id)

	var policy SyncPolicy
	var targetsJSON string
	var intervalSecs int

	err := row.Scan(&policy.ID, &policy.TenantID, &policy.VectaKeyID, &targetsJSON,
		&policy.SyncMode, &intervalSecs, &policy.ConflictResolution,
		&policy.Enabled, &policy.CreatedAt, &policy.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("multicloudsync/store: get policy %s: %w", id, err)
	}

	policy.SyncInterval = time.Duration(intervalSecs) * time.Second
	if err := json.Unmarshal([]byte(targetsJSON), &policy.TargetProviders); err != nil {
		return nil, fmt.Errorf("multicloudsync/store: unmarshal targets: %w", err)
	}

	return &policy, nil
}

// ListEnabledPolicies returns all enabled sync policies.
func (s *SQLStore) ListEnabledPolicies(ctx context.Context) ([]*SyncPolicy, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, vecta_key_id, target_providers, sync_mode, sync_interval_seconds, conflict_resolution, enabled, created_at, updated_at
		 FROM multicloud_sync_policies WHERE enabled = TRUE`)
	if err != nil {
		return nil, fmt.Errorf("multicloudsync/store: list enabled policies: %w", err)
	}
	defer rows.Close()

	return s.scanPolicies(rows)
}

// ListPoliciesByTenant returns all sync policies for a tenant.
func (s *SQLStore) ListPoliciesByTenant(ctx context.Context, tenantID string) ([]*SyncPolicy, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, tenant_id, vecta_key_id, target_providers, sync_mode, sync_interval_seconds, conflict_resolution, enabled, created_at, updated_at
		 FROM multicloud_sync_policies WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("multicloudsync/store: list policies by tenant: %w", err)
	}
	defer rows.Close()

	return s.scanPolicies(rows)
}

func (s *SQLStore) scanPolicies(rows *sql.Rows) ([]*SyncPolicy, error) {
	var policies []*SyncPolicy
	for rows.Next() {
		var p SyncPolicy
		var targetsJSON string
		var intervalSecs int
		err := rows.Scan(&p.ID, &p.TenantID, &p.VectaKeyID, &targetsJSON,
			&p.SyncMode, &intervalSecs, &p.ConflictResolution,
			&p.Enabled, &p.CreatedAt, &p.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("multicloudsync/store: scan policy: %w", err)
		}
		p.SyncInterval = time.Duration(intervalSecs) * time.Second
		if err := json.Unmarshal([]byte(targetsJSON), &p.TargetProviders); err != nil {
			return nil, fmt.Errorf("multicloudsync/store: unmarshal targets: %w", err)
		}
		policies = append(policies, &p)
	}
	return policies, rows.Err()
}

// UpdatePolicy updates an existing sync policy.
func (s *SQLStore) UpdatePolicy(ctx context.Context, policy *SyncPolicy) error {
	targets, err := json.Marshal(policy.TargetProviders)
	if err != nil {
		return fmt.Errorf("multicloudsync/store: marshal targets: %w", err)
	}

	result, err := s.db.ExecContext(ctx,
		`UPDATE multicloud_sync_policies SET
			vecta_key_id = $2, target_providers = $3, sync_mode = $4,
			sync_interval_seconds = $5, conflict_resolution = $6, enabled = $7, updated_at = $8
		 WHERE id = $1`,
		policy.ID, policy.VectaKeyID, string(targets),
		policy.SyncMode, int(policy.SyncInterval.Seconds()),
		policy.ConflictResolution, policy.Enabled, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("multicloudsync/store: update policy: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("multicloudsync/store: policy %s not found", policy.ID)
	}
	return nil
}

// DeletePolicy removes a sync policy and its statuses.
func (s *SQLStore) DeletePolicy(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("multicloudsync/store: begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM multicloud_sync_status WHERE policy_id = $1`, id); err != nil {
		return fmt.Errorf("multicloudsync/store: delete statuses: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM multicloud_sync_policies WHERE id = $1`, id); err != nil {
		return fmt.Errorf("multicloudsync/store: delete policy: %w", err)
	}

	return tx.Commit()
}

// UpsertSyncStatus inserts or updates a sync status record.
func (s *SQLStore) UpsertSyncStatus(ctx context.Context, status *SyncStatus) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO multicloud_sync_status (policy_id, provider, account_id, region, status, last_sync, next_sync, error_msg, remote_key_version, local_key_version)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (policy_id, provider, account_id, region)
		 DO UPDATE SET status = $5, last_sync = $6, next_sync = $7, error_msg = $8, remote_key_version = $9, local_key_version = $10`,
		status.PolicyID, status.Provider, status.AccountID, status.Region,
		status.Status, status.LastSync, status.NextSync, status.ErrorMsg,
		status.RemoteKeyVer, status.LocalKeyVersion,
	)
	if err != nil {
		return fmt.Errorf("multicloudsync/store: upsert status: %w", err)
	}
	return nil
}

// ListSyncStatuses returns all sync statuses for a policy.
func (s *SQLStore) ListSyncStatuses(ctx context.Context, policyID string) ([]SyncStatus, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT policy_id, provider, account_id, region, status, last_sync, next_sync, COALESCE(error_msg, ''), COALESCE(remote_key_version, ''), COALESCE(local_key_version, '')
		 FROM multicloud_sync_status WHERE policy_id = $1`, policyID)
	if err != nil {
		return nil, fmt.Errorf("multicloudsync/store: list statuses: %w", err)
	}
	defer rows.Close()

	var statuses []SyncStatus
	for rows.Next() {
		var s SyncStatus
		err := rows.Scan(&s.PolicyID, &s.Provider, &s.AccountID, &s.Region,
			&s.Status, &s.LastSync, &s.NextSync, &s.ErrorMsg,
			&s.RemoteKeyVer, &s.LocalKeyVersion)
		if err != nil {
			return nil, fmt.Errorf("multicloudsync/store: scan status: %w", err)
		}
		statuses = append(statuses, s)
	}
	return statuses, rows.Err()
}
