package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

// Store defines the storage interface for the backup service.
type Store interface {
	// Policies
	ListPolicies(ctx context.Context, tenantID string) ([]BackupPolicy, error)
	GetPolicy(ctx context.Context, tenantID, id string) (BackupPolicy, error)
	CreatePolicy(ctx context.Context, p BackupPolicy) (BackupPolicy, error)
	UpdatePolicy(ctx context.Context, tenantID, id string, req UpdatePolicyRequest) (BackupPolicy, error)
	DeletePolicy(ctx context.Context, tenantID, id string) error

	// Runs
	CreateRun(ctx context.Context, run BackupRun) (BackupRun, error)
	UpdateRun(ctx context.Context, tenantID, id string, status string, backedUp, failed int, sizeBytes int64, destPath string, completedAt time.Time, runErr string) error
	GetRun(ctx context.Context, tenantID, id string) (BackupRun, error)
	ListRuns(ctx context.Context, tenantID string) ([]BackupRun, error)

	// Restore points
	CreateRestorePoint(ctx context.Context, rp RestorePoint) (RestorePoint, error)
	ListRestorePoints(ctx context.Context, tenantID string) ([]RestorePoint, error)
	GetRestorePoint(ctx context.Context, tenantID, id string) (RestorePoint, error)
	UpdateRestorePointStatus(ctx context.Context, tenantID, id, status string) error

	// Metrics
	GetMetrics(ctx context.Context, tenantID string) (BackupMetrics, error)
}

// SQLStore implements Store backed by a SQL database.
type SQLStore struct {
	db *pkgdb.DB
}

// NewSQLStore creates a new SQLStore.
func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

// --- Policies ---

func (s *SQLStore) ListPolicies(ctx context.Context, tenantID string) ([]BackupPolicy, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, description, scope, tag_filter, cron_expr,
       retention_days, encrypt_backup, compress, destination, destination_uri,
       enabled, last_run_at, next_run_at, created_at
FROM backup_policies
WHERE tenant_id = $1
ORDER BY created_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]BackupPolicy, 0)
	for rows.Next() {
		p, scanErr := scanPolicy(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetPolicy(ctx context.Context, tenantID, id string) (BackupPolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, description, scope, tag_filter, cron_expr,
       retention_days, encrypt_backup, compress, destination, destination_uri,
       enabled, last_run_at, next_run_at, created_at
FROM backup_policies
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	p, err := scanPolicy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return BackupPolicy{}, errNotFound
	}
	return p, err
}

func (s *SQLStore) CreatePolicy(ctx context.Context, p BackupPolicy) (BackupPolicy, error) {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO backup_policies (
    id, tenant_id, name, description, scope, tag_filter, cron_expr,
    retention_days, encrypt_backup, compress, destination, destination_uri,
    enabled, created_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
`,
		p.ID, p.TenantID, p.Name, p.Description, p.Scope, p.TagFilter,
		p.CronExpr, p.RetentionDays, p.EncryptBackup, p.Compress,
		p.Destination, p.DestinationURI, p.Enabled, p.CreatedAt.UTC(),
	)
	if err != nil {
		return BackupPolicy{}, err
	}
	return s.GetPolicy(ctx, p.TenantID, p.ID)
}

func (s *SQLStore) UpdatePolicy(ctx context.Context, tenantID, id string, req UpdatePolicyRequest) (BackupPolicy, error) {
	existing, err := s.GetPolicy(ctx, tenantID, id)
	if err != nil {
		return BackupPolicy{}, err
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.CronExpr != nil {
		existing.CronExpr = *req.CronExpr
	}
	if req.RetentionDays != nil {
		existing.RetentionDays = *req.RetentionDays
	}
	if req.DestinationURI != nil {
		existing.DestinationURI = *req.DestinationURI
	}
	_, err = s.db.SQL().ExecContext(ctx, `
UPDATE backup_policies
SET enabled = $1, cron_expr = $2, retention_days = $3, destination_uri = $4
WHERE tenant_id = $5 AND id = $6
`, existing.Enabled, existing.CronExpr, existing.RetentionDays, existing.DestinationURI,
		strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return BackupPolicy{}, err
	}
	return s.GetPolicy(ctx, tenantID, id)
}

func (s *SQLStore) DeletePolicy(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM backup_policies WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

// markPolicyRun updates last_run_at on a policy.
func (s *SQLStore) markPolicyRun(ctx context.Context, tenantID, policyID string, at time.Time) {
	_, _ = s.db.SQL().ExecContext(ctx, `
UPDATE backup_policies SET last_run_at = $1 WHERE tenant_id = $2 AND id = $3
`, at.UTC(), strings.TrimSpace(tenantID), strings.TrimSpace(policyID))
}

// --- Runs ---

func (s *SQLStore) CreateRun(ctx context.Context, run BackupRun) (BackupRun, error) {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO backup_runs (
    id, tenant_id, policy_id, policy_name, status, scope,
    total_keys, backed_up_keys, failed_keys, backup_size_bytes,
    destination, destination_path, triggered_by, started_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
`,
		run.ID, run.TenantID,
		nullableStr(run.PolicyID), nullableStr(run.PolicyName),
		run.Status, run.Scope,
		run.TotalKeys, run.BackedUpKeys, run.FailedKeys, run.BackupSizeBytes,
		run.Destination, run.DestinationPath, run.TriggeredBy,
		run.StartedAt.UTC(),
	)
	if err != nil {
		return BackupRun{}, err
	}
	return s.GetRun(ctx, run.TenantID, run.ID)
}

func (s *SQLStore) UpdateRun(ctx context.Context, tenantID, id, status string, backedUp, failed int, sizeBytes int64, destPath string, completedAt time.Time, runErr string) error {
	var completedAtVal interface{}
	if !completedAt.IsZero() {
		completedAtVal = completedAt.UTC()
	}
	var errVal interface{}
	if strings.TrimSpace(runErr) != "" {
		errVal = strings.TrimSpace(runErr)
	}
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE backup_runs
SET status = $1, backed_up_keys = $2, failed_keys = $3,
    backup_size_bytes = $4, destination_path = $5, completed_at = $6, error = $7
WHERE tenant_id = $8 AND id = $9
`, status, backedUp, failed, sizeBytes, destPath, completedAtVal, errVal,
		strings.TrimSpace(tenantID), strings.TrimSpace(id))
	return err
}

func (s *SQLStore) GetRun(ctx context.Context, tenantID, id string) (BackupRun, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, COALESCE(policy_id,''), COALESCE(policy_name,''),
       status, scope, total_keys, backed_up_keys, failed_keys, backup_size_bytes,
       destination, destination_path, triggered_by, started_at, completed_at, COALESCE(error,'')
FROM backup_runs
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	run, err := scanRun(row)
	if errors.Is(err, sql.ErrNoRows) {
		return BackupRun{}, errNotFound
	}
	return run, err
}

func (s *SQLStore) ListRuns(ctx context.Context, tenantID string) ([]BackupRun, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, COALESCE(policy_id,''), COALESCE(policy_name,''),
       status, scope, total_keys, backed_up_keys, failed_keys, backup_size_bytes,
       destination, destination_path, triggered_by, started_at, completed_at, COALESCE(error,'')
FROM backup_runs
WHERE tenant_id = $1
ORDER BY started_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]BackupRun, 0)
	for rows.Next() {
		r, scanErr := scanRun(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- Restore Points ---

func (s *SQLStore) CreateRestorePoint(ctx context.Context, rp RestorePoint) (RestorePoint, error) {
	var expiresAt interface{}
	if rp.ExpiresAt != nil && !rp.ExpiresAt.IsZero() {
		expiresAt = rp.ExpiresAt.UTC()
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO backup_restore_points (
    id, tenant_id, run_id, name, key_count, backup_size_bytes,
    created_at, expires_at, checksum, status
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
`,
		rp.ID, rp.TenantID, rp.RunID, rp.Name,
		rp.KeyCount, rp.BackupSizeBytes, rp.CreatedAt.UTC(),
		expiresAt, rp.Checksum, rp.Status,
	)
	if err != nil {
		return RestorePoint{}, err
	}
	return rp, nil
}

func (s *SQLStore) ListRestorePoints(ctx context.Context, tenantID string) ([]RestorePoint, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, run_id, name, key_count, backup_size_bytes,
       created_at, expires_at, checksum, status
FROM backup_restore_points
WHERE tenant_id = $1
ORDER BY created_at DESC
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]RestorePoint, 0)
	for rows.Next() {
		rp, scanErr := scanRestorePoint(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, rp)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetRestorePoint(ctx context.Context, tenantID, id string) (RestorePoint, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, run_id, name, key_count, backup_size_bytes,
       created_at, expires_at, checksum, status
FROM backup_restore_points
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	rp, err := scanRestorePoint(row)
	if errors.Is(err, sql.ErrNoRows) {
		return RestorePoint{}, errNotFound
	}
	return rp, err
}

func (s *SQLStore) UpdateRestorePointStatus(ctx context.Context, tenantID, id, status string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE backup_restore_points SET status = $1
WHERE tenant_id = $2 AND id = $3
`, strings.TrimSpace(status), strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

// --- Metrics ---

func (s *SQLStore) GetMetrics(ctx context.Context, tenantID string) (BackupMetrics, error) {
	m := BackupMetrics{
		TenantID:   strings.TrimSpace(tenantID),
		ComputedAt: time.Now().UTC(),
	}

	// Policy counts.
	_ = s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*), SUM(CASE WHEN enabled THEN 1 ELSE 0 END)
FROM backup_policies WHERE tenant_id = $1
`, m.TenantID).Scan(&m.TotalPolicies, &m.EnabledPolicies)

	// Run counts.
	_ = s.db.SQL().QueryRowContext(ctx, `
SELECT
    COUNT(*),
    SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END),
    SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END),
    SUM(CASE WHEN status='running' THEN 1 ELSE 0 END),
    COALESCE(SUM(backup_size_bytes), 0),
    MAX(started_at)
FROM backup_runs WHERE tenant_id = $1
`, m.TenantID).Scan(
		&m.TotalRuns,
		&m.SuccessfulRuns,
		&m.FailedRuns,
		&m.RunningRuns,
		&m.TotalBackupBytes,
		new(interface{}),
	)

	// Last run time.
	var lastRunRaw interface{}
	_ = s.db.SQL().QueryRowContext(ctx, `
SELECT MAX(started_at) FROM backup_runs WHERE tenant_id = $1
`, m.TenantID).Scan(&lastRunRaw)
	if lastRunRaw != nil {
		t := parseBackupTime(lastRunRaw)
		if !t.IsZero() {
			m.LastRunAt = &t
		}
	}

	// Restore point count.
	_ = s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*) FROM backup_restore_points WHERE tenant_id = $1
`, m.TenantID).Scan(&m.TotalRestorePoints)

	return m, nil
}

// --- scan helpers ---

func scanPolicy(row interface{ Scan(...interface{}) error }) (BackupPolicy, error) {
	var p BackupPolicy
	var lastRunRaw, nextRunRaw, createdAtRaw interface{}
	err := row.Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description, &p.Scope, &p.TagFilter,
		&p.CronExpr, &p.RetentionDays, &p.EncryptBackup, &p.Compress,
		&p.Destination, &p.DestinationURI, &p.Enabled,
		&lastRunRaw, &nextRunRaw, &createdAtRaw,
	)
	if err != nil {
		return BackupPolicy{}, err
	}
	p.CreatedAt = parseBackupTime(createdAtRaw)
	if lastRunRaw != nil {
		t := parseBackupTime(lastRunRaw)
		if !t.IsZero() {
			p.LastRunAt = &t
		}
	}
	if nextRunRaw != nil {
		t := parseBackupTime(nextRunRaw)
		if !t.IsZero() {
			p.NextRunAt = &t
		}
	}
	return p, nil
}

func scanRun(row interface{ Scan(...interface{}) error }) (BackupRun, error) {
	var run BackupRun
	var startedAtRaw, completedAtRaw interface{}
	err := row.Scan(
		&run.ID, &run.TenantID, &run.PolicyID, &run.PolicyName,
		&run.Status, &run.Scope,
		&run.TotalKeys, &run.BackedUpKeys, &run.FailedKeys, &run.BackupSizeBytes,
		&run.Destination, &run.DestinationPath, &run.TriggeredBy,
		&startedAtRaw, &completedAtRaw, &run.Error,
	)
	if err != nil {
		return BackupRun{}, err
	}
	run.StartedAt = parseBackupTime(startedAtRaw)
	if completedAtRaw != nil {
		t := parseBackupTime(completedAtRaw)
		if !t.IsZero() {
			run.CompletedAt = &t
		}
	}
	return run, nil
}

func scanRestorePoint(row interface{ Scan(...interface{}) error }) (RestorePoint, error) {
	var rp RestorePoint
	var createdAtRaw, expiresAtRaw interface{}
	err := row.Scan(
		&rp.ID, &rp.TenantID, &rp.RunID, &rp.Name,
		&rp.KeyCount, &rp.BackupSizeBytes,
		&createdAtRaw, &expiresAtRaw, &rp.Checksum, &rp.Status,
	)
	if err != nil {
		return RestorePoint{}, err
	}
	rp.CreatedAt = parseBackupTime(createdAtRaw)
	if expiresAtRaw != nil {
		t := parseBackupTime(expiresAtRaw)
		if !t.IsZero() {
			rp.ExpiresAt = &t
		}
	}
	return rp, nil
}

// --- utility ---

func parseBackupTime(v interface{}) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t.UTC()
	case string:
		return parseBackupTimeString(t)
	case []byte:
		return parseBackupTimeString(string(t))
	default:
		return time.Time{}
	}
}

func parseBackupTimeString(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, f := range formats {
		if ts, err := time.Parse(f, s); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func newBackupID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func nullableStr(v string) interface{} {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return strings.TrimSpace(v)
}
