package main

import (
	"context"
	"encoding/json"
	"time"
)

// ─── Types for genuinely new tables ──────────────────────────────────────────

type KeySchedulingJob struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	Name          string     `json:"name"`
	JobType       string     `json:"job_type"`
	CronExpr      string     `json:"cron_expr"`
	TargetFilter  string     `json:"target_filter"`
	Payload       KeyLabels  `json:"payload"`
	Status        string     `json:"status"`
	Enabled       bool       `json:"enabled"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty"`
	LastRunStatus string     `json:"last_run_status"`
	LastRunError  string     `json:"last_run_error,omitempty"`
	NextRunAt     *time.Time `json:"next_run_at,omitempty"`
	RunCount      int        `json:"run_count"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type KDFConfig struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Algorithm string    `json:"algorithm"`
	Params    KeyLabels `json:"params"`
	Purpose   string    `json:"purpose"`
	Enabled   bool      `json:"enabled"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type KDFDerivationLog struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	ConfigID    string    `json:"config_id"`
	SourceKey   string    `json:"source_key"`
	Purpose     string    `json:"purpose"`
	ContextHash string    `json:"context_hash"`
	PerformedBy string    `json:"performed_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// ─── Key Scheduling Jobs ─────────────────────────────────────────────────────

func (s *SQLStore) ListSchedulingJobs(ctx context.Context, tenantID string) ([]KeySchedulingJob, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, job_type, cron_expr, target_filter, payload, status,
       enabled, last_run_at, last_run_status, last_run_error, next_run_at, run_count,
       created_by, created_at, updated_at
FROM key_scheduling_jobs WHERE tenant_id=$1 ORDER BY name ASC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []KeySchedulingJob
	for rows.Next() {
		j, err := scanSchedulingJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateSchedulingJob(ctx context.Context, j KeySchedulingJob) (KeySchedulingJob, error) {
	payloadRaw, _ := json.Marshal(j.Payload)
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO key_scheduling_jobs
  (id, tenant_id, name, job_type, cron_expr, target_filter, payload, status, enabled,
   next_run_at, created_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
RETURNING id, tenant_id, name, job_type, cron_expr, target_filter, payload, status,
          enabled, last_run_at, last_run_status, last_run_error, next_run_at, run_count,
          created_by, created_at, updated_at
`, j.ID, j.TenantID, j.Name, j.JobType, j.CronExpr, j.TargetFilter, payloadRaw,
		j.Status, j.Enabled, nullableTime(j.NextRunAt), j.CreatedBy)
	return scanSchedulingJob(row)
}

func (s *SQLStore) UpdateSchedulingJob(ctx context.Context, tenantID, id string, j KeySchedulingJob) (KeySchedulingJob, error) {
	payloadRaw, _ := json.Marshal(j.Payload)
	row := s.db.SQL().QueryRowContext(ctx, `
UPDATE key_scheduling_jobs SET name=$1, job_type=$2, cron_expr=$3, target_filter=$4,
  payload=$5, enabled=$6, next_run_at=$7, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$8 AND id=$9
RETURNING id, tenant_id, name, job_type, cron_expr, target_filter, payload, status,
          enabled, last_run_at, last_run_status, last_run_error, next_run_at, run_count,
          created_by, created_at, updated_at
`, j.Name, j.JobType, j.CronExpr, j.TargetFilter, payloadRaw, j.Enabled,
		nullableTime(j.NextRunAt), tenantID, id)
	return scanSchedulingJob(row)
}

func (s *SQLStore) DeleteSchedulingJob(ctx context.Context, tenantID, id string) error {
	_, err := s.db.SQL().ExecContext(ctx, `DELETE FROM key_scheduling_jobs WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	return err
}

func scanSchedulingJob(s interface{ Scan(...any) error }) (KeySchedulingJob, error) {
	var j KeySchedulingJob
	var payloadRaw []byte
	if err := s.Scan(&j.ID, &j.TenantID, &j.Name, &j.JobType, &j.CronExpr, &j.TargetFilter,
		&payloadRaw, &j.Status, &j.Enabled, &j.LastRunAt, &j.LastRunStatus, &j.LastRunError,
		&j.NextRunAt, &j.RunCount, &j.CreatedBy, &j.CreatedAt, &j.UpdatedAt); err != nil {
		return j, err
	}
	_ = json.Unmarshal(payloadRaw, &j.Payload)
	return j, nil
}

// ─── KDF ─────────────────────────────────────────────────────────────────────

func (s *SQLStore) ListKDFConfigs(ctx context.Context, tenantID string) ([]KDFConfig, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, algorithm, params, purpose, enabled, created_by, created_at, updated_at
FROM kdf_configs WHERE tenant_id=$1 ORDER BY name ASC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []KDFConfig
	for rows.Next() {
		c, err := scanKDFConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateKDFConfig(ctx context.Context, c KDFConfig) (KDFConfig, error) {
	paramsRaw, _ := json.Marshal(c.Params)
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO kdf_configs (id, tenant_id, name, algorithm, params, purpose, enabled, created_by, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
RETURNING id, tenant_id, name, algorithm, params, purpose, enabled, created_by, created_at, updated_at
`, c.ID, c.TenantID, c.Name, c.Algorithm, paramsRaw, c.Purpose, c.Enabled, c.CreatedBy)
	return scanKDFConfig(row)
}

func (s *SQLStore) DeleteKDFConfig(ctx context.Context, tenantID, id string) error {
	_, err := s.db.SQL().ExecContext(ctx, `DELETE FROM kdf_configs WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	return err
}

func (s *SQLStore) ListKDFDerivationLog(ctx context.Context, tenantID string, limit int) ([]KDFDerivationLog, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, config_id, source_key, purpose, context_hash, performed_by, created_at
FROM kdf_derivation_log WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []KDFDerivationLog
	for rows.Next() {
		var l KDFDerivationLog
		if err := rows.Scan(&l.ID, &l.TenantID, &l.ConfigID, &l.SourceKey, &l.Purpose,
			&l.ContextHash, &l.PerformedBy, &l.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (s *SQLStore) AppendKDFDerivationLog(ctx context.Context, l KDFDerivationLog) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO kdf_derivation_log (id, tenant_id, config_id, source_key, purpose, context_hash, performed_by, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP)`,
		l.ID, l.TenantID, l.ConfigID, l.SourceKey, l.Purpose, l.ContextHash, l.PerformedBy)
	return err
}

func scanKDFConfig(s interface{ Scan(...any) error }) (KDFConfig, error) {
	var c KDFConfig
	var paramsRaw []byte
	if err := s.Scan(&c.ID, &c.TenantID, &c.Name, &c.Algorithm, &paramsRaw, &c.Purpose,
		&c.Enabled, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return c, err
	}
	_ = json.Unmarshal(paramsRaw, &c.Params)
	return c, nil
}
