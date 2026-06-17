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
