package main

import (
	"context"
	"database/sql"
	"encoding/json"
)

// ---- Schedules ----

func (s *SQLStore) ListDrillSchedules(ctx context.Context, tenantID string) ([]DrillSchedule, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, cron_expr, drill_type, scope, target_env,
       enabled, last_run_at, next_run_at, created_at
FROM dr_drill_schedules
WHERE tenant_id = $1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []DrillSchedule
	for rows.Next() {
		ds, err := scanDrillScheduleRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ds)
	}
	if out == nil {
		out = []DrillSchedule{}
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateDrillSchedule(ctx context.Context, ds DrillSchedule) (DrillSchedule, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO dr_drill_schedules
  (id, tenant_id, name, cron_expr, drill_type, scope, target_env, enabled, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP)
RETURNING id, tenant_id, name, cron_expr, drill_type, scope, target_env,
          enabled, last_run_at, next_run_at, created_at
`, ds.ID, ds.TenantID, ds.Name, ds.CronExpr, ds.DrillType, ds.Scope, ds.TargetEnv, ds.Enabled)

	return scanDrillScheduleSingleRow(row)
}

func (s *SQLStore) DeleteDrillSchedule(ctx context.Context, tenantID, id string) error {
	result, err := s.db.SQL().ExecContext(ctx,
		`DELETE FROM dr_drill_schedules WHERE tenant_id=$1 AND id=$2`,
		tenantID, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errStoreNotFound
	}
	return nil
}

func scanDrillScheduleRow(rows interface {
	Scan(dest ...any) error
}) (DrillSchedule, error) {
	var ds DrillSchedule
	var lastRunAt sql.NullTime
	var nextRunAt sql.NullTime
	if err := rows.Scan(
		&ds.ID, &ds.TenantID, &ds.Name, &ds.CronExpr, &ds.DrillType,
		&ds.Scope, &ds.TargetEnv, &ds.Enabled,
		&lastRunAt, &nextRunAt, &ds.CreatedAt,
	); err != nil {
		return DrillSchedule{}, err
	}
	if lastRunAt.Valid {
		t := lastRunAt.Time.UTC()
		ds.LastRunAt = &t
	}
	if nextRunAt.Valid {
		t := nextRunAt.Time.UTC()
		ds.NextRunAt = &t
	}
	return ds, nil
}

func scanDrillScheduleSingleRow(row *sql.Row) (DrillSchedule, error) {
	var ds DrillSchedule
	var lastRunAt sql.NullTime
	var nextRunAt sql.NullTime
	if err := row.Scan(
		&ds.ID, &ds.TenantID, &ds.Name, &ds.CronExpr, &ds.DrillType,
		&ds.Scope, &ds.TargetEnv, &ds.Enabled,
		&lastRunAt, &nextRunAt, &ds.CreatedAt,
	); err != nil {
		return DrillSchedule{}, err
	}
	if lastRunAt.Valid {
		t := lastRunAt.Time.UTC()
		ds.LastRunAt = &t
	}
	if nextRunAt.Valid {
		t := nextRunAt.Time.UTC()
		ds.NextRunAt = &t
	}
	return ds, nil
}

// ---- Drill Runs ----

func (s *SQLStore) CreateDrillRun(ctx context.Context, run DrillRun) (DrillRun, error) {
	stepsJSON, err := json.Marshal(run.Steps)
	if err != nil {
		return DrillRun{}, err
	}
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO dr_drill_runs
  (id, tenant_id, schedule_id, schedule_name, drill_type, status,
   started_at, total_keys, restored_keys, failed_keys, steps_json, triggered_by)
VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP,$7,$8,$9,$10,$11)
RETURNING id, tenant_id, COALESCE(schedule_id,''), COALESCE(schedule_name,''),
          drill_type, status, started_at, completed_at,
          COALESCE(rto_seconds,0), COALESCE(rpo_seconds,0),
          total_keys, restored_keys, failed_keys, steps_json, triggered_by
`, run.ID, run.TenantID,
		nullable(run.ScheduleID), nullable(run.ScheduleName),
		run.DrillType, run.Status,
		run.TotalKeys, run.RestoredKeys, run.FailedKeys,
		string(stepsJSON), run.TriggeredBy)

	return scanDrillRunSingleRow(row)
}

func (s *SQLStore) UpdateDrillRun(ctx context.Context, run DrillRun) (DrillRun, error) {
	stepsJSON, err := json.Marshal(run.Steps)
	if err != nil {
		return DrillRun{}, err
	}
	row := s.db.SQL().QueryRowContext(ctx, `
UPDATE dr_drill_runs
SET status=$3, completed_at=$4, rto_seconds=$5, rpo_seconds=$6,
    total_keys=$7, restored_keys=$8, failed_keys=$9, steps_json=$10
WHERE tenant_id=$1 AND id=$2
RETURNING id, tenant_id, COALESCE(schedule_id,''), COALESCE(schedule_name,''),
          drill_type, status, started_at, completed_at,
          COALESCE(rto_seconds,0), COALESCE(rpo_seconds,0),
          total_keys, restored_keys, failed_keys, steps_json, triggered_by
`, run.TenantID, run.ID, run.Status, nullableTime(run.CompletedAt),
		run.RTOSeconds, run.RPOSeconds,
		run.TotalKeys, run.RestoredKeys, run.FailedKeys, string(stepsJSON))

	dr, err := scanDrillRunSingleRow(row)
	if err == sql.ErrNoRows {
		return DrillRun{}, errStoreNotFound
	}
	return dr, err
}

func (s *SQLStore) ListDrillRuns(ctx context.Context, tenantID string, limit int) ([]DrillRun, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, COALESCE(schedule_id,''), COALESCE(schedule_name,''),
       drill_type, status, started_at, completed_at,
       COALESCE(rto_seconds,0), COALESCE(rpo_seconds,0),
       total_keys, restored_keys, failed_keys, steps_json, triggered_by
FROM dr_drill_runs
WHERE tenant_id = $1
ORDER BY started_at DESC
LIMIT $2
`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []DrillRun
	for rows.Next() {
		dr, err := scanDrillRunRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, dr)
	}
	if out == nil {
		out = []DrillRun{}
	}
	return out, rows.Err()
}

func (s *SQLStore) GetDrillRun(ctx context.Context, tenantID, id string) (DrillRun, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, COALESCE(schedule_id,''), COALESCE(schedule_name,''),
       drill_type, status, started_at, completed_at,
       COALESCE(rto_seconds,0), COALESCE(rpo_seconds,0),
       total_keys, restored_keys, failed_keys, steps_json, triggered_by
FROM dr_drill_runs
WHERE tenant_id=$1 AND id=$2
`, tenantID, id)
	dr, err := scanDrillRunSingleRow(row)
	if err == sql.ErrNoRows {
		return DrillRun{}, errStoreNotFound
	}
	return dr, err
}

func (s *SQLStore) GetDrillMetrics(ctx context.Context, tenantID string) (DrillMetrics, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT
  COUNT(*) AS total_runs,
  SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) AS successful_runs,
  SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) AS failed_runs,
  COALESCE(AVG(CASE WHEN rto_seconds > 0 THEN rto_seconds END), 0) AS avg_rto,
  COALESCE(AVG(CASE WHEN rpo_seconds > 0 THEN rpo_seconds END), 0) AS avg_rpo,
  COALESCE(AVG(CASE WHEN total_keys > 0 THEN restored_keys::float / total_keys * 100 END), 0) AS avg_restore_rate,
  MAX(started_at) AS last_run_at
FROM dr_drill_runs
WHERE tenant_id=$1
`, tenantID)

	var m DrillMetrics
	var lastRunAt sql.NullTime
	if err := row.Scan(
		&m.TotalRuns, &m.SuccessfulRuns, &m.FailedRuns,
		&m.AvgRTOSeconds, &m.AvgRPOSeconds, &m.AvgKeyRestoreRate,
		&lastRunAt,
	); err != nil {
		return DrillMetrics{}, err
	}
	if lastRunAt.Valid {
		t := lastRunAt.Time.UTC()
		m.LastRunAt = &t
	}

	// Fetch the status of the most recent run.
	statusRow := s.db.SQL().QueryRowContext(ctx, `
SELECT status FROM dr_drill_runs WHERE tenant_id=$1 ORDER BY started_at DESC LIMIT 1
`, tenantID)
	_ = statusRow.Scan(&m.LastRunStatus)

	return m, nil
}

func scanDrillRunRow(rows interface {
	Scan(dest ...any) error
}) (DrillRun, error) {
	var dr DrillRun
	var completedAt sql.NullTime
	var rawSteps string
	if err := rows.Scan(
		&dr.ID, &dr.TenantID, &dr.ScheduleID, &dr.ScheduleName,
		&dr.DrillType, &dr.Status, &dr.StartedAt, &completedAt,
		&dr.RTOSeconds, &dr.RPOSeconds,
		&dr.TotalKeys, &dr.RestoredKeys, &dr.FailedKeys,
		&rawSteps, &dr.TriggeredBy,
	); err != nil {
		return DrillRun{}, err
	}
	if completedAt.Valid {
		t := completedAt.Time.UTC()
		dr.CompletedAt = &t
	}
	if rawSteps != "" {
		_ = json.Unmarshal([]byte(rawSteps), &dr.Steps)
	}
	if dr.Steps == nil {
		dr.Steps = []DrillStep{}
	}
	return dr, nil
}

func scanDrillRunSingleRow(row *sql.Row) (DrillRun, error) {
	var dr DrillRun
	var completedAt sql.NullTime
	var rawSteps string
	if err := row.Scan(
		&dr.ID, &dr.TenantID, &dr.ScheduleID, &dr.ScheduleName,
		&dr.DrillType, &dr.Status, &dr.StartedAt, &completedAt,
		&dr.RTOSeconds, &dr.RPOSeconds,
		&dr.TotalKeys, &dr.RestoredKeys, &dr.FailedKeys,
		&rawSteps, &dr.TriggeredBy,
	); err != nil {
		return DrillRun{}, err
	}
	if completedAt.Valid {
		t := completedAt.Time.UTC()
		dr.CompletedAt = &t
	}
	if rawSteps != "" {
		_ = json.Unmarshal([]byte(rawSteps), &dr.Steps)
	}
	if dr.Steps == nil {
		dr.Steps = []DrillStep{}
	}
	return dr, nil
}
