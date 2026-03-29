package main

import (
	"context"
	"database/sql"
	"time"
)

// ListRotationPolicies returns all rotation policies for a tenant.
func (s *SQLStore) ListRotationPolicies(ctx context.Context, tenantID string) ([]RotationPolicy, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, target_type, target_filter, interval_days,
       COALESCE(cron_expr,''), auto_rotate, notify_days_before, enabled, status,
       last_rotation_at, next_rotation_at, total_rotations, COALESCE(last_error,''),
       created_at, updated_at
FROM rotation_policies
WHERE tenant_id = $1
ORDER BY name ASC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []RotationPolicy
	for rows.Next() {
		p, err := scanRotationPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CreateRotationPolicy inserts a new rotation policy.
func (s *SQLStore) CreateRotationPolicy(ctx context.Context, p RotationPolicy) (RotationPolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO rotation_policies
  (id, tenant_id, name, target_type, target_filter, interval_days, cron_expr,
   auto_rotate, notify_days_before, enabled, status, next_rotation_at, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
RETURNING id, tenant_id, name, target_type, target_filter, interval_days,
          COALESCE(cron_expr,''), auto_rotate, notify_days_before, enabled, status,
          last_rotation_at, next_rotation_at, total_rotations, COALESCE(last_error,''),
          created_at, updated_at
`, p.ID, p.TenantID, p.Name, p.TargetType, p.TargetFilter, p.IntervalDays,
		nullable(p.CronExpr), p.AutoRotate, p.NotifyDaysBefore, p.Enabled, p.Status,
		nullableTime(p.NextRotationAt))

	return scanRotationPolicy(row)
}

// UpdateRotationPolicy updates an existing rotation policy's mutable fields.
func (s *SQLStore) UpdateRotationPolicy(ctx context.Context, tenantID, id string, p RotationPolicy) (RotationPolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
UPDATE rotation_policies
SET name = $1,
    target_type = $2,
    target_filter = $3,
    interval_days = $4,
    cron_expr = $5,
    auto_rotate = $6,
    notify_days_before = $7,
    enabled = $8,
    status = $9,
    next_rotation_at = $10,
    updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $11 AND id = $12
RETURNING id, tenant_id, name, target_type, target_filter, interval_days,
          COALESCE(cron_expr,''), auto_rotate, notify_days_before, enabled, status,
          last_rotation_at, next_rotation_at, total_rotations, COALESCE(last_error,''),
          created_at, updated_at
`, p.Name, p.TargetType, p.TargetFilter, p.IntervalDays, nullable(p.CronExpr),
		p.AutoRotate, p.NotifyDaysBefore, p.Enabled, p.Status, nullableTime(p.NextRotationAt),
		tenantID, id)

	out, err := scanRotationPolicy(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return RotationPolicy{}, errStoreNotFound
		}
		return RotationPolicy{}, err
	}
	return out, nil
}

// DeleteRotationPolicy removes a rotation policy.
func (s *SQLStore) DeleteRotationPolicy(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM rotation_policies WHERE tenant_id = $1 AND id = $2
`, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

// ListRotationRuns returns rotation runs for a tenant, optionally filtered by policy.
func (s *SQLStore) ListRotationRuns(ctx context.Context, tenantID, policyID string) ([]RotationRun, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if policyID != "" {
		rows, err = s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, policy_id, policy_name, target_id, target_name, target_type,
       status, triggered_by, started_at, completed_at, COALESCE(error,'')
FROM rotation_runs
WHERE tenant_id = $1 AND policy_id = $2
ORDER BY started_at DESC
`, tenantID, policyID)
	} else {
		rows, err = s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, policy_id, policy_name, target_id, target_name, target_type,
       status, triggered_by, started_at, completed_at, COALESCE(error,'')
FROM rotation_runs
WHERE tenant_id = $1
ORDER BY started_at DESC
`, tenantID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []RotationRun
	for rows.Next() {
		rr, err := scanRotationRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rr)
	}
	return out, rows.Err()
}

// CreateRotationRun inserts a new rotation run record.
func (s *SQLStore) CreateRotationRun(ctx context.Context, r RotationRun) (RotationRun, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO rotation_runs
  (id, tenant_id, policy_id, policy_name, target_id, target_name, target_type,
   status, triggered_by, started_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
RETURNING id, tenant_id, policy_id, policy_name, target_id, target_name, target_type,
          status, triggered_by, started_at, completed_at, COALESCE(error,'')
`, r.ID, r.TenantID, r.PolicyID, r.PolicyName, r.TargetID, r.TargetName, r.TargetType,
		r.Status, r.TriggeredBy)

	return scanRotationRun(row)
}

// ListUpcomingRotations returns rotation policies with next_rotation_at within 30 days.
func (s *SQLStore) ListUpcomingRotations(ctx context.Context, tenantID string) ([]UpcomingRotation, error) {
	now := time.Now().UTC()
	horizon := now.AddDate(0, 0, 30)

	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, name, '' AS target_id, target_type, next_rotation_at
FROM rotation_policies
WHERE tenant_id = $1
  AND enabled = TRUE
  AND next_rotation_at IS NOT NULL
  AND next_rotation_at <= $2
ORDER BY next_rotation_at ASC
`, tenantID, horizon)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []UpcomingRotation
	for rows.Next() {
		var (
			policyID    string
			policyName  string
			targetID    string
			targetType  string
			scheduledAt time.Time
		)
		if err := rows.Scan(&policyID, &policyName, &targetID, &targetType, &scheduledAt); err != nil {
			return nil, err
		}
		scheduledAt = scheduledAt.UTC()
		diff := scheduledAt.Sub(now)
		daysUntil := int(diff.Hours() / 24)
		overdue := scheduledAt.Before(now)
		if overdue {
			daysUntil = 0
		}
		out = append(out, UpcomingRotation{
			PolicyID:    policyID,
			PolicyName:  policyName,
			TargetID:    targetID,
			TargetName:  policyName,
			TargetType:  targetType,
			ScheduledAt: scheduledAt,
			DaysUntil:   daysUntil,
			Overdue:     overdue,
		})
	}
	return out, rows.Err()
}

// scanRotationPolicy scans a single rotation policy row.
func scanRotationPolicy(scanner interface {
	Scan(dest ...interface{}) error
}) (RotationPolicy, error) {
	var (
		p              RotationPolicy
		lastRotationAt sql.NullTime
		nextRotationAt sql.NullTime
	)
	if err := scanner.Scan(
		&p.ID,
		&p.TenantID,
		&p.Name,
		&p.TargetType,
		&p.TargetFilter,
		&p.IntervalDays,
		&p.CronExpr,
		&p.AutoRotate,
		&p.NotifyDaysBefore,
		&p.Enabled,
		&p.Status,
		&lastRotationAt,
		&nextRotationAt,
		&p.TotalRotations,
		&p.LastError,
		&p.CreatedAt,
		&p.UpdatedAt,
	); err != nil {
		return RotationPolicy{}, err
	}
	if lastRotationAt.Valid {
		t := lastRotationAt.Time.UTC()
		p.LastRotationAt = &t
	}
	if nextRotationAt.Valid {
		t := nextRotationAt.Time.UTC()
		p.NextRotationAt = &t
	}
	return p, nil
}

// scanRotationRun scans a single rotation run row.
func scanRotationRun(scanner interface {
	Scan(dest ...interface{}) error
}) (RotationRun, error) {
	var (
		rr          RotationRun
		completedAt sql.NullTime
	)
	if err := scanner.Scan(
		&rr.ID,
		&rr.TenantID,
		&rr.PolicyID,
		&rr.PolicyName,
		&rr.TargetID,
		&rr.TargetName,
		&rr.TargetType,
		&rr.Status,
		&rr.TriggeredBy,
		&rr.StartedAt,
		&completedAt,
		&rr.Error,
	); err != nil {
		return RotationRun{}, err
	}
	if completedAt.Valid {
		t := completedAt.Time.UTC()
		rr.CompletedAt = &t
	}
	return rr, nil
}
