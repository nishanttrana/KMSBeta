package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ListLeakTargets returns all scan targets for a tenant.
func (s *SQLStore) ListLeakTargets(ctx context.Context, tenantID string) ([]LeakScanTarget, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, type, uri, enabled, last_scanned_at,
       created_at, scan_count, open_findings
FROM leak_scan_targets
WHERE tenant_id=$1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []LeakScanTarget
	for rows.Next() {
		t, err := scanLeakTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetLeakTarget retrieves a single scan target by id.
func (s *SQLStore) GetLeakTarget(ctx context.Context, tenantID, id string) (LeakScanTarget, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, type, uri, enabled, last_scanned_at,
       created_at, scan_count, open_findings
FROM leak_scan_targets
WHERE tenant_id=$1 AND id=$2
`, tenantID, id)
	t, err := scanLeakTarget(row)
	if errors.Is(err, sql.ErrNoRows) {
		return LeakScanTarget{}, errNotFound
	}
	return t, err
}

// CreateLeakTarget inserts a new scan target.
func (s *SQLStore) CreateLeakTarget(ctx context.Context, t LeakScanTarget) (LeakScanTarget, error) {
	if t.ID == "" {
		t.ID = newID("lst")
	}
	t.CreatedAt = nowUTC()
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO leak_scan_targets (id, tenant_id, name, type, uri, enabled, created_at, scan_count, open_findings)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
`, t.ID, t.TenantID, t.Name, t.Type, t.URI, t.Enabled, t.CreatedAt, 0, 0)
	if err != nil {
		return LeakScanTarget{}, err
	}
	return t, nil
}

// DeleteLeakTarget removes a scan target.
func (s *SQLStore) DeleteLeakTarget(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM leak_scan_targets WHERE tenant_id=$1 AND id=$2
`, tenantID, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

// CreateLeakScanJob inserts a new scan job record.
func (s *SQLStore) CreateLeakScanJob(ctx context.Context, job LeakScanJob) (LeakScanJob, error) {
	if job.ID == "" {
		job.ID = newID("lsj")
	}
	job.CreatedAt = nowUTC()
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO leak_scan_jobs (id, tenant_id, target_id, target_name, target_type,
                            status, findings_count, progress_pct, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
`, job.ID, job.TenantID, job.TargetID, job.TargetName, job.TargetType,
		job.Status, job.FindingsCount, job.ProgressPct, job.CreatedAt)
	if err != nil {
		return LeakScanJob{}, err
	}
	return job, nil
}

// UpdateLeakScanJob updates status fields on an existing scan job.
func (s *SQLStore) UpdateLeakScanJob(ctx context.Context, tenantID, id, status string, progressPct, findingsCount int, startedAt, completedAt *time.Time, errMsg string) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE leak_scan_jobs
SET status=$1, progress_pct=$2, findings_count=$3, started_at=$4, completed_at=$5, error=$6
WHERE tenant_id=$7 AND id=$8
`, status, progressPct, findingsCount,
		nullableTimePtr(startedAt), nullableTimePtr(completedAt),
		nullableStr(errMsg), tenantID, id)
	return err
}

// ListLeakScanJobs returns recent scan jobs for a tenant, optionally filtered by target_id.
func (s *SQLStore) ListLeakScanJobs(ctx context.Context, tenantID, targetID string, limit int) ([]LeakScanJob, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var rows *sql.Rows
	var err error
	if strings.TrimSpace(targetID) != "" {
		rows, err = s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, target_id, target_name, target_type, status,
       started_at, completed_at, findings_count, COALESCE(error,''), progress_pct, created_at
FROM leak_scan_jobs
WHERE tenant_id=$1 AND target_id=$2
ORDER BY created_at DESC
LIMIT $3
`, tenantID, targetID, limit)
	} else {
		rows, err = s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, target_id, target_name, target_type, status,
       started_at, completed_at, findings_count, COALESCE(error,''), progress_pct, created_at
FROM leak_scan_jobs
WHERE tenant_id=$1
ORDER BY created_at DESC
LIMIT $2
`, tenantID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []LeakScanJob
	for rows.Next() {
		j, err := scanLeakScanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// CreateLeakFinding inserts a single leak finding.
func (s *SQLStore) CreateLeakFinding(ctx context.Context, f LeakFinding) (LeakFinding, error) {
	if f.ID == "" {
		f.ID = newID("lf")
	}
	if f.DetectedAt.IsZero() {
		f.DetectedAt = nowUTC()
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO leak_findings (id, tenant_id, job_id, target_id, target_name,
                           severity, type, description, location, context_preview,
                           entropy, status, detected_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT (tenant_id, id) DO NOTHING
`, f.ID, f.TenantID, f.JobID, f.TargetID, f.TargetName,
		f.Severity, f.Type, f.Description, f.Location, f.ContextPreview,
		f.Entropy, f.Status, f.DetectedAt)
	if err != nil {
		return LeakFinding{}, err
	}
	return f, nil
}

// ListLeakFindings returns findings for a tenant with optional status/severity filters.
func (s *SQLStore) ListLeakFindings(ctx context.Context, tenantID, status, severity string, limit int) ([]LeakFinding, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, job_id, target_id, target_name, severity, type,
       description, location, context_preview, entropy, status,
       detected_at, resolved_at, COALESCE(resolved_by,''), COALESCE(notes,'')
FROM leak_findings
WHERE tenant_id=$1
  AND ($2='' OR status=$2)
  AND ($3='' OR severity=$3)
ORDER BY detected_at DESC
LIMIT $4
`, tenantID, status, severity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []LeakFinding
	for rows.Next() {
		f, err := scanLeakFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// UpdateLeakFinding applies status/notes changes to a finding.
func (s *SQLStore) UpdateLeakFinding(ctx context.Context, tenantID, id, status, resolvedBy, notes string) error {
	var resolvedAt interface{}
	if strings.TrimSpace(status) == "resolved" {
		t := nowUTC()
		resolvedAt = t
	}
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE leak_findings
SET status=$1, resolved_by=$2, notes=$3, resolved_at=$4
WHERE tenant_id=$5 AND id=$6
`, nullableStr(status), nullableStr(resolvedBy), nullableStr(notes), resolvedAt, tenantID, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

// IncrementTargetScanCount increments the scan_count and sets last_scanned_at.
func (s *SQLStore) IncrementTargetScanCount(ctx context.Context, tenantID, targetID string, openFindings int) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE leak_scan_targets
SET scan_count    = scan_count + 1,
    last_scanned_at = CURRENT_TIMESTAMP,
    open_findings  = $1
WHERE tenant_id=$2 AND id=$3
`, openFindings, tenantID, targetID)
	return err
}

// scanLeakTarget scans a row into a LeakScanTarget.
func scanLeakTarget(scanner interface {
	Scan(dest ...interface{}) error
}) (LeakScanTarget, error) {
	var t LeakScanTarget
	var lastScannedRaw interface{}
	var createdRaw interface{}
	err := scanner.Scan(
		&t.ID, &t.TenantID, &t.Name, &t.Type, &t.URI, &t.Enabled,
		&lastScannedRaw, &createdRaw, &t.ScanCount, &t.OpenFindings,
	)
	if err != nil {
		return LeakScanTarget{}, err
	}
	t.CreatedAt = parseTimeValue(createdRaw)
	ts := parseTimeValue(lastScannedRaw)
	if !ts.IsZero() {
		t.LastScannedAt = &ts
	}
	return t, nil
}

// scanLeakScanJob scans a row into a LeakScanJob.
func scanLeakScanJob(scanner interface {
	Scan(dest ...interface{}) error
}) (LeakScanJob, error) {
	var j LeakScanJob
	var startedRaw interface{}
	var completedRaw interface{}
	var createdRaw interface{}
	err := scanner.Scan(
		&j.ID, &j.TenantID, &j.TargetID, &j.TargetName, &j.TargetType,
		&j.Status, &startedRaw, &completedRaw, &j.FindingsCount,
		&j.Error, &j.ProgressPct, &createdRaw,
	)
	if err != nil {
		return LeakScanJob{}, err
	}
	j.CreatedAt = parseTimeValue(createdRaw)
	if ts := parseTimeValue(startedRaw); !ts.IsZero() {
		j.StartedAt = &ts
	}
	if ts := parseTimeValue(completedRaw); !ts.IsZero() {
		j.CompletedAt = &ts
	}
	return j, nil
}

// scanLeakFinding scans a row into a LeakFinding.
func scanLeakFinding(scanner interface {
	Scan(dest ...interface{}) error
}) (LeakFinding, error) {
	var f LeakFinding
	var detectedRaw interface{}
	var resolvedRaw interface{}
	err := scanner.Scan(
		&f.ID, &f.TenantID, &f.JobID, &f.TargetID, &f.TargetName,
		&f.Severity, &f.Type, &f.Description, &f.Location, &f.ContextPreview,
		&f.Entropy, &f.Status, &detectedRaw, &resolvedRaw,
		&f.ResolvedBy, &f.Notes,
	)
	if err != nil {
		return LeakFinding{}, err
	}
	f.DetectedAt = parseTimeValue(detectedRaw)
	if ts := parseTimeValue(resolvedRaw); !ts.IsZero() {
		f.ResolvedAt = &ts
	}
	return f, nil
}

func nullableStr(v string) interface{} {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func nullableTimePtr(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return *t
}
