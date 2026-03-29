package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// ---- Playbooks ----

func (s *SQLStore) ListPlaybooks(ctx context.Context, tenantID string) ([]Playbook, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, description, trigger_json, actions_json,
       enabled, run_count, last_run_at, created_at
FROM compliance_playbooks
WHERE tenant_id = $1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []Playbook
	for rows.Next() {
		p, err := scanPlaybookRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if out == nil {
		out = []Playbook{}
	}
	return out, rows.Err()
}

func (s *SQLStore) CreatePlaybook(ctx context.Context, p Playbook) (Playbook, error) {
	triggerJSON, err := json.Marshal(p.Trigger)
	if err != nil {
		return Playbook{}, err
	}
	if p.Actions == nil {
		p.Actions = []PlaybookAction{}
	}
	actionsJSON, err := json.Marshal(p.Actions)
	if err != nil {
		return Playbook{}, err
	}
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO compliance_playbooks
  (id, tenant_id, name, description, trigger_json, actions_json, enabled, run_count, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,0,CURRENT_TIMESTAMP)
RETURNING id, tenant_id, name, description, trigger_json, actions_json,
          enabled, run_count, last_run_at, created_at
`, p.ID, p.TenantID, p.Name, p.Description,
		string(triggerJSON), string(actionsJSON), p.Enabled)
	return scanPlaybookSingleRow(row)
}

func (s *SQLStore) GetPlaybook(ctx context.Context, tenantID, id string) (Playbook, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, description, trigger_json, actions_json,
       enabled, run_count, last_run_at, created_at
FROM compliance_playbooks
WHERE tenant_id=$1 AND id=$2
`, tenantID, id)
	p, err := scanPlaybookSingleRow(row)
	if err == sql.ErrNoRows {
		return Playbook{}, errNotFound
	}
	return p, err
}

func (s *SQLStore) UpdatePlaybook(ctx context.Context, p Playbook) (Playbook, error) {
	triggerJSON, err := json.Marshal(p.Trigger)
	if err != nil {
		return Playbook{}, err
	}
	if p.Actions == nil {
		p.Actions = []PlaybookAction{}
	}
	actionsJSON, err := json.Marshal(p.Actions)
	if err != nil {
		return Playbook{}, err
	}
	row := s.db.SQL().QueryRowContext(ctx, `
UPDATE compliance_playbooks
SET name=$3, description=$4, trigger_json=$5, actions_json=$6, enabled=$7
WHERE tenant_id=$1 AND id=$2
RETURNING id, tenant_id, name, description, trigger_json, actions_json,
          enabled, run_count, last_run_at, created_at
`, p.TenantID, p.ID, p.Name, p.Description,
		string(triggerJSON), string(actionsJSON), p.Enabled)
	pb, err := scanPlaybookSingleRow(row)
	if err == sql.ErrNoRows {
		return Playbook{}, errNotFound
	}
	return pb, err
}

func (s *SQLStore) DeletePlaybook(ctx context.Context, tenantID, id string) error {
	result, err := s.db.SQL().ExecContext(ctx,
		`DELETE FROM compliance_playbooks WHERE tenant_id=$1 AND id=$2`,
		tenantID, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errNotFound
	}
	return nil
}

// ---- Playbook Runs ----

func (s *SQLStore) CreatePlaybookRun(ctx context.Context, run PlaybookRun) (PlaybookRun, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO compliance_playbook_runs
  (id, playbook_id, tenant_id, trigger_event, status, actions_run, output, started_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP)
RETURNING id, playbook_id, tenant_id, trigger_event, status, actions_run, output, started_at, completed_at
`, run.ID, run.PlaybookID, run.TenantID, run.TriggerEvent,
		run.Status, run.ActionsRun, run.Output)
	return scanPlaybookRunSingleRow(row)
}

func (s *SQLStore) UpdatePlaybookRun(ctx context.Context, run PlaybookRun) (PlaybookRun, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
UPDATE compliance_playbook_runs
SET status=$3, actions_run=$4, output=$5, completed_at=$6
WHERE tenant_id=$1 AND id=$2
RETURNING id, playbook_id, tenant_id, trigger_event, status, actions_run, output, started_at, completed_at
`, run.TenantID, run.ID, run.Status, run.ActionsRun, run.Output, nullableTimePtr(run.CompletedAt))
	pr, err := scanPlaybookRunSingleRow(row)
	if err == sql.ErrNoRows {
		return PlaybookRun{}, errNotFound
	}
	return pr, err
}

func (s *SQLStore) IncrementPlaybookRunCount(ctx context.Context, tenantID, id string, lastRunAt time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE compliance_playbooks
SET run_count = run_count + 1, last_run_at = $3
WHERE tenant_id=$1 AND id=$2
`, tenantID, id, lastRunAt)
	return err
}

func (s *SQLStore) ListPlaybookRuns(ctx context.Context, tenantID, playbookID string, limit int) ([]PlaybookRun, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, playbook_id, tenant_id, trigger_event, status, actions_run, output, started_at, completed_at
FROM compliance_playbook_runs
WHERE tenant_id=$1 AND playbook_id=$2
ORDER BY started_at DESC
LIMIT $3
`, tenantID, playbookID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []PlaybookRun
	for rows.Next() {
		pr, err := scanPlaybookRunRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, pr)
	}
	if out == nil {
		out = []PlaybookRun{}
	}
	return out, rows.Err()
}

func (s *SQLStore) GetPlaybookSummary(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	// Total and enabled playbook counts.
	var total, enabled int
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*), SUM(CASE WHEN enabled THEN 1 ELSE 0 END)
FROM compliance_playbooks
WHERE tenant_id=$1
`, tenantID)
	if err := row.Scan(&total, &enabled); err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	// Runs today.
	var runsToday int
	row = s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*)
FROM compliance_playbook_runs
WHERE tenant_id=$1 AND started_at >= DATE_TRUNC('day', NOW())
`, tenantID)
	_ = row.Scan(&runsToday)

	// Last run status.
	var lastRunStatus sql.NullString
	var lastRunAt sql.NullTime
	row = s.db.SQL().QueryRowContext(ctx, `
SELECT status, started_at
FROM compliance_playbook_runs
WHERE tenant_id=$1
ORDER BY started_at DESC
LIMIT 1
`, tenantID)
	_ = row.Scan(&lastRunStatus, &lastRunAt)

	var lastRunAtPtr *time.Time
	if lastRunAt.Valid {
		t := lastRunAt.Time.UTC()
		lastRunAtPtr = &t
	}

	return map[string]interface{}{
		"total_playbooks":  total,
		"enabled_count":    enabled,
		"runs_today":       runsToday,
		"last_run_status":  lastRunStatus.String,
		"last_run_at":      lastRunAtPtr,
	}, nil
}

// ---- scan helpers ----

func scanPlaybookRow(rows interface {
	Scan(dest ...any) error
}) (Playbook, error) {
	var p Playbook
	var rawTrigger, rawActions string
	var lastRunAt sql.NullTime
	if err := rows.Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description,
		&rawTrigger, &rawActions,
		&p.Enabled, &p.RunCount, &lastRunAt, &p.CreatedAt,
	); err != nil {
		return Playbook{}, err
	}
	p.CreatedAt = p.CreatedAt.UTC()
	if lastRunAt.Valid {
		t := lastRunAt.Time.UTC()
		p.LastRunAt = &t
	}
	if rawTrigger != "" {
		_ = json.Unmarshal([]byte(rawTrigger), &p.Trigger)
	}
	if rawActions != "" {
		_ = json.Unmarshal([]byte(rawActions), &p.Actions)
	}
	if p.Actions == nil {
		p.Actions = []PlaybookAction{}
	}
	return p, nil
}

func scanPlaybookSingleRow(row *sql.Row) (Playbook, error) {
	var p Playbook
	var rawTrigger, rawActions string
	var lastRunAt sql.NullTime
	if err := row.Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description,
		&rawTrigger, &rawActions,
		&p.Enabled, &p.RunCount, &lastRunAt, &p.CreatedAt,
	); err != nil {
		return Playbook{}, err
	}
	p.CreatedAt = p.CreatedAt.UTC()
	if lastRunAt.Valid {
		t := lastRunAt.Time.UTC()
		p.LastRunAt = &t
	}
	if rawTrigger != "" {
		_ = json.Unmarshal([]byte(rawTrigger), &p.Trigger)
	}
	if rawActions != "" {
		_ = json.Unmarshal([]byte(rawActions), &p.Actions)
	}
	if p.Actions == nil {
		p.Actions = []PlaybookAction{}
	}
	return p, nil
}

func scanPlaybookRunRow(rows interface {
	Scan(dest ...any) error
}) (PlaybookRun, error) {
	var pr PlaybookRun
	var completedAt sql.NullTime
	if err := rows.Scan(
		&pr.ID, &pr.PlaybookID, &pr.TenantID, &pr.TriggerEvent,
		&pr.Status, &pr.ActionsRun, &pr.Output, &pr.StartedAt, &completedAt,
	); err != nil {
		return PlaybookRun{}, err
	}
	pr.StartedAt = pr.StartedAt.UTC()
	if completedAt.Valid {
		t := completedAt.Time.UTC()
		pr.CompletedAt = &t
	}
	return pr, nil
}

func scanPlaybookRunSingleRow(row *sql.Row) (PlaybookRun, error) {
	var pr PlaybookRun
	var completedAt sql.NullTime
	if err := row.Scan(
		&pr.ID, &pr.PlaybookID, &pr.TenantID, &pr.TriggerEvent,
		&pr.Status, &pr.ActionsRun, &pr.Output, &pr.StartedAt, &completedAt,
	); err != nil {
		return PlaybookRun{}, err
	}
	pr.StartedAt = pr.StartedAt.UTC()
	if completedAt.Valid {
		t := completedAt.Time.UTC()
		pr.CompletedAt = &t
	}
	return pr, nil
}

// nullableTimePtr converts a *time.Time to a driver value.
func nullableTimePtr(v *time.Time) interface{} {
	if v == nil {
		return nil
	}
	return v.UTC()
}
