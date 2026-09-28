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
SELECT id, tenant_id, name, description, category, trigger_json, actions_json,
       enabled, authorized_by, run_count, last_run_at, created_at
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

// ListAllPlaybooks returns every tenant's playbooks (the credential
// migration, primary only).
func (s *SQLStore) ListAllPlaybooks(ctx context.Context) ([]Playbook, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, description, category, trigger_json, actions_json,
       enabled, authorized_by, run_count, last_run_at, created_at
FROM compliance_playbooks
ORDER BY tenant_id, id
`)
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
  (id, tenant_id, name, description, category, trigger_json, actions_json, enabled, authorized_by, run_count, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,0,CURRENT_TIMESTAMP)
RETURNING id, tenant_id, name, description, category, trigger_json, actions_json,
          enabled, authorized_by, run_count, last_run_at, created_at
`, p.ID, p.TenantID, p.Name, p.Description, p.Category,
		string(triggerJSON), string(actionsJSON), p.Enabled, p.AuthorizedBy)
	return scanPlaybookRow(row)
}

func (s *SQLStore) GetPlaybook(ctx context.Context, tenantID, id string) (Playbook, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, description, category, trigger_json, actions_json,
       enabled, authorized_by, run_count, last_run_at, created_at
FROM compliance_playbooks
WHERE tenant_id=$1 AND id=$2
`, tenantID, id)
	p, err := scanPlaybookRow(row)
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
SET name=$3, description=$4, category=$5, trigger_json=$6, actions_json=$7, enabled=$8, authorized_by=$9
WHERE tenant_id=$1 AND id=$2
RETURNING id, tenant_id, name, description, category, trigger_json, actions_json,
          enabled, authorized_by, run_count, last_run_at, created_at
`, p.TenantID, p.ID, p.Name, p.Description, p.Category,
		string(triggerJSON), string(actionsJSON), p.Enabled, p.AuthorizedBy)
	pb, err := scanPlaybookRow(row)
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

// IncrementPlaybookRunCount counts a finished run.
func (s *SQLStore) IncrementPlaybookRunCount(ctx context.Context, tenantID, id string, lastRunAt time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE compliance_playbooks
SET run_count = run_count + 1, last_run_at = $3
WHERE tenant_id=$1 AND id=$2
`, tenantID, id, lastRunAt)
	return err
}

func (s *SQLStore) GetPlaybookSummary(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	// Total and enabled playbook counts.
	var total, enabled int
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*), COALESCE(SUM(CASE WHEN enabled THEN 1 ELSE 0 END), 0)
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

type rowScanner interface {
	Scan(dest ...any) error
}

func scanPlaybookRow(row rowScanner) (Playbook, error) {
	var p Playbook
	var rawTrigger, rawActions string
	var lastRunAt sql.NullTime
	if err := row.Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description, &p.Category,
		&rawTrigger, &rawActions,
		&p.Enabled, &p.AuthorizedBy, &p.RunCount, &lastRunAt, &p.CreatedAt,
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
	for i := range p.Actions {
		if renamed, ok := legacyActionNames[p.Actions[i].Type]; ok {
			p.Actions[i].Type = renamed
		}
		if p.Actions[i].Parameters == nil {
			p.Actions[i].Parameters = map[string]string{}
		}
	}
	return p, nil
}

// nullableTimePtr converts a *time.Time to a driver value.
func nullableTimePtr(v *time.Time) interface{} {
	if v == nil {
		return nil
	}
	return v.UTC()
}
