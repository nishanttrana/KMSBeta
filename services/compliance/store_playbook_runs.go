package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// RunQuery selects runs: of one playbook, in one status, or responding to
// one reporting incident.
type RunQuery struct {
	PlaybookID string
	Status     string
	IncidentID string
	Limit      int
}

const runColumns = `id, playbook_id, tenant_id, trigger_event, actor, actor_type, status, actions_run, output,
       context_json, results_json, resume_index, approved_index, approval_request_id, incident_id, retry_of,
       started_at, completed_at`

func runArgs(run PlaybookRun) (string, string) {
	ctxJSON, _ := json.Marshal(run.Context)
	if run.Results == nil {
		run.Results = []ActionResult{}
	}
	resJSON, _ := json.Marshal(run.Results)
	return string(ctxJSON), string(resJSON)
}

func (s *SQLStore) CreatePlaybookRun(ctx context.Context, run PlaybookRun) (PlaybookRun, error) {
	ctxJSON, resJSON := runArgs(run)
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO compliance_playbook_runs
  (id, playbook_id, tenant_id, trigger_event, actor, actor_type, status, actions_run, output,
   context_json, results_json, resume_index, approved_index, approval_request_id, incident_id, retry_of, started_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,CURRENT_TIMESTAMP)
RETURNING `+runColumns, run.ID, run.PlaybookID, run.TenantID, run.TriggerEvent, run.Actor, run.ActorType,
		run.Status, run.ActionsRun, run.Output, ctxJSON, resJSON, run.ResumeIndex, run.ApprovedIndex,
		run.ApprovalRequestID, run.IncidentID, run.RetryOf)
	return scanPlaybookRunRow(row)
}

func (s *SQLStore) UpdatePlaybookRun(ctx context.Context, run PlaybookRun) (PlaybookRun, error) {
	_, resJSON := runArgs(run)
	row := s.db.SQL().QueryRowContext(ctx, `
UPDATE compliance_playbook_runs
SET status=$3, actions_run=$4, output=$5, results_json=$6, resume_index=$7, approved_index=$8,
    approval_request_id=$9, completed_at=$10
WHERE tenant_id=$1 AND id=$2
RETURNING `+runColumns, run.TenantID, run.ID, run.Status, run.ActionsRun, run.Output, resJSON,
		run.ResumeIndex, run.ApprovedIndex, run.ApprovalRequestID, nullableTimePtr(run.CompletedAt))
	pr, err := scanPlaybookRunRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PlaybookRun{}, errNotFound
	}
	return pr, err
}

func (s *SQLStore) GetPlaybookRun(ctx context.Context, tenantID, id string) (PlaybookRun, error) {
	pr, err := scanPlaybookRunRow(s.db.SQL().QueryRowContext(ctx, `SELECT `+runColumns+`
FROM compliance_playbook_runs WHERE tenant_id=$1 AND id=$2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return PlaybookRun{}, errNotFound
	}
	return pr, err
}

func (s *SQLStore) GetPlaybookRunByApproval(ctx context.Context, tenantID, approvalID string) (PlaybookRun, error) {
	if strings.TrimSpace(approvalID) == "" {
		return PlaybookRun{}, errNotFound
	}
	pr, err := scanPlaybookRunRow(s.db.SQL().QueryRowContext(ctx, `SELECT `+runColumns+`
FROM compliance_playbook_runs WHERE tenant_id=$1 AND approval_request_id=$2`, tenantID, approvalID))
	if errors.Is(err, sql.ErrNoRows) {
		return PlaybookRun{}, errNotFound
	}
	return pr, err
}

func (s *SQLStore) ListPlaybookRuns(ctx context.Context, tenantID string, q RunQuery) ([]PlaybookRun, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 50
	}
	where, args := []string{"tenant_id=$1"}, []interface{}{tenantID}
	for col, v := range map[string]string{"playbook_id": q.PlaybookID, "status": q.Status, "incident_id": q.IncidentID} {
		if v = strings.TrimSpace(v); v != "" {
			args = append(args, v)
			where = append(where, col+"=$"+strconv.Itoa(len(args)))
		}
	}
	args = append(args, q.Limit)
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+runColumns+`
FROM compliance_playbook_runs WHERE `+strings.Join(where, " AND ")+`
ORDER BY started_at DESC LIMIT $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []PlaybookRun{}
	for rows.Next() {
		pr, err := scanPlaybookRunRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, pr)
	}
	return out, rows.Err()
}

func scanPlaybookRunRow(row rowScanner) (PlaybookRun, error) {
	var pr PlaybookRun
	var completedAt sql.NullTime
	var ctxJSON, resJSON string
	if err := row.Scan(
		&pr.ID, &pr.PlaybookID, &pr.TenantID, &pr.TriggerEvent, &pr.Actor, &pr.ActorType, &pr.Status,
		&pr.ActionsRun, &pr.Output, &ctxJSON, &resJSON, &pr.ResumeIndex, &pr.ApprovedIndex,
		&pr.ApprovalRequestID, &pr.IncidentID, &pr.RetryOf, &pr.StartedAt, &completedAt,
	); err != nil {
		return PlaybookRun{}, err
	}
	_ = json.Unmarshal([]byte(ctxJSON), &pr.Context)
	_ = json.Unmarshal([]byte(resJSON), &pr.Results)
	if pr.Results == nil {
		pr.Results = []ActionResult{}
	}
	pr.StartedAt = pr.StartedAt.UTC()
	if completedAt.Valid {
		t := completedAt.Time.UTC()
		pr.CompletedAt = &t
	}
	return pr, nil
}

// ---- connections ----

const connColumns = `id, tenant_id, name, type, endpoint, fields_set, created_by, created_at, updated_at,
       creds_ciphertext, creds_data_iv, creds_wrapped_dek, creds_wrapped_dek_iv`

func (s *SQLStore) ListConnections(ctx context.Context, tenantID string) ([]Connection, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT `+connColumns+`
FROM compliance_playbook_connections WHERE tenant_id=$1 ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []Connection{}
	for rows.Next() {
		c, err := scanConnection(rows)
		if err != nil {
			return nil, err
		}
		c.Sealed = nil
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetConnection(ctx context.Context, tenantID, id string) (Connection, error) {
	c, err := scanConnection(s.db.SQL().QueryRowContext(ctx, `SELECT `+connColumns+`
FROM compliance_playbook_connections WHERE tenant_id=$1 AND id=$2`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Connection{}, errNotFound
	}
	return c, err
}

func (s *SQLStore) CreateConnection(ctx context.Context, c Connection) (Connection, error) {
	if c.Sealed == nil {
		return Connection{}, errors.New("connection fields must be sealed before storing")
	}
	fields, _ := json.Marshal(c.FieldSet)
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO compliance_playbook_connections
  (id, tenant_id, name, type, endpoint, fields_set, created_by, created_at, updated_at,
   creds_ciphertext, creds_data_iv, creds_wrapped_dek, creds_wrapped_dek_iv)
VALUES ($1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,$8,$9,$10,$11)
`, c.ID, c.TenantID, c.Name, c.Type, c.Endpoint, string(fields), c.CreatedBy,
		c.Sealed.Ciphertext, c.Sealed.DataIV, c.Sealed.WrappedDEK, c.Sealed.WrappedDEKIV)
	if err != nil {
		return Connection{}, err
	}
	out, err := s.GetConnection(ctx, c.TenantID, c.ID)
	out.Sealed = nil
	return out, err
}

func (s *SQLStore) UpdateConnection(ctx context.Context, c Connection) (Connection, error) {
	if c.Sealed == nil {
		return Connection{}, errors.New("connection fields must be sealed before storing")
	}
	fields, _ := json.Marshal(c.FieldSet)
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE compliance_playbook_connections
SET name=$3, endpoint=$4, fields_set=$5, updated_at=CURRENT_TIMESTAMP,
    creds_ciphertext=$6, creds_data_iv=$7, creds_wrapped_dek=$8, creds_wrapped_dek_iv=$9
WHERE tenant_id=$1 AND id=$2
`, c.TenantID, c.ID, c.Name, c.Endpoint, string(fields),
		c.Sealed.Ciphertext, c.Sealed.DataIV, c.Sealed.WrappedDEK, c.Sealed.WrappedDEKIV)
	if err != nil {
		return Connection{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Connection{}, errNotFound
	}
	out, err := s.GetConnection(ctx, c.TenantID, c.ID)
	out.Sealed = nil
	return out, err
}

func (s *SQLStore) DeleteConnection(ctx context.Context, tenantID, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM compliance_playbook_connections WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func scanConnection(row rowScanner) (Connection, error) {
	var c Connection
	var fields string
	env := &pkgcrypto.EnvelopeCiphertext{}
	if err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.Type, &c.Endpoint, &fields, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt,
		&env.Ciphertext, &env.DataIV, &env.WrappedDEK, &env.WrappedDEKIV); err != nil {
		return Connection{}, err
	}
	_ = json.Unmarshal([]byte(fields), &c.FieldSet)
	if c.FieldSet == nil {
		c.FieldSet = []string{}
	}
	c.CreatedAt, c.UpdatedAt = c.CreatedAt.UTC(), c.UpdatedAt.UTC()
	if len(env.WrappedDEK) > 0 {
		c.Sealed = env
	}
	return c, nil
}
