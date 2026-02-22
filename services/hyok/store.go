package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	UpsertEndpoint(ctx context.Context, endpoint EndpointConfig) error
	GetEndpoint(ctx context.Context, tenantID string, protocol string) (EndpointConfig, error)
	ListEndpoints(ctx context.Context, tenantID string) ([]EndpointConfig, error)
	DeleteEndpoint(ctx context.Context, tenantID string, protocol string) error

	CreateRequestLog(ctx context.Context, req ProxyRequestLog) error
	CompleteRequestLog(ctx context.Context, tenantID string, requestID string, status string, responseJSON string, errMessage string, approvalRequestID string, decision string) error
	GetRequestLog(ctx context.Context, tenantID string, requestID string) (ProxyRequestLog, error)
	ListRequestLogs(ctx context.Context, tenantID string, protocol string, limit int, offset int) ([]ProxyRequestLog, error)
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) UpsertEndpoint(ctx context.Context, endpoint EndpointConfig) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO hyok_endpoints (
	tenant_id, protocol, enabled, auth_mode, policy_id, governance_required, metadata_json, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, protocol) DO UPDATE SET
	enabled = excluded.enabled,
	auth_mode = excluded.auth_mode,
	policy_id = excluded.policy_id,
	governance_required = excluded.governance_required,
	metadata_json = excluded.metadata_json,
	updated_at = excluded.updated_at
`, endpoint.TenantID, endpoint.Protocol, endpoint.Enabled, endpoint.AuthMode, endpoint.PolicyID, endpoint.GovernanceRequired, validJSONOr(endpoint.MetadataJSON, "{}"))
	return err
}

func (s *SQLStore) GetEndpoint(ctx context.Context, tenantID string, protocol string) (EndpointConfig, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, protocol, enabled, auth_mode, policy_id, governance_required, metadata_json, created_at, updated_at
FROM hyok_endpoints
WHERE tenant_id = $1 AND protocol = $2
`, tenantID, protocol)
	out, err := scanEndpoint(row)
	if errors.Is(err, sql.ErrNoRows) {
		return EndpointConfig{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) ListEndpoints(ctx context.Context, tenantID string) ([]EndpointConfig, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, protocol, enabled, auth_mode, policy_id, governance_required, metadata_json, created_at, updated_at
FROM hyok_endpoints
WHERE tenant_id = $1
ORDER BY protocol
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]EndpointConfig, 0)
	for rows.Next() {
		item, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteEndpoint(ctx context.Context, tenantID string, protocol string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM hyok_endpoints
WHERE tenant_id = $1 AND protocol = $2
`, tenantID, protocol)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateRequestLog(ctx context.Context, req ProxyRequestLog) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO hyok_requests (
	id, tenant_id, protocol, operation, key_id, endpoint, auth_mode, auth_subject,
	requester_id, requester_email, policy_decision, governance_required, approval_request_id, status,
	request_json, response_json, error_message, created_at, completed_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,
	$9,$10,$11,$12,$13,$14,
	$15,$16,$17,CURRENT_TIMESTAMP,$18
)
`, req.ID, req.TenantID, req.Protocol, req.Operation, req.KeyID, req.Endpoint, req.AuthMode, req.AuthSubject,
		req.RequesterID, req.RequesterEmail, req.PolicyDecision, req.GovernanceReq, req.ApprovalRequestID, req.Status,
		validJSONOr(req.RequestJSON, "{}"), validJSONOr(req.ResponseJSON, "{}"), req.ErrorMessage, nullableTime(req.CompletedAt))
	return err
}

func (s *SQLStore) CompleteRequestLog(ctx context.Context, tenantID string, requestID string, status string, responseJSON string, errMessage string, approvalRequestID string, decision string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE hyok_requests
SET status = $1,
	response_json = $2,
	error_message = $3,
	approval_request_id = $4,
	policy_decision = $5,
	completed_at = $6
WHERE tenant_id = $7 AND id = $8
`, status, validJSONOr(responseJSON, "{}"), errMessage, approvalRequestID, decision, time.Now().UTC(), tenantID, requestID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) GetRequestLog(ctx context.Context, tenantID string, requestID string) (ProxyRequestLog, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, protocol, operation, key_id, endpoint, auth_mode, auth_subject,
	   requester_id, requester_email, policy_decision, governance_required, approval_request_id, status,
	   request_json, response_json, error_message, created_at, completed_at
FROM hyok_requests
WHERE tenant_id = $1 AND id = $2
`, tenantID, requestID)
	out, err := scanRequestLog(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ProxyRequestLog{}, errNotFound
	}
	return out, err
}

func (s *SQLStore) ListRequestLogs(ctx context.Context, tenantID string, protocol string, limit int, offset int) ([]ProxyRequestLog, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `
SELECT id, tenant_id, protocol, operation, key_id, endpoint, auth_mode, auth_subject,
	   requester_id, requester_email, policy_decision, governance_required, approval_request_id, status,
	   request_json, response_json, error_message, created_at, completed_at
FROM hyok_requests
WHERE tenant_id = $1
`
	args := []interface{}{tenantID}
	if strings.TrimSpace(protocol) != "" {
		q += " AND protocol = $2"
		args = append(args, normalizeProtocol(protocol))
		q += " ORDER BY created_at DESC LIMIT $3 OFFSET $4"
		args = append(args, limit, offset)
	} else {
		q += " ORDER BY created_at DESC LIMIT $2 OFFSET $3"
		args = append(args, limit, offset)
	}
	rows, err := s.db.SQL().QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ProxyRequestLog, 0)
	for rows.Next() {
		item, err := scanRequestLog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanEndpoint(scanner interface {
	Scan(dest ...interface{}) error
}) (EndpointConfig, error) {
	var (
		out        EndpointConfig
		enabledRaw interface{}
		govRaw     interface{}
		createdRaw interface{}
		updatedRaw interface{}
	)
	err := scanner.Scan(
		&out.TenantID, &out.Protocol, &enabledRaw, &out.AuthMode, &out.PolicyID, &govRaw, &out.MetadataJSON, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return EndpointConfig{}, err
	}
	out.Enabled = boolValue(enabledRaw)
	out.GovernanceRequired = boolValue(govRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	if out.MetadataJSON == "" {
		out.MetadataJSON = "{}"
	}
	return out, nil
}

func scanRequestLog(scanner interface {
	Scan(dest ...interface{}) error
}) (ProxyRequestLog, error) {
	var (
		out          ProxyRequestLog
		govRaw       interface{}
		createdRaw   interface{}
		completedRaw interface{}
	)
	err := scanner.Scan(
		&out.ID, &out.TenantID, &out.Protocol, &out.Operation, &out.KeyID, &out.Endpoint, &out.AuthMode, &out.AuthSubject,
		&out.RequesterID, &out.RequesterEmail, &out.PolicyDecision, &govRaw, &out.ApprovalRequestID, &out.Status,
		&out.RequestJSON, &out.ResponseJSON, &out.ErrorMessage, &createdRaw, &completedRaw,
	)
	if err != nil {
		return ProxyRequestLog{}, err
	}
	out.GovernanceReq = boolValue(govRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	out.CompletedAt = parseTimeValue(completedRaw)
	if out.RequestJSON == "" {
		out.RequestJSON = "{}"
	}
	if out.ResponseJSON == "" {
		out.ResponseJSON = "{}"
	}
	return out, nil
}

func boolValue(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case int:
		return x != 0
	case []byte:
		s := strings.TrimSpace(string(x))
		return s == "1" || strings.EqualFold(s, "true")
	case string:
		s := strings.TrimSpace(x)
		return s == "1" || strings.EqualFold(s, "true")
	default:
		return false
	}
}

func nullableTime(v time.Time) interface{} {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
}
