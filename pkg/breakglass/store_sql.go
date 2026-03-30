package breakglass

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"vecta-kms/pkg/db"
)

const breakglassMigration = `
CREATE TABLE IF NOT EXISTS breakglass_requests (
	id TEXT PRIMARY KEY,
	tenant_id TEXT NOT NULL,
	requestor_id TEXT NOT NULL,
	reason TEXT NOT NULL,
	target_key_id TEXT NOT NULL,
	required_approvals INT NOT NULL,
	status TEXT NOT NULL DEFAULT 'pending',
	expires_at TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS breakglass_approvals (
	request_id TEXT NOT NULL,
	approver_id TEXT NOT NULL,
	approver_email TEXT NOT NULL,
	challenge TEXT,
	approved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (request_id, approver_id)
);
`

// SQLStore implements the Store interface backed by PostgreSQL or SQLite.
type SQLStore struct {
	db *db.DB
}

// NewSQLStore creates a new SQL-backed break-glass store.
func NewSQLStore(database *db.DB) *SQLStore {
	return &SQLStore{db: database}
}

// Migrate creates the required tables if they do not exist.
func (s *SQLStore) Migrate(ctx context.Context) error {
	_, err := s.db.SQL().ExecContext(ctx, breakglassMigration)
	if err != nil {
		return fmt.Errorf("breakglass: migrate: %w", err)
	}
	return nil
}

// CreateRequest inserts a new emergency access request.
func (s *SQLStore) CreateRequest(ctx context.Context, req *EmergencyRequest) error {
	const query = `
		INSERT INTO breakglass_requests
			(id, tenant_id, requestor_id, reason, target_key_id, required_approvals, status, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := s.db.SQL().ExecContext(ctx, query,
		req.ID,
		req.TenantID,
		req.RequestorID,
		req.Reason,
		req.TargetKeyID,
		req.RequiredApprovals,
		req.Status,
		req.ExpiresAt,
		req.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("breakglass: insert request: %w", err)
	}
	return nil
}

// GetRequest fetches a request by ID and loads all associated approvals.
func (s *SQLStore) GetRequest(ctx context.Context, requestID string) (*EmergencyRequest, error) {
	const reqQuery = `
		SELECT id, tenant_id, requestor_id, reason, target_key_id,
		       required_approvals, status, expires_at, created_at
		FROM breakglass_requests
		WHERE id = $1
	`
	req := &EmergencyRequest{}
	err := s.db.SQL().QueryRowContext(ctx, reqQuery, requestID).Scan(
		&req.ID,
		&req.TenantID,
		&req.RequestorID,
		&req.Reason,
		&req.TargetKeyID,
		&req.RequiredApprovals,
		&req.Status,
		&req.ExpiresAt,
		&req.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrRequestNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("breakglass: get request: %w", err)
	}

	// Load approvals for this request
	const appQuery = `
		SELECT approver_id, approver_email, challenge, approved_at
		FROM breakglass_approvals
		WHERE request_id = $1
		ORDER BY approved_at ASC
	`
	rows, err := s.db.SQL().QueryContext(ctx, appQuery, requestID)
	if err != nil {
		return nil, fmt.Errorf("breakglass: get approvals: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var a Approval
		var challenge sql.NullString
		if err := rows.Scan(&a.ApproverID, &a.ApproverEmail, &challenge, &a.ApprovedAt); err != nil {
			return nil, fmt.Errorf("breakglass: scan approval: %w", err)
		}
		if challenge.Valid {
			a.Challenge = challenge.String
		}
		req.Approvals = append(req.Approvals, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("breakglass: iterate approvals: %w", err)
	}

	return req, nil
}

// AddApproval inserts an approval record for the given request.
func (s *SQLStore) AddApproval(ctx context.Context, requestID string, approval Approval) error {
	const query = `
		INSERT INTO breakglass_approvals
			(request_id, approver_id, approver_email, challenge, approved_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := s.db.SQL().ExecContext(ctx, query,
		requestID,
		approval.ApproverID,
		approval.ApproverEmail,
		approval.Challenge,
		approval.ApprovedAt,
	)
	if err != nil {
		return fmt.Errorf("breakglass: insert approval: %w", err)
	}
	return nil
}

// UpdateStatus changes the status of a request.
func (s *SQLStore) UpdateStatus(ctx context.Context, requestID string, status string) error {
	const query = `UPDATE breakglass_requests SET status = $1 WHERE id = $2`
	result, err := s.db.SQL().ExecContext(ctx, query, status, requestID)
	if err != nil {
		return fmt.Errorf("breakglass: update status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("breakglass: rows affected: %w", err)
	}
	if rows == 0 {
		return ErrRequestNotFound
	}
	return nil
}

// ListPending returns all pending requests for a tenant that have not expired.
func (s *SQLStore) ListPending(ctx context.Context, tenantID string) ([]*EmergencyRequest, error) {
	const query = `
		SELECT id, tenant_id, requestor_id, reason, target_key_id,
		       required_approvals, status, expires_at, created_at
		FROM breakglass_requests
		WHERE tenant_id = $1 AND status = 'pending' AND expires_at > $2
		ORDER BY created_at DESC
	`
	now := time.Now().UTC()
	rows, err := s.db.SQL().QueryContext(ctx, query, tenantID, now)
	if err != nil {
		return nil, fmt.Errorf("breakglass: list pending: %w", err)
	}
	defer rows.Close()

	var requests []*EmergencyRequest
	for rows.Next() {
		req := &EmergencyRequest{}
		if err := rows.Scan(
			&req.ID,
			&req.TenantID,
			&req.RequestorID,
			&req.Reason,
			&req.TargetKeyID,
			&req.RequiredApprovals,
			&req.Status,
			&req.ExpiresAt,
			&req.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("breakglass: scan request: %w", err)
		}
		requests = append(requests, req)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("breakglass: iterate requests: %w", err)
	}

	// Load approvals for each request
	for _, req := range requests {
		const appQuery = `
			SELECT approver_id, approver_email, challenge, approved_at
			FROM breakglass_approvals
			WHERE request_id = $1
			ORDER BY approved_at ASC
		`
		appRows, err := s.db.SQL().QueryContext(ctx, appQuery, req.ID)
		if err != nil {
			return nil, fmt.Errorf("breakglass: get approvals for %s: %w", req.ID, err)
		}
		for appRows.Next() {
			var a Approval
			var challenge sql.NullString
			if err := appRows.Scan(&a.ApproverID, &a.ApproverEmail, &challenge, &a.ApprovedAt); err != nil {
				appRows.Close()
				return nil, fmt.Errorf("breakglass: scan approval: %w", err)
			}
			if challenge.Valid {
				a.Challenge = challenge.String
			}
			req.Approvals = append(req.Approvals, a)
		}
		appRows.Close()
		if err := appRows.Err(); err != nil {
			return nil, fmt.Errorf("breakglass: iterate approvals: %w", err)
		}
	}

	return requests, nil
}
