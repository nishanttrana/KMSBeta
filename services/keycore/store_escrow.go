package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// ---- Guardians ----

func (s *SQLStore) ListEscrowGuardians(ctx context.Context, tenantID string) ([]EscrowGuardian, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, email, organization, notary_cert_fingerprint, status, added_at
FROM escrow_guardians
WHERE tenant_id = $1
ORDER BY added_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []EscrowGuardian
	for rows.Next() {
		var g EscrowGuardian
		if err := rows.Scan(
			&g.ID, &g.TenantID, &g.Name, &g.Email,
			&g.Organization, &g.NotaryCertFingerprint, &g.Status, &g.AddedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	if out == nil {
		out = []EscrowGuardian{}
	}
	return out, rows.Err()
}

func (s *SQLStore) AddEscrowGuardian(ctx context.Context, g EscrowGuardian) (EscrowGuardian, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO escrow_guardians (id, tenant_id, name, email, organization, notary_cert_fingerprint, status, added_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
RETURNING id, tenant_id, name, email, organization, notary_cert_fingerprint, status, added_at
`, g.ID, g.TenantID, g.Name, g.Email, g.Organization, g.NotaryCertFingerprint, g.Status)

	var out EscrowGuardian
	if err := row.Scan(
		&out.ID, &out.TenantID, &out.Name, &out.Email,
		&out.Organization, &out.NotaryCertFingerprint, &out.Status, &out.AddedAt,
	); err != nil {
		return EscrowGuardian{}, err
	}
	return out, nil
}

// ---- Policies ----

func (s *SQLStore) ListEscrowPolicies(ctx context.Context, tenantID string) ([]EscrowPolicy, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, description, key_filter, threshold,
       guardian_ids_json, legal_hold, jurisdiction, enabled, created_at, escrow_count
FROM escrow_policies
WHERE tenant_id = $1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []EscrowPolicy
	for rows.Next() {
		p, err := scanEscrowPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if out == nil {
		out = []EscrowPolicy{}
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateEscrowPolicy(ctx context.Context, p EscrowPolicy) (EscrowPolicy, error) {
	guardianJSON, err := json.Marshal(p.GuardianIDs)
	if err != nil {
		return EscrowPolicy{}, err
	}
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO escrow_policies
  (id, tenant_id, name, description, key_filter, threshold, guardian_ids_json,
   legal_hold, jurisdiction, enabled, created_at, escrow_count)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,CURRENT_TIMESTAMP,0)
RETURNING id, tenant_id, name, description, key_filter, threshold,
          guardian_ids_json, legal_hold, jurisdiction, enabled, created_at, escrow_count
`, p.ID, p.TenantID, p.Name, p.Description, p.KeyFilter, p.Threshold,
		string(guardianJSON), p.LegalHold, p.Jurisdiction, p.Enabled)

	return scanEscrowPolicyRow(row)
}

func scanEscrowPolicy(rows interface {
	Scan(dest ...any) error
}) (EscrowPolicy, error) {
	var p EscrowPolicy
	var rawGuardians string
	if err := rows.Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description, &p.KeyFilter, &p.Threshold,
		&rawGuardians, &p.LegalHold, &p.Jurisdiction, &p.Enabled, &p.CreatedAt, &p.EscrowCount,
	); err != nil {
		return EscrowPolicy{}, err
	}
	if rawGuardians != "" {
		_ = json.Unmarshal([]byte(rawGuardians), &p.GuardianIDs)
	}
	if p.GuardianIDs == nil {
		p.GuardianIDs = []string{}
	}
	return p, nil
}

func scanEscrowPolicyRow(row *sql.Row) (EscrowPolicy, error) {
	var p EscrowPolicy
	var rawGuardians string
	if err := row.Scan(
		&p.ID, &p.TenantID, &p.Name, &p.Description, &p.KeyFilter, &p.Threshold,
		&rawGuardians, &p.LegalHold, &p.Jurisdiction, &p.Enabled, &p.CreatedAt, &p.EscrowCount,
	); err != nil {
		return EscrowPolicy{}, err
	}
	if rawGuardians != "" {
		_ = json.Unmarshal([]byte(rawGuardians), &p.GuardianIDs)
	}
	if p.GuardianIDs == nil {
		p.GuardianIDs = []string{}
	}
	return p, nil
}

// ---- Escrowed Keys ----

func (s *SQLStore) ListEscrowedKeys(ctx context.Context, tenantID string) ([]EscrowedKey, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, policy_id, policy_name, key_id, key_name,
       algorithm, guardian_ids_json, status, escrowed_at, escrowed_by
FROM escrowed_keys
WHERE tenant_id = $1
ORDER BY escrowed_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []EscrowedKey
	for rows.Next() {
		var ek EscrowedKey
		var rawGuardians string
		if err := rows.Scan(
			&ek.ID, &ek.TenantID, &ek.PolicyID, &ek.PolicyName, &ek.KeyID, &ek.KeyName,
			&ek.Algorithm, &rawGuardians, &ek.Status, &ek.EscrowedAt, &ek.EscrowedBy,
		); err != nil {
			return nil, err
		}
		if rawGuardians != "" {
			_ = json.Unmarshal([]byte(rawGuardians), &ek.GuardianIDs)
		}
		if ek.GuardianIDs == nil {
			ek.GuardianIDs = []string{}
		}
		out = append(out, ek)
	}
	if out == nil {
		out = []EscrowedKey{}
	}
	return out, rows.Err()
}

func (s *SQLStore) AddEscrowedKey(ctx context.Context, ek EscrowedKey) (EscrowedKey, error) {
	guardianJSON, err := json.Marshal(ek.GuardianIDs)
	if err != nil {
		return EscrowedKey{}, err
	}
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO escrowed_keys
  (id, tenant_id, policy_id, policy_name, key_id, key_name, algorithm,
   guardian_ids_json, status, escrowed_at, escrowed_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',CURRENT_TIMESTAMP,$9)
RETURNING id, tenant_id, policy_id, policy_name, key_id, key_name,
          algorithm, guardian_ids_json, status, escrowed_at, escrowed_by
`, ek.ID, ek.TenantID, ek.PolicyID, ek.PolicyName, ek.KeyID, ek.KeyName,
		ek.Algorithm, string(guardianJSON), ek.EscrowedBy)

	var out EscrowedKey
	var rawGuardians string
	if err := row.Scan(
		&out.ID, &out.TenantID, &out.PolicyID, &out.PolicyName, &out.KeyID, &out.KeyName,
		&out.Algorithm, &rawGuardians, &out.Status, &out.EscrowedAt, &out.EscrowedBy,
	); err != nil {
		return EscrowedKey{}, err
	}
	if rawGuardians != "" {
		_ = json.Unmarshal([]byte(rawGuardians), &out.GuardianIDs)
	}
	if out.GuardianIDs == nil {
		out.GuardianIDs = []string{}
	}
	// Increment escrow_count on the policy.
	_, _ = s.db.SQL().ExecContext(ctx,
		`UPDATE escrow_policies SET escrow_count = escrow_count + 1 WHERE tenant_id=$1 AND id=$2`,
		out.TenantID, out.PolicyID)
	return out, nil
}

// ---- Recovery Requests ----

func (s *SQLStore) ListRecoveryRequests(ctx context.Context, tenantID string) ([]RecoveryRequest, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, escrow_id, key_id, key_name, requestor, reason, legal_reference,
       status, required_approvals, approvals_json, created_at, completed_at
FROM escrow_recovery_requests
WHERE tenant_id = $1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []RecoveryRequest
	for rows.Next() {
		rr, err := scanRecoveryRequestRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rr)
	}
	if out == nil {
		out = []RecoveryRequest{}
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateRecoveryRequest(ctx context.Context, rr RecoveryRequest) (RecoveryRequest, error) {
	approvalsJSON, err := json.Marshal([]RecoveryApproval{})
	if err != nil {
		return RecoveryRequest{}, err
	}
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO escrow_recovery_requests
  (id, tenant_id, escrow_id, key_id, key_name, requestor, reason, legal_reference,
   status, required_approvals, approvals_json, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$10,CURRENT_TIMESTAMP)
RETURNING id, tenant_id, escrow_id, key_id, key_name, requestor, reason, legal_reference,
          status, required_approvals, approvals_json, created_at, completed_at
`, rr.ID, rr.TenantID, rr.EscrowID, rr.KeyID, rr.KeyName, rr.Requestor, rr.Reason,
		rr.LegalReference, rr.RequiredApprovals, string(approvalsJSON))

	return scanRecoveryRequestSingleRow(row)
}

func (s *SQLStore) GetRecoveryRequest(ctx context.Context, tenantID, id string) (RecoveryRequest, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, escrow_id, key_id, key_name, requestor, reason, legal_reference,
       status, required_approvals, approvals_json, created_at, completed_at
FROM escrow_recovery_requests
WHERE tenant_id = $1 AND id = $2
`, tenantID, id)
	rr, err := scanRecoveryRequestSingleRow(row)
	if err == sql.ErrNoRows {
		return RecoveryRequest{}, errStoreNotFound
	}
	return rr, err
}

func (s *SQLStore) UpdateRecoveryRequestStatus(ctx context.Context, tenantID, id, status string, approvals []RecoveryApproval) (RecoveryRequest, error) {
	approvalsJSON, err := json.Marshal(approvals)
	if err != nil {
		return RecoveryRequest{}, err
	}
	var completedAt interface{}
	if status == "approved" || status == "denied" {
		t := time.Now().UTC()
		completedAt = t
	}
	row := s.db.SQL().QueryRowContext(ctx, `
UPDATE escrow_recovery_requests
SET status=$3, approvals_json=$4, completed_at=$5
WHERE tenant_id=$1 AND id=$2
RETURNING id, tenant_id, escrow_id, key_id, key_name, requestor, reason, legal_reference,
          status, required_approvals, approvals_json, created_at, completed_at
`, tenantID, id, status, string(approvalsJSON), completedAt)

	return scanRecoveryRequestSingleRow(row)
}

func scanRecoveryRequestRow(rows interface {
	Scan(dest ...any) error
}) (RecoveryRequest, error) {
	var rr RecoveryRequest
	var rawApprovals string
	var completedAt sql.NullTime
	if err := rows.Scan(
		&rr.ID, &rr.TenantID, &rr.EscrowID, &rr.KeyID, &rr.KeyName,
		&rr.Requestor, &rr.Reason, &rr.LegalReference,
		&rr.Status, &rr.RequiredApprovals, &rawApprovals,
		&rr.CreatedAt, &completedAt,
	); err != nil {
		return RecoveryRequest{}, err
	}
	if rawApprovals != "" {
		_ = json.Unmarshal([]byte(rawApprovals), &rr.Approvals)
	}
	if rr.Approvals == nil {
		rr.Approvals = []RecoveryApproval{}
	}
	if completedAt.Valid {
		t := completedAt.Time.UTC()
		rr.CompletedAt = &t
	}
	return rr, nil
}

func scanRecoveryRequestSingleRow(row *sql.Row) (RecoveryRequest, error) {
	var rr RecoveryRequest
	var rawApprovals string
	var completedAt sql.NullTime
	if err := row.Scan(
		&rr.ID, &rr.TenantID, &rr.EscrowID, &rr.KeyID, &rr.KeyName,
		&rr.Requestor, &rr.Reason, &rr.LegalReference,
		&rr.Status, &rr.RequiredApprovals, &rawApprovals,
		&rr.CreatedAt, &completedAt,
	); err != nil {
		return RecoveryRequest{}, err
	}
	if rawApprovals != "" {
		_ = json.Unmarshal([]byte(rawApprovals), &rr.Approvals)
	}
	if rr.Approvals == nil {
		rr.Approvals = []RecoveryApproval{}
	}
	if completedAt.Valid {
		t := completedAt.Time.UTC()
		rr.CompletedAt = &t
	}
	return rr, nil
}
