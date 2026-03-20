package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

func (s *SQLStore) ListAccessGroups(ctx context.Context, tenantID string) ([]AccessGroup, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT g.id, g.tenant_id, g.name, COALESCE(g.description,''), COALESCE(g.created_by,''), COUNT(m.user_id) AS member_count, g.created_at, g.updated_at
FROM key_access_groups g
LEFT JOIN key_access_group_members m
  ON m.tenant_id = g.tenant_id AND m.group_id = g.id
WHERE g.tenant_id = $1
GROUP BY g.id, g.tenant_id, g.name, g.description, g.created_by, g.created_at, g.updated_at
ORDER BY g.name ASC
`, tenantID)
	if err != nil {
		if isMissingKeyAccessTableError(err) {
			return []AccessGroup{}, nil
		}
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]AccessGroup, 0)
	for rows.Next() {
		var item AccessGroup
		if err := rows.Scan(
			&item.ID,
			&item.TenantID,
			&item.Name,
			&item.Description,
			&item.CreatedBy,
			&item.MemberCount,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateAccessGroup(ctx context.Context, group AccessGroup) (AccessGroup, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO key_access_groups (tenant_id, id, name, description, created_by, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
RETURNING id, tenant_id, name, COALESCE(description,''), COALESCE(created_by,''), created_at, updated_at
`, group.TenantID, group.ID, group.Name, nullable(group.Description), group.CreatedBy)

	var out AccessGroup
	if err := row.Scan(
		&out.ID,
		&out.TenantID,
		&out.Name,
		&out.Description,
		&out.CreatedBy,
		&out.CreatedAt,
		&out.UpdatedAt,
	); err != nil {
		if isMissingKeyAccessTableError(err) {
			return AccessGroup{}, errors.New("key access control schema is not initialized")
		}
		return AccessGroup{}, err
	}
	out.MemberCount = 0
	return out, nil
}

func (s *SQLStore) DeleteAccessGroup(ctx context.Context, tenantID string, groupID string) error {
	return s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM key_access_group_members WHERE tenant_id=$1 AND group_id=$2`, tenantID, groupID)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM key_access_grants WHERE tenant_id=$1 AND subject_type='group' AND subject_id=$2`, tenantID, groupID)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM key_access_groups WHERE tenant_id=$1 AND id=$2`, tenantID, groupID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errStoreNotFound
		}
		return nil
	})
}

func (s *SQLStore) ReplaceAccessGroupMembers(ctx context.Context, tenantID string, groupID string, userIDs []string) error {
	return s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM key_access_groups WHERE tenant_id=$1 AND id=$2`, tenantID, groupID).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errStoreNotFound
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM key_access_group_members WHERE tenant_id=$1 AND group_id=$2`, tenantID, groupID); err != nil {
			return err
		}
		for _, userID := range userIDs {
			trimmed := strings.TrimSpace(userID)
			if trimmed == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, `
INSERT INTO key_access_group_members (tenant_id, group_id, user_id, created_at)
VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
`, tenantID, groupID, trimmed); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLStore) ListAccessGroupIDsForUser(ctx context.Context, tenantID string, userID string) ([]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT group_id
FROM key_access_group_members
WHERE tenant_id=$1 AND user_id=$2
`, tenantID, userID)
	if err != nil {
		if isMissingKeyAccessTableError(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]string, 0)
	for rows.Next() {
		var groupID string
		if err := rows.Scan(&groupID); err != nil {
			return nil, err
		}
		out = append(out, strings.TrimSpace(groupID))
	}
	return out, rows.Err()
}

func (s *SQLStore) ListKeyAccessGrants(ctx context.Context, tenantID string, keyID string) ([]KeyAccessGrant, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT subject_type, subject_id, operations, not_before, expires_at, COALESCE(justification,''), COALESCE(ticket_id,'')
FROM key_access_grants
WHERE tenant_id=$1 AND key_id=$2
ORDER BY subject_type ASC, subject_id ASC
`, tenantID, keyID)
	if err != nil {
		if isMissingKeyAccessTableError(err) {
			return []KeyAccessGrant{}, nil
		}
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]KeyAccessGrant, 0)
	for rows.Next() {
		var (
			subjectType   string
			subjectID     string
			rawOps        []byte
			notBefore     sql.NullTime
			expiresAt     sql.NullTime
			justification string
			ticketID      string
		)
		if err := rows.Scan(&subjectType, &subjectID, &rawOps, &notBefore, &expiresAt, &justification, &ticketID); err != nil {
			return nil, err
		}
		ops := make([]string, 0)
		if len(rawOps) > 0 {
			_ = json.Unmarshal(rawOps, &ops)
		}
		var notBeforePtr *time.Time
		if notBefore.Valid {
			v := notBefore.Time.UTC()
			notBeforePtr = &v
		}
		var expiresAtPtr *time.Time
		if expiresAt.Valid {
			v := expiresAt.Time.UTC()
			expiresAtPtr = &v
		}
		out = append(out, KeyAccessGrant{
			SubjectType:   AccessSubjectType(subjectType),
			SubjectID:     subjectID,
			Operations:    ops,
			NotBefore:     notBeforePtr,
			ExpiresAt:     expiresAtPtr,
			Justification: strings.TrimSpace(justification),
			TicketID:      strings.TrimSpace(ticketID),
		})
	}
	return out, rows.Err()
}

func isMissingKeyAccessTableError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if msg == "" {
		return false
	}
	return strings.Contains(msg, "no such table: key_access_grants") ||
		strings.Contains(msg, "no such table: key_access_group_members") ||
		strings.Contains(msg, "no such table: key_access_groups") ||
		strings.Contains(msg, "no such table: key_access_policy_settings") ||
		strings.Contains(msg, "no such table: key_interface_subject_policies") ||
		strings.Contains(msg, "no such table: key_interface_ports") ||
		strings.Contains(msg, "no such table: key_interface_tls_defaults") ||
		strings.Contains(msg, "no such table: key_request_nonce_cache") ||
		strings.Contains(msg, "relation \"key_access_grants\" does not exist") ||
		strings.Contains(msg, "relation \"key_access_group_members\" does not exist") ||
		strings.Contains(msg, "relation \"key_access_groups\" does not exist") ||
		strings.Contains(msg, "relation \"key_access_policy_settings\" does not exist") ||
		strings.Contains(msg, "relation \"key_interface_subject_policies\" does not exist") ||
		strings.Contains(msg, "relation \"key_interface_ports\" does not exist") ||
		strings.Contains(msg, "relation \"key_interface_tls_defaults\" does not exist") ||
		strings.Contains(msg, "relation \"key_request_nonce_cache\" does not exist")
}

func (s *SQLStore) ReplaceKeyAccessGrants(ctx context.Context, tenantID string, keyID string, grants []KeyAccessGrant, createdBy string) error {
	return s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM keys WHERE tenant_id=$1 AND id=$2`, tenantID, keyID).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errStoreNotFound
			}
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM key_access_grants WHERE tenant_id=$1 AND key_id=$2`, tenantID, keyID); err != nil {
			return err
		}
		for _, grant := range grants {
			rawOps, _ := json.Marshal(grant.Operations)
			if _, err := tx.ExecContext(ctx, `
INSERT INTO key_access_grants (
	tenant_id, key_id, subject_type, subject_id, operations, not_before, expires_at, justification, ticket_id, created_by, created_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
`, tenantID, keyID, string(grant.SubjectType), grant.SubjectID, rawOps, nullableTime(grant.NotBefore), nullableTime(grant.ExpiresAt), nullable(grant.Justification), nullable(grant.TicketID), createdBy); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLStore) GetKeyAccessSettings(ctx context.Context, tenantID string) (KeyAccessSettings, error) {
	var out KeyAccessSettings
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, deny_by_default, require_approval_for_policy_change, grant_default_ttl_minutes, grant_max_ttl_minutes,
       enforce_signed_requests, replay_window_seconds, nonce_ttl_seconds, require_interface_policies,
       COALESCE(updated_by,''), updated_at
FROM key_access_policy_settings
WHERE tenant_id=$1
`, tenantID).Scan(
		&out.TenantID,
		&out.DenyByDefault,
		&out.RequireApprovalForPolicyChange,
		&out.GrantDefaultTTLMinutes,
		&out.GrantMaxTTLMinutes,
		&out.EnforceSignedRequests,
		&out.ReplayWindowSeconds,
		&out.NonceTTLSeconds,
		&out.RequireInterfacePolicies,
		&out.UpdatedBy,
		&out.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultKeyAccessSettings(tenantID), nil
	}
	if err != nil {
		if isMissingKeyAccessTableError(err) {
			return defaultKeyAccessSettings(tenantID), nil
		}
		return KeyAccessSettings{}, err
	}
	return out, nil
}

func (s *SQLStore) UpsertKeyAccessSettings(ctx context.Context, settings KeyAccessSettings) (KeyAccessSettings, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO key_access_policy_settings (
    tenant_id, deny_by_default, require_approval_for_policy_change, grant_default_ttl_minutes, grant_max_ttl_minutes,
    enforce_signed_requests, replay_window_seconds, nonce_ttl_seconds, require_interface_policies, updated_by, updated_at
)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id)
DO UPDATE SET
    deny_by_default=EXCLUDED.deny_by_default,
    require_approval_for_policy_change=EXCLUDED.require_approval_for_policy_change,
    grant_default_ttl_minutes=EXCLUDED.grant_default_ttl_minutes,
    grant_max_ttl_minutes=EXCLUDED.grant_max_ttl_minutes,
    enforce_signed_requests=EXCLUDED.enforce_signed_requests,
    replay_window_seconds=EXCLUDED.replay_window_seconds,
    nonce_ttl_seconds=EXCLUDED.nonce_ttl_seconds,
    require_interface_policies=EXCLUDED.require_interface_policies,
    updated_by=EXCLUDED.updated_by,
    updated_at=CURRENT_TIMESTAMP
RETURNING tenant_id, deny_by_default, require_approval_for_policy_change, grant_default_ttl_minutes, grant_max_ttl_minutes,
          enforce_signed_requests, replay_window_seconds, nonce_ttl_seconds, require_interface_policies, COALESCE(updated_by,''), updated_at
`, settings.TenantID, settings.DenyByDefault, settings.RequireApprovalForPolicyChange, settings.GrantDefaultTTLMinutes, settings.GrantMaxTTLMinutes,
		settings.EnforceSignedRequests, settings.ReplayWindowSeconds, settings.NonceTTLSeconds, settings.RequireInterfacePolicies, nullable(settings.UpdatedBy))

	var out KeyAccessSettings
	if err := row.Scan(
		&out.TenantID,
		&out.DenyByDefault,
		&out.RequireApprovalForPolicyChange,
		&out.GrantDefaultTTLMinutes,
		&out.GrantMaxTTLMinutes,
		&out.EnforceSignedRequests,
		&out.ReplayWindowSeconds,
		&out.NonceTTLSeconds,
		&out.RequireInterfacePolicies,
		&out.UpdatedBy,
		&out.UpdatedAt,
	); err != nil {
		return KeyAccessSettings{}, err
	}
	return out, nil
}

func (s *SQLStore) ListKeyInterfaceSubjectPolicies(ctx context.Context, tenantID string, interfaceName string) ([]KeyInterfaceSubjectPolicy, error) {
	interfaceName = normalizeInterfaceName(interfaceName)
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, interface_name, subject_type, subject_id, operations, enabled, COALESCE(created_by,''), created_at, updated_at
FROM key_interface_subject_policies
WHERE tenant_id=$1 AND interface_name=$2
ORDER BY subject_type ASC, subject_id ASC
`, tenantID, interfaceName)
	if err != nil {
		if isMissingKeyAccessTableError(err) {
			return []KeyInterfaceSubjectPolicy{}, nil
		}
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]KeyInterfaceSubjectPolicy, 0)
	for rows.Next() {
		var (
			item   KeyInterfaceSubjectPolicy
			rawOps []byte
		)
		if err := rows.Scan(
			&item.ID,
			&item.TenantID,
			&item.InterfaceName,
			&item.SubjectType,
			&item.SubjectID,
			&rawOps,
			&item.Enabled,
			&item.CreatedBy,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if len(rawOps) > 0 {
			_ = json.Unmarshal(rawOps, &item.Operations)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertKeyInterfaceSubjectPolicy(ctx context.Context, policy KeyInterfaceSubjectPolicy) (KeyInterfaceSubjectPolicy, error) {
	rawOps, _ := json.Marshal(policy.Operations)
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO key_interface_subject_policies (
    tenant_id, id, interface_name, subject_type, subject_id, operations, enabled, created_by, created_at, updated_at
)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id, id)
DO UPDATE SET
    interface_name=EXCLUDED.interface_name,
    subject_type=EXCLUDED.subject_type,
    subject_id=EXCLUDED.subject_id,
    operations=EXCLUDED.operations,
    enabled=EXCLUDED.enabled,
    created_by=EXCLUDED.created_by,
    updated_at=CURRENT_TIMESTAMP
RETURNING id, tenant_id, interface_name, subject_type, subject_id, operations, enabled, COALESCE(created_by,''), created_at, updated_at
`, policy.TenantID, policy.ID, policy.InterfaceName, string(policy.SubjectType), policy.SubjectID, rawOps, policy.Enabled, nullable(policy.CreatedBy))

	var out KeyInterfaceSubjectPolicy
	var outOps []byte
	if err := row.Scan(
		&out.ID,
		&out.TenantID,
		&out.InterfaceName,
		&out.SubjectType,
		&out.SubjectID,
		&outOps,
		&out.Enabled,
		&out.CreatedBy,
		&out.CreatedAt,
		&out.UpdatedAt,
	); err != nil {
		return KeyInterfaceSubjectPolicy{}, err
	}
	if len(outOps) > 0 {
		_ = json.Unmarshal(outOps, &out.Operations)
	}
	return out, nil
}

func (s *SQLStore) DeleteKeyInterfaceSubjectPolicy(ctx context.Context, tenantID string, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM key_interface_subject_policies WHERE tenant_id=$1 AND id=$2
`, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) ListKeyInterfacePorts(ctx context.Context, tenantID string) ([]KeyInterfacePort, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, interface_name, bind_address, port, COALESCE(protocol,''), COALESCE(pqc_mode,''), COALESCE(certificate_source,''), COALESCE(ca_id,''), COALESCE(certificate_id,''), enabled, COALESCE(description,''), COALESCE(updated_by,''), updated_at
FROM key_interface_ports
WHERE tenant_id=$1
ORDER BY interface_name ASC
`, tenantID)
	if err != nil {
		if isMissingKeyAccessTableError(err) {
			return []KeyInterfacePort{}, nil
		}
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]KeyInterfacePort, 0)
	for rows.Next() {
		var item KeyInterfacePort
		if err := rows.Scan(&item.TenantID, &item.InterfaceName, &item.BindAddress, &item.Port, &item.Protocol, &item.PQCMode, &item.CertSource, &item.CAID, &item.CertificateID, &item.Enabled, &item.Description, &item.UpdatedBy, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetKeyInterfaceTLSConfig(ctx context.Context, tenantID string) (KeyInterfaceTLSConfig, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, COALESCE(certificate_source,''), COALESCE(ca_id,''), COALESCE(certificate_id,''), COALESCE(updated_by,''), updated_at
FROM key_interface_tls_defaults
WHERE tenant_id=$1
`, tenantID)
	var out KeyInterfaceTLSConfig
	if err := row.Scan(&out.TenantID, &out.CertSource, &out.CAID, &out.CertificateID, &out.UpdatedBy, &out.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) || isMissingKeyAccessTableError(err) {
			return defaultKeyInterfaceTLSConfig(tenantID), nil
		}
		return KeyInterfaceTLSConfig{}, err
	}
	return out, nil
}

func (s *SQLStore) UpsertKeyInterfaceTLSConfig(ctx context.Context, cfg KeyInterfaceTLSConfig) (KeyInterfaceTLSConfig, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO key_interface_tls_defaults (tenant_id, certificate_source, ca_id, certificate_id, updated_by, updated_at)
VALUES ($1,$2,$3,$4,$5,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id)
DO UPDATE SET
    certificate_source=EXCLUDED.certificate_source,
    ca_id=EXCLUDED.ca_id,
    certificate_id=EXCLUDED.certificate_id,
    updated_by=EXCLUDED.updated_by,
    updated_at=CURRENT_TIMESTAMP
RETURNING tenant_id, COALESCE(certificate_source,''), COALESCE(ca_id,''), COALESCE(certificate_id,''), COALESCE(updated_by,''), updated_at
`, cfg.TenantID, cfg.CertSource, nullable(cfg.CAID), nullable(cfg.CertificateID), nullable(cfg.UpdatedBy))

	var out KeyInterfaceTLSConfig
	if err := row.Scan(&out.TenantID, &out.CertSource, &out.CAID, &out.CertificateID, &out.UpdatedBy, &out.UpdatedAt); err != nil {
		return KeyInterfaceTLSConfig{}, err
	}
	return out, nil
}

func (s *SQLStore) UpsertKeyInterfacePort(ctx context.Context, port KeyInterfacePort) (KeyInterfacePort, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO key_interface_ports (tenant_id, interface_name, bind_address, port, protocol, pqc_mode, certificate_source, ca_id, certificate_id, enabled, description, updated_by, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id, interface_name)
DO UPDATE SET
    bind_address=EXCLUDED.bind_address,
    port=EXCLUDED.port,
    protocol=EXCLUDED.protocol,
    pqc_mode=EXCLUDED.pqc_mode,
    certificate_source=EXCLUDED.certificate_source,
    ca_id=EXCLUDED.ca_id,
    certificate_id=EXCLUDED.certificate_id,
    enabled=EXCLUDED.enabled,
    description=EXCLUDED.description,
    updated_by=EXCLUDED.updated_by,
    updated_at=CURRENT_TIMESTAMP
RETURNING tenant_id, interface_name, bind_address, port, COALESCE(protocol,''), COALESCE(pqc_mode,''), COALESCE(certificate_source,''), COALESCE(ca_id,''), COALESCE(certificate_id,''), enabled, COALESCE(description,''), COALESCE(updated_by,''), updated_at
`, port.TenantID, port.InterfaceName, port.BindAddress, port.Port, port.Protocol, port.PQCMode, port.CertSource, nullable(port.CAID), nullable(port.CertificateID), port.Enabled, nullable(port.Description), nullable(port.UpdatedBy))

	var out KeyInterfacePort
	if err := row.Scan(&out.TenantID, &out.InterfaceName, &out.BindAddress, &out.Port, &out.Protocol, &out.PQCMode, &out.CertSource, &out.CAID, &out.CertificateID, &out.Enabled, &out.Description, &out.UpdatedBy, &out.UpdatedAt); err != nil {
		return KeyInterfacePort{}, err
	}
	return out, nil
}

func (s *SQLStore) DeleteKeyInterfacePort(ctx context.Context, tenantID string, interfaceName string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM key_interface_ports WHERE tenant_id=$1 AND interface_name=$2
`, tenantID, interfaceName)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errStoreNotFound
	}
	return nil
}

func (s *SQLStore) ReserveRequestNonce(ctx context.Context, tenantID string, nonce string, expiresAt time.Time) error {
	trimmedNonce := strings.TrimSpace(nonce)
	if trimmedNonce == "" {
		return errors.New("nonce is required")
	}
	_, _ = s.db.SQL().ExecContext(ctx, `
DELETE FROM key_request_nonce_cache
WHERE tenant_id=$1 AND expires_at < CURRENT_TIMESTAMP
`, tenantID)
	res, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_request_nonce_cache (tenant_id, nonce, expires_at, created_at)
VALUES ($1,$2,$3,CURRENT_TIMESTAMP)
ON CONFLICT (tenant_id, nonce) DO NOTHING
`, tenantID, trimmedNonce, expiresAt.UTC())
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return errors.New("replay detected: nonce already used")
	}
	return nil
}

func (s *SQLStore) GetRESTClientSecurityBinding(ctx context.Context, tenantID string, clientID string) (RESTClientSecurityBinding, error) {
	var out RESTClientSecurityBinding
	err := s.db.WithTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
SELECT COALESCE(auth_mode,'api_key'),
       COALESCE(replay_protection_enabled, TRUE),
       COALESCE(http_signature_key_id,''),
       COALESCE(http_signature_public_key_pem,'')
FROM auth_client_registrations
WHERE tenant_id=$1 AND id=$2
`, tenantID, clientID).Scan(&out.AuthMode, &out.ReplayProtectionEnabled, &out.HTTPSignatureKeyID, &out.HTTPSignaturePublicKeyPEM)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return RESTClientSecurityBinding{}, errStoreNotFound
	}
	if err != nil {
		return RESTClientSecurityBinding{}, err
	}
	return out, nil
}

func (s *SQLStore) RecordRESTClientSecurityObservation(ctx context.Context, tenantID string, clientID string, observation RESTClientSecurityObservation) error {
	tenantID = strings.TrimSpace(tenantID)
	clientID = strings.TrimSpace(clientID)
	if tenantID == "" || clientID == "" {
		return errors.New("tenant_id and client_id are required")
	}
	if observation.ObservedAt.IsZero() {
		observation.ObservedAt = time.Now().UTC()
	}
	return s.withTenantTx(ctx, tenantID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
UPDATE auth_client_registrations
SET verified_request_count = verified_request_count + CASE WHEN $1 THEN 1 ELSE 0 END,
    replay_violation_count = replay_violation_count + CASE WHEN $2 THEN 1 ELSE 0 END,
    signature_failure_count = signature_failure_count + CASE WHEN $3 THEN 1 ELSE 0 END,
    unsigned_reject_count = unsigned_reject_count + CASE WHEN $4 THEN 1 ELSE 0 END,
    last_verified_request_at = CASE WHEN $1 THEN $5 ELSE last_verified_request_at END,
    last_replay_violation_at = CASE WHEN $2 THEN $5 ELSE last_replay_violation_at END,
    last_signature_failure_at = CASE WHEN $3 THEN $5 ELSE last_signature_failure_at END,
    last_unsigned_reject_at = CASE WHEN $4 THEN $5 ELSE last_unsigned_reject_at END,
    last_auth_mode_used = CASE WHEN $6 <> '' THEN $6 ELSE last_auth_mode_used END,
    last_used = CASE WHEN $1 THEN $5 ELSE last_used END
WHERE tenant_id=$7 AND id=$8
`, observation.Verified, observation.ReplayViolation, observation.SignatureFailure, observation.UnsignedBlocked, observation.ObservedAt.UTC(), strings.TrimSpace(observation.AuthMode), tenantID, clientID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errStoreNotFound
		}
		return nil
	})
}
