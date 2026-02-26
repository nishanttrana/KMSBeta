package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type TenantActivityBlocker struct {
	Code        string   `json:"code"`
	Label       string   `json:"label"`
	Count       int64    `json:"count"`
	Details     []string `json:"details,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

type TenantDeleteReadiness struct {
	TenantID                  string                  `json:"tenant_id"`
	TenantStatus              string                  `json:"tenant_status"`
	CheckedAt                 time.Time               `json:"checked_at"`
	ActiveUISessionCount      int64                   `json:"active_ui_session_count"`
	ActiveServiceLinkCount    int64                   `json:"active_service_link_count"`
	RequiresGovernanceApprove bool                    `json:"requires_governance_approval"`
	CanDisable                bool                    `json:"can_disable"`
	CanDelete                 bool                    `json:"can_delete"`
	Blockers                  []TenantActivityBlocker `json:"blockers"`
}

type tenantReadinessCheck struct {
	Code        string
	Label       string
	CountQuery  string
	DetailQuery string
	Remediation string
	IsUISession bool
}

func (s *SQLStore) GetTenantDeleteReadiness(ctx context.Context, tenantID string) (TenantDeleteReadiness, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return TenantDeleteReadiness{}, errors.New("tenant id is required")
	}
	tenant, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return TenantDeleteReadiness{}, err
	}
	readiness := TenantDeleteReadiness{
		TenantID:                  tenantID,
		TenantStatus:              normalizeTenantStatus(tenant.Status),
		CheckedAt:                 time.Now().UTC(),
		RequiresGovernanceApprove: true,
		Blockers:                  []TenantActivityBlocker{},
	}
	checks := []tenantReadinessCheck{
		{
			Code:        "ui_sessions",
			Label:       "Active UI Sessions",
			CountQuery:  `SELECT COUNT(1) FROM auth_sessions WHERE tenant_id=$1 AND expires_at > CURRENT_TIMESTAMP`,
			DetailQuery: `SELECT id FROM auth_sessions WHERE tenant_id=$1 AND expires_at > CURRENT_TIMESTAMP ORDER BY expires_at DESC LIMIT 10`,
			Remediation: "Log out active tenant users from User Management and wait for session expiry.",
			IsUISession: true,
		},
		{
			Code:        "ekm_agents",
			Label:       "Connected EKM Agents",
			CountQuery:  `SELECT COUNT(1) FROM ekm_agents WHERE tenant_id=$1 AND LOWER(COALESCE(status,'')) IN ('connected','active')`,
			DetailQuery: `SELECT id FROM ekm_agents WHERE tenant_id=$1 AND LOWER(COALESCE(status,'')) IN ('connected','active') ORDER BY updated_at DESC LIMIT 10`,
			Remediation: "Disconnect or delete EKM agents.",
		},
		{
			Code:        "bitlocker_clients",
			Label:       "Connected BitLocker Clients",
			CountQuery:  `SELECT COUNT(1) FROM ekm_bitlocker_clients WHERE tenant_id=$1 AND LOWER(COALESCE(status,'')) IN ('connected','active')`,
			DetailQuery: `SELECT id FROM ekm_bitlocker_clients WHERE tenant_id=$1 AND LOWER(COALESCE(status,'')) IN ('connected','active') ORDER BY updated_at DESC LIMIT 10`,
			Remediation: "Disconnect BitLocker clients and stop pending endpoint jobs.",
		},
		{
			Code:        "kmip_sessions",
			Label:       "Active KMIP Sessions",
			CountQuery:  `SELECT COUNT(1) FROM kmip_sessions WHERE tenant_id=$1 AND disconnected_at IS NULL`,
			DetailQuery: `SELECT id FROM kmip_sessions WHERE tenant_id=$1 AND disconnected_at IS NULL ORDER BY connected_at DESC LIMIT 10`,
			Remediation: "Close active KMIP client sessions.",
		},
		{
			Code:        "kmip_clients",
			Label:       "Active KMIP Clients",
			CountQuery:  `SELECT COUNT(1) FROM kmip_clients WHERE tenant_id=$1 AND LOWER(COALESCE(status,''))='active'`,
			DetailQuery: `SELECT id FROM kmip_clients WHERE tenant_id=$1 AND LOWER(COALESCE(status,''))='active' ORDER BY updated_at DESC LIMIT 10`,
			Remediation: "Disable KMIP clients registered for the tenant.",
		},
		{
			Code:        "mpc_ceremonies",
			Label:       "Open MPC Ceremonies",
			CountQuery:  `SELECT COUNT(1) FROM mpc_ceremonies WHERE tenant_id=$1 AND LOWER(COALESCE(status,'')) IN ('pending','open','running','in_progress','active')`,
			DetailQuery: `SELECT id FROM mpc_ceremonies WHERE tenant_id=$1 AND LOWER(COALESCE(status,'')) IN ('pending','open','running','in_progress','active') ORDER BY created_at DESC LIMIT 10`,
			Remediation: "Complete or cancel active MPC ceremonies.",
		},
		{
			Code:        "qkd_sessions",
			Label:       "Open QKD Sessions",
			CountQuery:  `SELECT COUNT(1) FROM qkd_sessions WHERE tenant_id=$1 AND LOWER(COALESCE(status,''))='open' AND closed_at IS NULL`,
			DetailQuery: `SELECT id FROM qkd_sessions WHERE tenant_id=$1 AND LOWER(COALESCE(status,''))='open' AND closed_at IS NULL ORDER BY opened_at DESC LIMIT 10`,
			Remediation: "Close open QKD sessions.",
		},
		{
			Code:        "hyok_requests",
			Label:       "Pending HYOK Requests",
			CountQuery:  `SELECT COUNT(1) FROM hyok_requests WHERE tenant_id=$1 AND LOWER(COALESCE(status,'')) IN ('pending','queued','running','in_progress')`,
			DetailQuery: `SELECT id FROM hyok_requests WHERE tenant_id=$1 AND LOWER(COALESCE(status,'')) IN ('pending','queued','running','in_progress') ORDER BY created_at DESC LIMIT 10`,
			Remediation: "Finish or cancel pending HYOK requests.",
		},
		{
			Code:        "field_encryption_leases",
			Label:       "Active Field Encryption Leases",
			CountQuery:  `SELECT COUNT(1) FROM field_encryption_leases WHERE tenant_id=$1 AND revoked=FALSE AND expires_at > CURRENT_TIMESTAMP`,
			DetailQuery: `SELECT lease_id FROM field_encryption_leases WHERE tenant_id=$1 AND revoked=FALSE AND expires_at > CURRENT_TIMESTAMP ORDER BY expires_at DESC LIMIT 10`,
			Remediation: "Revoke active wrapper leases before tenant disable.",
		},
		{
			Code:        "payment_injection_jobs",
			Label:       "Pending Payment Injection Jobs",
			CountQuery:  `SELECT COUNT(1) FROM payment_injection_jobs WHERE tenant_id=$1 AND LOWER(COALESCE(status,'')) IN ('pending','queued','running','in_progress','dispatched')`,
			DetailQuery: `SELECT id FROM payment_injection_jobs WHERE tenant_id=$1 AND LOWER(COALESCE(status,'')) IN ('pending','queued','running','in_progress','dispatched') ORDER BY created_at DESC LIMIT 10`,
			Remediation: "Wait for jobs to finish or cancel queued payment injection jobs.",
		},
		{
			Code:        "cloud_sync_jobs",
			Label:       "Running Cloud Sync Jobs",
			CountQuery:  `SELECT COUNT(1) FROM cloud_sync_jobs WHERE tenant_id=$1 AND LOWER(COALESCE(status,'')) IN ('pending','queued','running','in_progress')`,
			DetailQuery: `SELECT id FROM cloud_sync_jobs WHERE tenant_id=$1 AND LOWER(COALESCE(status,'')) IN ('pending','queued','running','in_progress') ORDER BY created_at DESC LIMIT 10`,
			Remediation: "Wait for cloud sync jobs to complete.",
		},
	}
	for _, check := range checks {
		count, countErr := s.queryTenantScopedCount(ctx, check.CountQuery, tenantID)
		if countErr != nil {
			return TenantDeleteReadiness{}, countErr
		}
		if count <= 0 {
			continue
		}
		details, detailsErr := s.queryTenantScopedDetails(ctx, check.DetailQuery, tenantID)
		if detailsErr != nil {
			return TenantDeleteReadiness{}, detailsErr
		}
		if check.IsUISession {
			readiness.ActiveUISessionCount += count
		} else {
			readiness.ActiveServiceLinkCount += count
		}
		readiness.Blockers = append(readiness.Blockers, TenantActivityBlocker{
			Code:        check.Code,
			Label:       check.Label,
			Count:       count,
			Details:     details,
			Remediation: check.Remediation,
		})
	}
	readiness.CanDisable = readiness.TenantStatus != "disabled" && len(readiness.Blockers) == 0
	readiness.CanDelete = readiness.TenantStatus == "disabled" && len(readiness.Blockers) == 0
	return readiness, nil
}

func (s *SQLStore) DisableTenant(ctx context.Context, tenantID string) (TenantDeleteReadiness, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return TenantDeleteReadiness{}, errors.New("tenant id is required")
	}
	readiness, err := s.GetTenantDeleteReadiness(ctx, tenantID)
	if err != nil {
		return TenantDeleteReadiness{}, err
	}
	if readiness.TenantStatus == "disabled" {
		readiness.CanDisable = false
		readiness.CanDelete = len(readiness.Blockers) == 0
		return readiness, nil
	}
	if len(readiness.Blockers) > 0 {
		return readiness, errors.New("tenant has active sessions or service connections")
	}
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE auth_tenants
SET status='disabled', updated_at=CURRENT_TIMESTAMP
WHERE id=$1
`, tenantID)
	if err != nil {
		return TenantDeleteReadiness{}, err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return TenantDeleteReadiness{}, errNotFound
	}
	return s.GetTenantDeleteReadiness(ctx, tenantID)
}

func (s *SQLStore) IsGovernanceRequestApproved(
	ctx context.Context,
	tenantID string,
	requestID string,
	action string,
	targetType string,
	targetID string,
) (bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	requestID = strings.TrimSpace(requestID)
	action = strings.ToLower(strings.TrimSpace(action))
	targetType = strings.ToLower(strings.TrimSpace(targetType))
	targetID = strings.TrimSpace(targetID)
	if tenantID == "" || requestID == "" || action == "" || targetType == "" || targetID == "" {
		return false, errors.New("tenant_id, request_id, action, target_type and target_id are required")
	}
	var status string
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT status
FROM approval_requests
WHERE tenant_id=$1
  AND id=$2
  AND LOWER(COALESCE(action,''))=$3
  AND LOWER(COALESCE(target_type,''))=$4
  AND target_id=$5
`, tenantID, requestID, action, targetType, targetID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return false, errNotFound
	}
	if err != nil {
		if isMissingTableOrColumn(err) {
			return false, errors.New("governance approval schema is not initialized")
		}
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(status), "approved"), nil
}

func (s *SQLStore) queryTenantScopedCount(ctx context.Context, query string, tenantID string) (int64, error) {
	var count int64
	err := s.db.SQL().QueryRowContext(ctx, query, tenantID).Scan(&count)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		if isMissingTableOrColumn(err) {
			return 0, nil
		}
		return 0, err
	}
	return count, nil
}

func (s *SQLStore) queryTenantScopedDetails(ctx context.Context, query string, tenantID string) ([]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx, query, tenantID)
	if err != nil {
		if isMissingTableOrColumn(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]string, 0, 10)
	for rows.Next() {
		var raw any
		if scanErr := rows.Scan(&raw); scanErr != nil {
			return nil, scanErr
		}
		value := strings.TrimSpace(toString(raw))
		if value != "" {
			out = append(out, value)
		}
	}
	return out, rows.Err()
}

func normalizeTenantStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "disabled":
		return "disabled"
	case "inactive":
		return "inactive"
	default:
		return "active"
	}
}

func isMissingTableOrColumn(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if msg == "" {
		return false
	}
	return strings.Contains(msg, "no such table") ||
		strings.Contains(msg, "no such column") ||
		strings.Contains(msg, "unknown column") ||
		(strings.Contains(msg, "relation") && strings.Contains(msg, "does not exist")) ||
		(strings.Contains(msg, "column") && strings.Contains(msg, "does not exist"))
}

func toString(v any) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	case []byte:
		return string(value)
	default:
		return fmt.Sprint(value)
	}
}
