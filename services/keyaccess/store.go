package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	pkgdb "vecta-kms/pkg/db"
)

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore { return &SQLStore{db: db} }

func (s *SQLStore) GetSettings(ctx context.Context, tenantID string) (KeyAccessSettings, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, enabled, mode, default_action, require_justification_code, require_justification_text,
       COALESCE(approval_policy_id,''), COALESCE(updated_by,''), updated_at
FROM key_access_settings
WHERE tenant_id = $1
`, strings.TrimSpace(tenantID))
	item, err := scanSettings(row)
	if errors.Is(err, sql.ErrNoRows) {
		return KeyAccessSettings{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) UpsertSettings(ctx context.Context, item KeyAccessSettings) (KeyAccessSettings, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO key_access_settings (
  tenant_id, enabled, mode, default_action, require_justification_code, require_justification_text,
  approval_policy_id, updated_by, updated_at
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id) DO UPDATE SET
  enabled = EXCLUDED.enabled,
  mode = EXCLUDED.mode,
  default_action = EXCLUDED.default_action,
  require_justification_code = EXCLUDED.require_justification_code,
  require_justification_text = EXCLUDED.require_justification_text,
  approval_policy_id = EXCLUDED.approval_policy_id,
  updated_by = EXCLUDED.updated_by,
  updated_at = CURRENT_TIMESTAMP
RETURNING tenant_id, enabled, mode, default_action, require_justification_code, require_justification_text,
          COALESCE(approval_policy_id,''), COALESCE(updated_by,''), updated_at
`, item.TenantID, item.Enabled, item.Mode, item.DefaultAction, item.RequireJustificationCode, item.RequireJustificationText, item.ApprovalPolicyID, item.UpdatedBy)
	return scanSettings(row)
}

func (s *SQLStore) ListRules(ctx context.Context, tenantID string) ([]KeyAccessRule, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, code, label, COALESCE(description,''), action, services_json, operations_json,
       require_text, COALESCE(approval_policy_id,''), enabled, COALESCE(updated_by,''), updated_at
FROM key_access_rules
WHERE tenant_id = $1
ORDER BY code, label
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []KeyAccessRule{}
	for rows.Next() {
		item, scanErr := scanRule(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertRule(ctx context.Context, item KeyAccessRule) (KeyAccessRule, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO key_access_rules (
  id, tenant_id, code, label, description, action, services_json, operations_json,
  require_text, approval_policy_id, enabled, updated_by, updated_at
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, id) DO UPDATE SET
  code = EXCLUDED.code,
  label = EXCLUDED.label,
  description = EXCLUDED.description,
  action = EXCLUDED.action,
  services_json = EXCLUDED.services_json,
  operations_json = EXCLUDED.operations_json,
  require_text = EXCLUDED.require_text,
  approval_policy_id = EXCLUDED.approval_policy_id,
  enabled = EXCLUDED.enabled,
  updated_by = EXCLUDED.updated_by,
  updated_at = CURRENT_TIMESTAMP
RETURNING id, tenant_id, code, label, COALESCE(description,''), action, services_json, operations_json,
          require_text, COALESCE(approval_policy_id,''), enabled, COALESCE(updated_by,''), updated_at
`, item.ID, item.TenantID, item.Code, item.Label, item.Description, item.Action, mustJSON(item.Services, "[]"), mustJSON(item.Operations, "[]"), item.RequireText, item.ApprovalPolicyID, item.Enabled, item.UpdatedBy)
	return scanRule(row)
}

func (s *SQLStore) DeleteRule(ctx context.Context, tenantID string, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM key_access_rules WHERE tenant_id = $1 AND id = $2`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateDecision(ctx context.Context, item KeyAccessDecision) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_access_decisions (
  id, tenant_id, service_name, connector, operation, key_id, resource_id, target_type, request_id,
  requester_id, requester_email, requester_ip, justification_code, justification_text, decision,
  approval_required, approval_request_id, matched_rule_id, matched_code, policy_mode, reason, bypass_detected,
  metadata_json, created_at
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,$9,
  $10,$11,$12,$13,$14,$15,
  $16,$17,$18,$19,$20,$21,$22,
  $23,CURRENT_TIMESTAMP
)
`, item.ID, item.TenantID, item.Service, item.Connector, item.Operation, item.KeyID, item.ResourceID, item.TargetType, item.RequestID,
		item.RequesterID, item.RequesterEmail, item.RequesterIP, item.JustificationCode, item.JustificationText, item.Decision,
		item.ApprovalRequired, item.ApprovalRequestID, item.MatchedRuleID, item.MatchedCode, item.PolicyMode, item.Reason, item.BypassDetected,
		mustJSON(item.Metadata, "{}"))
	return err
}

func (s *SQLStore) ListDecisions(ctx context.Context, tenantID string, service string, action string, limit int) ([]KeyAccessDecision, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `
SELECT id, tenant_id, service_name, COALESCE(connector,''), operation, COALESCE(key_id,''), COALESCE(resource_id,''), COALESCE(target_type,''), COALESCE(request_id,''),
       COALESCE(requester_id,''), COALESCE(requester_email,''), COALESCE(requester_ip,''), COALESCE(justification_code,''), COALESCE(justification_text,''),
       decision, approval_required, COALESCE(approval_request_id,''), COALESCE(matched_rule_id,''), COALESCE(matched_code,''), policy_mode, COALESCE(reason,''),
       bypass_detected, metadata_json, created_at
FROM key_access_decisions
WHERE tenant_id = $1
`
	args := []interface{}{strings.TrimSpace(tenantID)}
	index := 2
	if strings.TrimSpace(service) != "" {
		query += " AND service_name = $" + strconvItoa(index)
		args = append(args, strings.ToLower(strings.TrimSpace(service)))
		index++
	}
	if strings.TrimSpace(action) != "" {
		query += " AND decision = $" + strconvItoa(index)
		args = append(args, strings.ToLower(strings.TrimSpace(action)))
		index++
	}
	query += " ORDER BY created_at DESC LIMIT $" + strconvItoa(index)
	args = append(args, limit)
	rows, err := s.db.SQL().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []KeyAccessDecision{}
	for rows.Next() {
		item, scanErr := scanDecision(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanSettings(scanner interface{ Scan(dest ...interface{}) error }) (KeyAccessSettings, error) {
	var out KeyAccessSettings
	var enabledRaw, codeRaw, textRaw interface{}
	var updatedRaw interface{}
	err := scanner.Scan(&out.TenantID, &enabledRaw, &out.Mode, &out.DefaultAction, &codeRaw, &textRaw, &out.ApprovalPolicyID, &out.UpdatedBy, &updatedRaw)
	if err != nil {
		return KeyAccessSettings{}, err
	}
	out.Enabled = boolValue(enabledRaw)
	out.RequireJustificationCode = boolValue(codeRaw)
	out.RequireJustificationText = boolValue(textRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return normalizeSettings(out), nil
}

func scanRule(scanner interface{ Scan(dest ...interface{}) error }) (KeyAccessRule, error) {
	var out KeyAccessRule
	var servicesRaw, operationsRaw string
	var requireTextRaw, enabledRaw interface{}
	var updatedRaw interface{}
	err := scanner.Scan(&out.ID, &out.TenantID, &out.Code, &out.Label, &out.Description, &out.Action, &servicesRaw, &operationsRaw, &requireTextRaw, &out.ApprovalPolicyID, &enabledRaw, &out.UpdatedBy, &updatedRaw)
	if err != nil {
		return KeyAccessRule{}, err
	}
	out.Services = parseJSONArrayString(servicesRaw)
	out.Operations = parseJSONArrayString(operationsRaw)
	out.RequireText = boolValue(requireTextRaw)
	out.Enabled = boolValue(enabledRaw)
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return normalizeRule(out), nil
}

func scanDecision(scanner interface{ Scan(dest ...interface{}) error }) (KeyAccessDecision, error) {
	var out KeyAccessDecision
	var approvalRaw, bypassRaw interface{}
	var metadataRaw string
	var createdRaw interface{}
	err := scanner.Scan(
		&out.ID, &out.TenantID, &out.Service, &out.Connector, &out.Operation, &out.KeyID, &out.ResourceID, &out.TargetType, &out.RequestID,
		&out.RequesterID, &out.RequesterEmail, &out.RequesterIP, &out.JustificationCode, &out.JustificationText,
		&out.Decision, &approvalRaw, &out.ApprovalRequestID, &out.MatchedRuleID, &out.MatchedCode, &out.PolicyMode, &out.Reason,
		&bypassRaw, &metadataRaw, &createdRaw,
	)
	if err != nil {
		return KeyAccessDecision{}, err
	}
	out.ApprovalRequired = boolValue(approvalRaw)
	out.BypassDetected = boolValue(bypassRaw)
	out.Metadata = parseJSONObjectString(metadataRaw)
	out.CreatedAt = parseTimeValue(createdRaw)
	return out, nil
}
