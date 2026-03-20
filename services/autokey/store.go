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

func (s *SQLStore) GetSettings(ctx context.Context, tenantID string) (AutokeySettings, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, enabled, mode, require_approval, require_justification, allow_template_override,
       COALESCE(default_policy_id,''), default_rotation_days, COALESCE(updated_by,''), updated_at
FROM autokey_settings
WHERE tenant_id = $1
`, strings.TrimSpace(tenantID))
	var item AutokeySettings
	var updatedRaw interface{}
	if err := row.Scan(&item.TenantID, &item.Enabled, &item.Mode, &item.RequireApproval, &item.RequireJustification, &item.AllowTemplateOverride,
		&item.DefaultPolicyID, &item.DefaultRotationDays, &item.UpdatedBy, &updatedRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AutokeySettings{}, errNotFound
		}
		return AutokeySettings{}, err
	}
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func (s *SQLStore) UpsertSettings(ctx context.Context, item AutokeySettings) (AutokeySettings, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO autokey_settings (
  tenant_id, enabled, mode, require_approval, require_justification, allow_template_override,
  default_policy_id, default_rotation_days, updated_by, updated_at
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id) DO UPDATE SET
  enabled = EXCLUDED.enabled,
  mode = EXCLUDED.mode,
  require_approval = EXCLUDED.require_approval,
  require_justification = EXCLUDED.require_justification,
  allow_template_override = EXCLUDED.allow_template_override,
  default_policy_id = EXCLUDED.default_policy_id,
  default_rotation_days = EXCLUDED.default_rotation_days,
  updated_by = EXCLUDED.updated_by,
  updated_at = CURRENT_TIMESTAMP
RETURNING tenant_id, enabled, mode, require_approval, require_justification, allow_template_override,
          COALESCE(default_policy_id,''), default_rotation_days, COALESCE(updated_by,''), updated_at
`, item.TenantID, item.Enabled, item.Mode, item.RequireApproval, item.RequireJustification, item.AllowTemplateOverride,
		item.DefaultPolicyID, item.DefaultRotationDays, item.UpdatedBy)
	var out AutokeySettings
	var updatedRaw interface{}
	if err := row.Scan(&out.TenantID, &out.Enabled, &out.Mode, &out.RequireApproval, &out.RequireJustification, &out.AllowTemplateOverride,
		&out.DefaultPolicyID, &out.DefaultRotationDays, &out.UpdatedBy, &updatedRaw); err != nil {
		return AutokeySettings{}, err
	}
	out.UpdatedAt = parseTimeValue(updatedRaw)
	return out, nil
}

func (s *SQLStore) ListTemplates(ctx context.Context, tenantID string) ([]AutokeyTemplate, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, name, service_name, resource_type, handle_name_pattern, key_name_pattern,
       algorithm, key_type, purpose, export_allowed, iv_mode, tags_json, labels_json,
       ops_limit, COALESCE(ops_limit_window,''), approval_required, COALESCE(approval_policy_id,''),
       COALESCE(description,''), enabled, COALESCE(updated_by,''), updated_at
FROM autokey_templates
WHERE tenant_id = $1
ORDER BY service_name, resource_type, name
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []AutokeyTemplate{}
	for rows.Next() {
		item, scanErr := scanTemplate(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetTemplate(ctx context.Context, tenantID string, id string) (AutokeyTemplate, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, name, service_name, resource_type, handle_name_pattern, key_name_pattern,
       algorithm, key_type, purpose, export_allowed, iv_mode, tags_json, labels_json,
       ops_limit, COALESCE(ops_limit_window,''), approval_required, COALESCE(approval_policy_id,''),
       COALESCE(description,''), enabled, COALESCE(updated_by,''), updated_at
FROM autokey_templates
WHERE tenant_id = $1 AND id = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanTemplate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AutokeyTemplate{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) UpsertTemplate(ctx context.Context, item AutokeyTemplate) (AutokeyTemplate, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO autokey_templates (
  id, tenant_id, name, service_name, resource_type, handle_name_pattern, key_name_pattern,
  algorithm, key_type, purpose, export_allowed, iv_mode, tags_json, labels_json,
  ops_limit, ops_limit_window, approval_required, approval_policy_id, description, enabled, updated_by, updated_at
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, id) DO UPDATE SET
  name = EXCLUDED.name,
  service_name = EXCLUDED.service_name,
  resource_type = EXCLUDED.resource_type,
  handle_name_pattern = EXCLUDED.handle_name_pattern,
  key_name_pattern = EXCLUDED.key_name_pattern,
  algorithm = EXCLUDED.algorithm,
  key_type = EXCLUDED.key_type,
  purpose = EXCLUDED.purpose,
  export_allowed = EXCLUDED.export_allowed,
  iv_mode = EXCLUDED.iv_mode,
  tags_json = EXCLUDED.tags_json,
  labels_json = EXCLUDED.labels_json,
  ops_limit = EXCLUDED.ops_limit,
  ops_limit_window = EXCLUDED.ops_limit_window,
  approval_required = EXCLUDED.approval_required,
  approval_policy_id = EXCLUDED.approval_policy_id,
  description = EXCLUDED.description,
  enabled = EXCLUDED.enabled,
  updated_by = EXCLUDED.updated_by,
  updated_at = CURRENT_TIMESTAMP
RETURNING id, tenant_id, name, service_name, resource_type, handle_name_pattern, key_name_pattern,
          algorithm, key_type, purpose, export_allowed, iv_mode, tags_json, labels_json,
          ops_limit, COALESCE(ops_limit_window,''), approval_required, COALESCE(approval_policy_id,''),
          COALESCE(description,''), enabled, COALESCE(updated_by,''), updated_at
`, item.ID, item.TenantID, item.Name, item.ServiceName, item.ResourceType, item.HandleNamePattern, item.KeyNamePattern,
		item.Algorithm, item.KeyType, item.Purpose, item.ExportAllowed, item.IVMode, mustJSON(item.Tags, "[]"), mustJSON(item.Labels, "{}"),
		item.OpsLimit, item.OpsLimitWindow, item.ApprovalRequired, item.ApprovalPolicyID, item.Description, item.Enabled, item.UpdatedBy)
	return scanTemplate(row)
}

func (s *SQLStore) DeleteTemplate(ctx context.Context, tenantID string, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM autokey_templates WHERE tenant_id=$1 AND id=$2`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) ListServicePolicies(ctx context.Context, tenantID string) ([]AutokeyServicePolicy, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, service_name, COALESCE(display_name,''), COALESCE(default_template_id,''), COALESCE(algorithm,''), COALESCE(key_type,''), COALESCE(purpose,''),
       export_allowed, COALESCE(iv_mode,''), tags_json, labels_json, ops_limit, COALESCE(ops_limit_window,''),
       approval_required, COALESCE(approval_policy_id,''), enforce_policy, COALESCE(description,''), enabled, COALESCE(updated_by,''), updated_at
FROM autokey_service_policies
WHERE tenant_id = $1
ORDER BY service_name
`, strings.TrimSpace(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []AutokeyServicePolicy{}
	for rows.Next() {
		item, scanErr := scanServicePolicy(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetServicePolicy(ctx context.Context, tenantID string, serviceName string) (AutokeyServicePolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, service_name, COALESCE(display_name,''), COALESCE(default_template_id,''), COALESCE(algorithm,''), COALESCE(key_type,''), COALESCE(purpose,''),
       export_allowed, COALESCE(iv_mode,''), tags_json, labels_json, ops_limit, COALESCE(ops_limit_window,''),
       approval_required, COALESCE(approval_policy_id,''), enforce_policy, COALESCE(description,''), enabled, COALESCE(updated_by,''), updated_at
FROM autokey_service_policies
WHERE tenant_id = $1 AND service_name = $2
`, strings.TrimSpace(tenantID), strings.TrimSpace(serviceName))
	item, err := scanServicePolicy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AutokeyServicePolicy{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) UpsertServicePolicy(ctx context.Context, item AutokeyServicePolicy) (AutokeyServicePolicy, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO autokey_service_policies (
  tenant_id, service_name, display_name, default_template_id, algorithm, key_type, purpose,
  export_allowed, iv_mode, tags_json, labels_json, ops_limit, ops_limit_window, approval_required,
  approval_policy_id, enforce_policy, description, enabled, updated_by, updated_at
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, service_name) DO UPDATE SET
  display_name = EXCLUDED.display_name,
  default_template_id = EXCLUDED.default_template_id,
  algorithm = EXCLUDED.algorithm,
  key_type = EXCLUDED.key_type,
  purpose = EXCLUDED.purpose,
  export_allowed = EXCLUDED.export_allowed,
  iv_mode = EXCLUDED.iv_mode,
  tags_json = EXCLUDED.tags_json,
  labels_json = EXCLUDED.labels_json,
  ops_limit = EXCLUDED.ops_limit,
  ops_limit_window = EXCLUDED.ops_limit_window,
  approval_required = EXCLUDED.approval_required,
  approval_policy_id = EXCLUDED.approval_policy_id,
  enforce_policy = EXCLUDED.enforce_policy,
  description = EXCLUDED.description,
  enabled = EXCLUDED.enabled,
  updated_by = EXCLUDED.updated_by,
  updated_at = CURRENT_TIMESTAMP
RETURNING tenant_id, service_name, COALESCE(display_name,''), COALESCE(default_template_id,''), COALESCE(algorithm,''), COALESCE(key_type,''), COALESCE(purpose,''),
          export_allowed, COALESCE(iv_mode,''), tags_json, labels_json, ops_limit, COALESCE(ops_limit_window,''),
          approval_required, COALESCE(approval_policy_id,''), enforce_policy, COALESCE(description,''), enabled, COALESCE(updated_by,''), updated_at
`, item.TenantID, item.ServiceName, item.DisplayName, item.DefaultTemplateID, item.Algorithm, item.KeyType, item.Purpose,
		item.ExportAllowed, item.IVMode, mustJSON(item.Tags, "[]"), mustJSON(item.Labels, "{}"), item.OpsLimit, item.OpsLimitWindow,
		item.ApprovalRequired, item.ApprovalPolicyID, item.EnforcePolicy, item.Description, item.Enabled, item.UpdatedBy)
	return scanServicePolicy(row)
}

func (s *SQLStore) DeleteServicePolicy(ctx context.Context, tenantID string, serviceName string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM autokey_service_policies WHERE tenant_id=$1 AND service_name=$2`, strings.TrimSpace(tenantID), strings.TrimSpace(serviceName))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateRequest(ctx context.Context, item AutokeyRequest) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO autokey_requests (
  id, tenant_id, service_name, resource_type, resource_ref, template_id, requester_id, requester_email, requester_ip,
  justification, requested_algorithm, requested_key_type, requested_purpose, handle_name, key_name, status,
  approval_required, governance_request_id, handle_id, key_id, policy_matched, policy_mismatch_reason,
  resolved_spec_json, failure_reason, created_at, updated_at, fulfilled_at
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,$25
)
`, item.ID, item.TenantID, item.ServiceName, item.ResourceType, item.ResourceRef, item.TemplateID, item.RequesterID, item.RequesterEmail, item.RequesterIP,
		item.Justification, item.RequestedAlgorithm, item.RequestedKeyType, item.RequestedPurpose, item.HandleName, item.KeyName, item.Status,
		item.ApprovalRequired, item.GovernanceRequestID, item.HandleID, item.KeyID, item.PolicyMatched, item.PolicyMismatchReason,
		mustJSON(item.ResolvedSpec, "{}"), item.FailureReason, nullableTime(item.FulfilledAt))
	return err
}

func (s *SQLStore) UpdateRequest(ctx context.Context, item AutokeyRequest) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE autokey_requests
SET status=$3, governance_request_id=$4, handle_id=$5, key_id=$6, policy_matched=$7, policy_mismatch_reason=$8,
    resolved_spec_json=$9, failure_reason=$10, updated_at=CURRENT_TIMESTAMP, fulfilled_at=$11
WHERE tenant_id=$1 AND id=$2
`, item.TenantID, item.ID, item.Status, item.GovernanceRequestID, item.HandleID, item.KeyID, item.PolicyMatched, item.PolicyMismatchReason,
		mustJSON(item.ResolvedSpec, "{}"), item.FailureReason, nullableTime(item.FulfilledAt))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) GetRequest(ctx context.Context, tenantID string, id string) (AutokeyRequest, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, service_name, resource_type, resource_ref, COALESCE(template_id,''), COALESCE(requester_id,''), COALESCE(requester_email,''), COALESCE(requester_ip,''),
       COALESCE(justification,''), COALESCE(requested_algorithm,''), COALESCE(requested_key_type,''), COALESCE(requested_purpose,''), COALESCE(handle_name,''), COALESCE(key_name,''),
       status, approval_required, COALESCE(governance_request_id,''), COALESCE(handle_id,''), COALESCE(key_id,''), policy_matched, COALESCE(policy_mismatch_reason,''),
       resolved_spec_json, COALESCE(failure_reason,''), created_at, updated_at, fulfilled_at
FROM autokey_requests
WHERE tenant_id=$1 AND id=$2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanRequest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AutokeyRequest{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListRequests(ctx context.Context, tenantID string, status string, limit int) ([]AutokeyRequest, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	base := `
SELECT id, tenant_id, service_name, resource_type, resource_ref, COALESCE(template_id,''), COALESCE(requester_id,''), COALESCE(requester_email,''), COALESCE(requester_ip,''),
       COALESCE(justification,''), COALESCE(requested_algorithm,''), COALESCE(requested_key_type,''), COALESCE(requested_purpose,''), COALESCE(handle_name,''), COALESCE(key_name,''),
       status, approval_required, COALESCE(governance_request_id,''), COALESCE(handle_id,''), COALESCE(key_id,''), policy_matched, COALESCE(policy_mismatch_reason,''),
       resolved_spec_json, COALESCE(failure_reason,''), created_at, updated_at, fulfilled_at
FROM autokey_requests
WHERE tenant_id=$1`
	args := []interface{}{strings.TrimSpace(tenantID)}
	if strings.TrimSpace(status) != "" {
		base += ` AND status = $2`
		args = append(args, strings.TrimSpace(status))
		base += ` ORDER BY created_at DESC LIMIT $3`
		args = append(args, limit)
	} else {
		base += ` ORDER BY created_at DESC LIMIT $2`
		args = append(args, limit)
	}
	rows, err := s.db.SQL().QueryContext(ctx, base, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []AutokeyRequest{}
	for rows.Next() {
		item, scanErr := scanRequest(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetHandleByBinding(ctx context.Context, tenantID string, serviceName string, resourceType string, resourceRef string) (AutokeyHandle, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, service_name, resource_type, resource_ref, handle_name, key_id, COALESCE(template_id,''), COALESCE(request_id,''),
       status, managed, policy_matched, spec_json, created_at, updated_at
FROM autokey_handles
WHERE tenant_id=$1 AND service_name=$2 AND resource_type=$3 AND resource_ref=$4
`, strings.TrimSpace(tenantID), strings.TrimSpace(serviceName), strings.TrimSpace(resourceType), strings.TrimSpace(resourceRef))
	item, err := scanHandle(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AutokeyHandle{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) GetHandle(ctx context.Context, tenantID string, id string) (AutokeyHandle, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, service_name, resource_type, resource_ref, handle_name, key_id, COALESCE(template_id,''), COALESCE(request_id,''),
       status, managed, policy_matched, spec_json, created_at, updated_at
FROM autokey_handles
WHERE tenant_id=$1 AND id=$2
`, strings.TrimSpace(tenantID), strings.TrimSpace(id))
	item, err := scanHandle(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AutokeyHandle{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListHandles(ctx context.Context, tenantID string, serviceName string, limit int) ([]AutokeyHandle, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	base := `
SELECT id, tenant_id, service_name, resource_type, resource_ref, handle_name, key_id, COALESCE(template_id,''), COALESCE(request_id,''),
       status, managed, policy_matched, spec_json, created_at, updated_at
FROM autokey_handles
WHERE tenant_id=$1`
	args := []interface{}{strings.TrimSpace(tenantID)}
	if strings.TrimSpace(serviceName) != "" {
		base += ` AND service_name=$2 ORDER BY created_at DESC LIMIT $3`
		args = append(args, strings.TrimSpace(serviceName), limit)
	} else {
		base += ` ORDER BY created_at DESC LIMIT $2`
		args = append(args, limit)
	}
	rows, err := s.db.SQL().QueryContext(ctx, base, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []AutokeyHandle{}
	for rows.Next() {
		item, scanErr := scanHandle(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertHandle(ctx context.Context, item AutokeyHandle) (AutokeyHandle, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
INSERT INTO autokey_handles (
  id, tenant_id, service_name, resource_type, resource_ref, handle_name, key_id, template_id, request_id,
  status, managed, policy_matched, spec_json, created_at, updated_at
) VALUES (
  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, service_name, resource_type, resource_ref) DO UPDATE SET
  handle_name = EXCLUDED.handle_name,
  key_id = EXCLUDED.key_id,
  template_id = EXCLUDED.template_id,
  request_id = EXCLUDED.request_id,
  status = EXCLUDED.status,
  managed = EXCLUDED.managed,
  policy_matched = EXCLUDED.policy_matched,
  spec_json = EXCLUDED.spec_json,
  updated_at = CURRENT_TIMESTAMP
RETURNING id, tenant_id, service_name, resource_type, resource_ref, handle_name, key_id, COALESCE(template_id,''), COALESCE(request_id,''),
          status, managed, policy_matched, spec_json, created_at, updated_at
`, item.ID, item.TenantID, item.ServiceName, item.ResourceType, item.ResourceRef, item.HandleName, item.KeyID, item.TemplateID, item.RequestID,
		item.Status, item.Managed, item.PolicyMatched, mustJSON(item.Spec, "{}"))
	return scanHandle(row)
}

func scanTemplate(scanner interface {
	Scan(dest ...interface{}) error
}) (AutokeyTemplate, error) {
	var item AutokeyTemplate
	var tagsJSON, labelsJSON string
	var updatedRaw interface{}
	err := scanner.Scan(&item.ID, &item.TenantID, &item.Name, &item.ServiceName, &item.ResourceType, &item.HandleNamePattern, &item.KeyNamePattern,
		&item.Algorithm, &item.KeyType, &item.Purpose, &item.ExportAllowed, &item.IVMode, &tagsJSON, &labelsJSON,
		&item.OpsLimit, &item.OpsLimitWindow, &item.ApprovalRequired, &item.ApprovalPolicyID,
		&item.Description, &item.Enabled, &item.UpdatedBy, &updatedRaw)
	if err != nil {
		return AutokeyTemplate{}, err
	}
	item.Tags = parseJSONArrayString(tagsJSON)
	item.Labels = parseJSONObjectString(labelsJSON)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func scanServicePolicy(scanner interface {
	Scan(dest ...interface{}) error
}) (AutokeyServicePolicy, error) {
	var item AutokeyServicePolicy
	var tagsJSON, labelsJSON string
	var updatedRaw interface{}
	err := scanner.Scan(&item.TenantID, &item.ServiceName, &item.DisplayName, &item.DefaultTemplateID, &item.Algorithm, &item.KeyType, &item.Purpose,
		&item.ExportAllowed, &item.IVMode, &tagsJSON, &labelsJSON, &item.OpsLimit, &item.OpsLimitWindow,
		&item.ApprovalRequired, &item.ApprovalPolicyID, &item.EnforcePolicy, &item.Description, &item.Enabled, &item.UpdatedBy, &updatedRaw)
	if err != nil {
		return AutokeyServicePolicy{}, err
	}
	item.Tags = parseJSONArrayString(tagsJSON)
	item.Labels = parseJSONObjectString(labelsJSON)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func scanRequest(scanner interface {
	Scan(dest ...interface{}) error
}) (AutokeyRequest, error) {
	var item AutokeyRequest
	var specJSON string
	var createdRaw, updatedRaw, fulfilledRaw interface{}
	err := scanner.Scan(&item.ID, &item.TenantID, &item.ServiceName, &item.ResourceType, &item.ResourceRef, &item.TemplateID, &item.RequesterID, &item.RequesterEmail, &item.RequesterIP,
		&item.Justification, &item.RequestedAlgorithm, &item.RequestedKeyType, &item.RequestedPurpose, &item.HandleName, &item.KeyName,
		&item.Status, &item.ApprovalRequired, &item.GovernanceRequestID, &item.HandleID, &item.KeyID, &item.PolicyMatched, &item.PolicyMismatchReason,
		&specJSON, &item.FailureReason, &createdRaw, &updatedRaw, &fulfilledRaw)
	if err != nil {
		return AutokeyRequest{}, err
	}
	item.ResolvedSpec = parseSpec(specJSON)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	item.FulfilledAt = parseTimeValue(fulfilledRaw)
	return item, nil
}

func scanHandle(scanner interface {
	Scan(dest ...interface{}) error
}) (AutokeyHandle, error) {
	var item AutokeyHandle
	var specJSON string
	var createdRaw, updatedRaw interface{}
	err := scanner.Scan(&item.ID, &item.TenantID, &item.ServiceName, &item.ResourceType, &item.ResourceRef, &item.HandleName, &item.KeyID, &item.TemplateID, &item.RequestID,
		&item.Status, &item.Managed, &item.PolicyMatched, &specJSON, &createdRaw, &updatedRaw)
	if err != nil {
		return AutokeyHandle{}, err
	}
	item.Spec = parseSpec(specJSON)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}
