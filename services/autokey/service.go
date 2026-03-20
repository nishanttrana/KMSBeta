package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Service struct {
	store      Store
	keycore    KeyCoreClient
	governance GovernanceClient
	events     EventPublisher
	now        func() time.Time
}

func NewService(store Store, keycore KeyCoreClient, governance GovernanceClient, events EventPublisher) *Service {
	return &Service{
		store:      store,
		keycore:    keycore,
		governance: governance,
		events:     events,
		now:        nowUTC,
	}
}

func (s *Service) ensureSettings(ctx context.Context, tenantID string) (AutokeySettings, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return AutokeySettings{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	item, err := s.store.GetSettings(ctx, tenantID)
	if err == nil {
		return normalizeSettings(item), nil
	}
	if !errorsIsNotFound(err) {
		return AutokeySettings{}, err
	}
	return s.store.UpsertSettings(ctx, defaultSettings(tenantID))
}

func (s *Service) GetSettings(ctx context.Context, tenantID string) (AutokeySettings, error) {
	item, err := s.ensureSettings(ctx, tenantID)
	if err != nil {
		return AutokeySettings{}, err
	}
	_ = publishAudit(ctx, s.events, "audit.autokey.settings_viewed", item.TenantID, map[string]interface{}{
		"enabled": item.Enabled,
		"mode":    item.Mode,
	})
	return item, nil
}

func (s *Service) UpdateSettings(ctx context.Context, in AutokeySettings) (AutokeySettings, error) {
	item := normalizeSettings(in)
	if item.TenantID == "" {
		return AutokeySettings{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	saved, err := s.store.UpsertSettings(ctx, item)
	if err != nil {
		return AutokeySettings{}, err
	}
	_ = publishAudit(ctx, s.events, "audit.autokey.settings_updated", saved.TenantID, map[string]interface{}{
		"enabled":                 saved.Enabled,
		"mode":                    saved.Mode,
		"require_approval":        saved.RequireApproval,
		"allow_template_override": saved.AllowTemplateOverride,
		"default_policy_id":       saved.DefaultPolicyID,
	})
	return saved, nil
}

func (s *Service) ListTemplates(ctx context.Context, tenantID string) ([]AutokeyTemplate, error) {
	if _, err := s.ensureSettings(ctx, tenantID); err != nil {
		return nil, err
	}
	items, err := s.store.ListTemplates(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	_ = publishAudit(ctx, s.events, "audit.autokey.templates_viewed", tenantID, map[string]interface{}{"count": len(items)})
	return items, nil
}

func (s *Service) UpsertTemplate(ctx context.Context, in AutokeyTemplate) (AutokeyTemplate, error) {
	if _, err := s.ensureSettings(ctx, in.TenantID); err != nil {
		return AutokeyTemplate{}, err
	}
	item := normalizeTemplate(in)
	if item.TenantID == "" || item.ServiceName == "" || item.ResourceType == "" {
		return AutokeyTemplate{}, newServiceError(400, "bad_request", "tenant_id, service_name, and resource_type are required")
	}
	saved, err := s.store.UpsertTemplate(ctx, item)
	if err != nil {
		return AutokeyTemplate{}, err
	}
	_ = publishAudit(ctx, s.events, "audit.autokey.template_upserted", saved.TenantID, map[string]interface{}{
		"template_id":       saved.ID,
		"service_name":      saved.ServiceName,
		"resource_type":     saved.ResourceType,
		"algorithm":         saved.Algorithm,
		"approval_required": saved.ApprovalRequired,
	})
	return saved, nil
}

func (s *Service) DeleteTemplate(ctx context.Context, tenantID string, id string) error {
	if err := s.store.DeleteTemplate(ctx, tenantID, id); err != nil {
		return err
	}
	_ = publishAudit(ctx, s.events, "audit.autokey.template_deleted", tenantID, map[string]interface{}{"template_id": id})
	return nil
}

func (s *Service) ListServicePolicies(ctx context.Context, tenantID string) ([]AutokeyServicePolicy, error) {
	if _, err := s.ensureSettings(ctx, tenantID); err != nil {
		return nil, err
	}
	items, err := s.store.ListServicePolicies(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	_ = publishAudit(ctx, s.events, "audit.autokey.service_policies_viewed", tenantID, map[string]interface{}{"count": len(items)})
	return items, nil
}

func (s *Service) UpsertServicePolicy(ctx context.Context, in AutokeyServicePolicy) (AutokeyServicePolicy, error) {
	if _, err := s.ensureSettings(ctx, in.TenantID); err != nil {
		return AutokeyServicePolicy{}, err
	}
	item := normalizeServicePolicy(in)
	if item.TenantID == "" || item.ServiceName == "" {
		return AutokeyServicePolicy{}, newServiceError(400, "bad_request", "tenant_id and service_name are required")
	}
	saved, err := s.store.UpsertServicePolicy(ctx, item)
	if err != nil {
		return AutokeyServicePolicy{}, err
	}
	_ = publishAudit(ctx, s.events, "audit.autokey.service_policy_upserted", saved.TenantID, map[string]interface{}{
		"service_name":        saved.ServiceName,
		"default_template_id": saved.DefaultTemplateID,
		"approval_required":   saved.ApprovalRequired,
		"enforce_policy":      saved.EnforcePolicy,
	})
	return saved, nil
}

func (s *Service) DeleteServicePolicy(ctx context.Context, tenantID string, serviceName string) error {
	if err := s.store.DeleteServicePolicy(ctx, tenantID, serviceName); err != nil {
		return err
	}
	_ = publishAudit(ctx, s.events, "audit.autokey.service_policy_deleted", tenantID, map[string]interface{}{"service_name": serviceName})
	return nil
}

func (s *Service) GetSummary(ctx context.Context, tenantID string) (AutokeySummary, error) {
	if err := s.reconcilePendingRequests(ctx, tenantID, 100); err != nil {
		return AutokeySummary{}, err
	}
	settings, err := s.ensureSettings(ctx, tenantID)
	if err != nil {
		return AutokeySummary{}, err
	}
	templates, _ := s.store.ListTemplates(ctx, tenantID)
	policies, _ := s.store.ListServicePolicies(ctx, tenantID)
	requests, _ := s.store.ListRequests(ctx, tenantID, "", 500)
	handles, _ := s.store.ListHandles(ctx, tenantID, "", 500)
	summary := AutokeySummary{
		TenantID:           tenantID,
		Enabled:            settings.Enabled,
		Mode:               settings.Mode,
		TemplateCount:      len(templates),
		ServicePolicyCount: len(policies),
		HandleCount:        len(handles),
		Services:           []AutokeyServiceSummary{},
	}
	serviceMap := map[string]*AutokeyServiceSummary{}
	cutoff := s.now().Add(-24 * time.Hour)
	for _, handle := range handles {
		item := ensureServiceSummary(serviceMap, handle.ServiceName)
		item.HandleCount++
	}
	for _, req := range requests {
		item := ensureServiceSummary(serviceMap, req.ServiceName)
		switch strings.ToLower(strings.TrimSpace(req.Status)) {
		case "pending_approval":
			item.PendingApprovals++
			summary.PendingApprovals++
		case "provisioned":
			if req.FulfilledAt.After(cutoff) {
				item.Provisioned24h++
				summary.Provisioned24h++
			}
		case "denied":
			summary.DeniedCount++
		case "failed":
			summary.FailedCount++
		}
		if req.PolicyMatched {
			summary.PolicyMatchedCount++
		} else if req.Status != "" {
			item.PolicyMismatchCount++
			summary.PolicyMismatchCount++
		}
	}
	for _, item := range serviceMap {
		summary.Services = append(summary.Services, *item)
	}
	sort.Slice(summary.Services, func(i, j int) bool {
		return summary.Services[i].ServiceName < summary.Services[j].ServiceName
	})
	_ = publishAudit(ctx, s.events, "audit.autokey.summary_viewed", tenantID, map[string]interface{}{
		"handle_count":      summary.HandleCount,
		"pending_approvals": summary.PendingApprovals,
		"policy_mismatches": summary.PolicyMismatchCount,
	})
	return summary, nil
}

func ensureServiceSummary(m map[string]*AutokeyServiceSummary, serviceName string) *AutokeyServiceSummary {
	key := normalizeServiceName(serviceName)
	if key == "" {
		key = "unknown"
	}
	if item, ok := m[key]; ok {
		return item
	}
	item := &AutokeyServiceSummary{ServiceName: key}
	m[key] = item
	return item
}

func (s *Service) ListRequests(ctx context.Context, tenantID string, status string, limit int) ([]AutokeyRequest, error) {
	if err := s.reconcilePendingRequests(ctx, tenantID, 100); err != nil {
		return nil, err
	}
	items, err := s.store.ListRequests(ctx, tenantID, status, limit)
	if err != nil {
		return nil, err
	}
	_ = publishAudit(ctx, s.events, "audit.autokey.requests_viewed", tenantID, map[string]interface{}{
		"count":  len(items),
		"status": status,
	})
	return items, nil
}

func (s *Service) GetRequest(ctx context.Context, tenantID string, id string) (AutokeyRequest, error) {
	if err := s.reconcilePendingRequests(ctx, tenantID, 100); err != nil {
		return AutokeyRequest{}, err
	}
	return s.store.GetRequest(ctx, tenantID, id)
}

func (s *Service) ListHandles(ctx context.Context, tenantID string, serviceName string, limit int) ([]AutokeyHandle, error) {
	if err := s.reconcilePendingRequests(ctx, tenantID, 100); err != nil {
		return nil, err
	}
	items, err := s.store.ListHandles(ctx, tenantID, serviceName, limit)
	if err != nil {
		return nil, err
	}
	_ = publishAudit(ctx, s.events, "audit.autokey.handles_viewed", tenantID, map[string]interface{}{
		"count":        len(items),
		"service_name": normalizeServiceName(serviceName),
	})
	return items, nil
}

func (s *Service) CreateRequest(ctx context.Context, in CreateAutokeyRequestInput) (AutokeyRequest, error) {
	input := normalizeRequestInput(in)
	settings, err := s.ensureSettings(ctx, input.TenantID)
	if err != nil {
		return AutokeyRequest{}, err
	}
	if !settings.Enabled {
		return AutokeyRequest{}, newServiceError(409, "autokey_disabled", "autokey is disabled for this tenant")
	}
	if input.ServiceName == "" || input.ResourceType == "" || input.ResourceRef == "" {
		return AutokeyRequest{}, newServiceError(400, "bad_request", "service_name, resource_type, and resource_ref are required")
	}
	if settings.RequireJustification && input.Justification == "" {
		return AutokeyRequest{}, newServiceError(400, "bad_request", "justification is required by autokey policy")
	}

	if existing, getErr := s.store.GetHandleByBinding(ctx, input.TenantID, input.ServiceName, input.ResourceType, input.ResourceRef); getErr == nil {
		item := AutokeyRequest{
			ID:             newID("akr"),
			TenantID:       input.TenantID,
			ServiceName:    input.ServiceName,
			ResourceType:   input.ResourceType,
			ResourceRef:    input.ResourceRef,
			RequesterID:    input.RequesterID,
			RequesterEmail: input.RequesterEmail,
			RequesterIP:    input.RequesterIP,
			Justification:  input.Justification,
			HandleName:     existing.HandleName,
			Status:         "provisioned",
			HandleID:       existing.ID,
			KeyID:          existing.KeyID,
			PolicyMatched:  existing.PolicyMatched,
			FulfilledAt:    s.now(),
		}
		if err := s.store.CreateRequest(ctx, item); err != nil {
			return AutokeyRequest{}, err
		}
		_ = publishAudit(ctx, s.events, "audit.autokey.request_reused", input.TenantID, map[string]interface{}{
			"request_id":    item.ID,
			"handle_id":     existing.ID,
			"service_name":  input.ServiceName,
			"resource_type": input.ResourceType,
			"resource_ref":  input.ResourceRef,
		})
		return s.store.GetRequest(ctx, input.TenantID, item.ID)
	}

	resolved, resolveErr := s.resolveProvisionSpec(ctx, settings, input)
	if resolveErr != nil {
		return AutokeyRequest{}, resolveErr
	}

	request := AutokeyRequest{
		ID:                   newID("akr"),
		TenantID:             input.TenantID,
		ServiceName:          input.ServiceName,
		ResourceType:         input.ResourceType,
		ResourceRef:          input.ResourceRef,
		TemplateID:           resolved.Template.ID,
		RequesterID:          input.RequesterID,
		RequesterEmail:       input.RequesterEmail,
		RequesterIP:          input.RequesterIP,
		Justification:        input.Justification,
		RequestedAlgorithm:   input.RequestedAlgorithm,
		RequestedKeyType:     input.RequestedKeyType,
		RequestedPurpose:     input.RequestedPurpose,
		HandleName:           resolved.HandleName,
		KeyName:              resolved.KeyName,
		Status:               "pending",
		ApprovalRequired:     resolved.ApprovalRequired,
		PolicyMatched:        resolved.PolicyMatched,
		PolicyMismatchReason: resolved.PolicyMismatchReason,
		ResolvedSpec:         resolved.Spec,
	}

	if !resolved.PolicyMatched && settings.Mode == "enforce" {
		request.Status = "denied"
		request.FailureReason = resolved.PolicyMismatchReason
		if err := s.store.CreateRequest(ctx, request); err != nil {
			return AutokeyRequest{}, err
		}
		_ = publishAudit(ctx, s.events, "audit.autokey.request_created", request.TenantID, map[string]interface{}{
			"request_id":      request.ID,
			"service_name":    request.ServiceName,
			"resource_type":   request.ResourceType,
			"resource_ref":    request.ResourceRef,
			"requested_by":    request.RequesterID,
			"approval_needed": request.ApprovalRequired,
			"policy_matched":  request.PolicyMatched,
		})
		_ = publishAudit(ctx, s.events, "audit.autokey.request_denied", request.TenantID, map[string]interface{}{
			"request_id":             request.ID,
			"service_name":           request.ServiceName,
			"resource_type":          request.ResourceType,
			"resource_ref":           request.ResourceRef,
			"policy_mismatch_reason": request.PolicyMismatchReason,
			"requested_by":           request.RequesterID,
		})
		return s.store.GetRequest(ctx, request.TenantID, request.ID)
	}

	if request.ApprovalRequired {
		if s.governance == nil {
			return AutokeyRequest{}, newServiceError(424, "governance_unavailable", "autokey approval is required but governance is not configured")
		}
		approval, createErr := s.governance.CreateApprovalRequest(ctx, GovernanceCreateApprovalRequest{
			TenantID:       request.TenantID,
			PolicyID:       firstNonEmpty(resolved.Policy.ApprovalPolicyID, resolved.Template.ApprovalPolicyID, settings.DefaultPolicyID),
			Action:         "autokey.provision",
			TargetType:     "autokey_handle",
			TargetID:       request.HandleName,
			TargetDetails:  resolved.Spec,
			RequesterID:    request.RequesterID,
			RequesterEmail: request.RequesterEmail,
			RequesterIP:    request.RequesterIP,
		})
		if createErr != nil {
			return AutokeyRequest{}, createErr
		}
		request.Status = "pending_approval"
		request.GovernanceRequestID = approval.ID
		if err := s.store.CreateRequest(ctx, request); err != nil {
			return AutokeyRequest{}, err
		}
		_ = publishAudit(ctx, s.events, "audit.autokey.request_created", request.TenantID, map[string]interface{}{
			"request_id":      request.ID,
			"service_name":    request.ServiceName,
			"resource_type":   request.ResourceType,
			"resource_ref":    request.ResourceRef,
			"requested_by":    request.RequesterID,
			"approval_needed": request.ApprovalRequired,
			"policy_matched":  request.PolicyMatched,
		})
		_ = publishAudit(ctx, s.events, "audit.autokey.request_pending_approval", request.TenantID, map[string]interface{}{
			"request_id":            request.ID,
			"governance_request_id": approval.ID,
			"service_name":          request.ServiceName,
			"resource_type":         request.ResourceType,
			"resource_ref":          request.ResourceRef,
		})
		return s.store.GetRequest(ctx, request.TenantID, request.ID)
	}

	if err := s.store.CreateRequest(ctx, request); err != nil {
		return AutokeyRequest{}, err
	}
	_ = publishAudit(ctx, s.events, "audit.autokey.request_created", request.TenantID, map[string]interface{}{
		"request_id":      request.ID,
		"service_name":    request.ServiceName,
		"resource_type":   request.ResourceType,
		"resource_ref":    request.ResourceRef,
		"requested_by":    request.RequesterID,
		"approval_needed": request.ApprovalRequired,
		"policy_matched":  request.PolicyMatched,
	})
	provisioned, provErr := s.provisionRequest(ctx, request)
	if provErr != nil {
		request.Status = "failed"
		request.FailureReason = provErr.Error()
		request.UpdatedAt = s.now()
		_ = s.store.UpdateRequest(ctx, request)
		_ = publishAudit(ctx, s.events, "audit.autokey.request_failed", request.TenantID, map[string]interface{}{
			"request_id":     request.ID,
			"service_name":   request.ServiceName,
			"resource_type":  request.ResourceType,
			"resource_ref":   request.ResourceRef,
			"failure_reason": provErr.Error(),
		})
		return s.store.GetRequest(ctx, request.TenantID, request.ID)
	}
	return provisioned, nil
}

type resolvedProvisionSpec struct {
	Template             AutokeyTemplate
	Policy               AutokeyServicePolicy
	HandleName           string
	KeyName              string
	ApprovalRequired     bool
	PolicyMatched        bool
	PolicyMismatchReason string
	Spec                 map[string]interface{}
	KeyCreate            KeyCoreCreateKeyRequest
}

func (s *Service) resolveProvisionSpec(ctx context.Context, settings AutokeySettings, input CreateAutokeyRequestInput) (resolvedProvisionSpec, error) {
	policy, _ := s.store.GetServicePolicy(ctx, input.TenantID, input.ServiceName)
	if !policy.Enabled && policy.ServiceName != "" {
		return resolvedProvisionSpec{}, newServiceError(409, "service_disabled", "autokey service policy is disabled for this service")
	}

	template, err := s.selectTemplate(ctx, input.TenantID, input, settings, policy)
	if err != nil {
		return resolvedProvisionSpec{}, err
	}
	handleName := firstNonEmpty(input.HandleName, renderPattern(template.HandleNamePattern, input.TenantID, input.ServiceName, input.ResourceType, input.ResourceRef))
	if handleName == "" {
		handleName = fmt.Sprintf("%s/%s/%s", input.ServiceName, input.ResourceType, slugify(input.ResourceRef))
	}
	keyName := firstNonEmpty(input.KeyName, renderPattern(template.KeyNamePattern, input.TenantID, input.ServiceName, input.ResourceType, input.ResourceRef))
	if keyName == "" {
		keyName = fmt.Sprintf("ak-%s-%s", input.ServiceName, slugify(input.ResourceRef))
	}

	algorithm := firstNonEmpty(policy.Algorithm, template.Algorithm)
	keyType := firstNonEmpty(policy.KeyType, template.KeyType)
	purpose := firstNonEmpty(policy.Purpose, template.Purpose)
	ivMode := firstNonEmpty(policy.IVMode, template.IVMode)
	opsLimit := template.OpsLimit
	if policy.OpsLimit > 0 {
		opsLimit = policy.OpsLimit
	}
	opsWindow := firstNonEmpty(policy.OpsLimitWindow, template.OpsLimitWindow)
	tags := uniqueStrings(append(append([]string{}, template.Tags...), policy.Tags...))
	tags = uniqueStrings(append(tags, input.Tags...))
	labels := map[string]string{}
	for key, value := range template.Labels {
		labels[key] = value
	}
	for key, value := range policy.Labels {
		labels[key] = value
	}
	for key, value := range input.Labels {
		labels[key] = value
	}
	labels["autokey_managed"] = "true"
	labels["autokey_service"] = input.ServiceName
	labels["autokey_resource_type"] = input.ResourceType
	labels["autokey_resource_ref"] = input.ResourceRef
	labels["autokey_handle_name"] = handleName

	policyMatched := true
	mismatchReason := ""
	if policy.EnforcePolicy {
		if input.RequestedAlgorithm != "" && !strings.EqualFold(input.RequestedAlgorithm, algorithm) {
			policyMatched = false
			mismatchReason = "requested algorithm does not match central autokey policy"
		}
		if policyMatched && input.RequestedKeyType != "" && !strings.EqualFold(input.RequestedKeyType, keyType) {
			policyMatched = false
			mismatchReason = "requested key type does not match central autokey policy"
		}
		if policyMatched && input.RequestedPurpose != "" && !strings.EqualFold(input.RequestedPurpose, purpose) {
			policyMatched = false
			mismatchReason = "requested purpose does not match central autokey policy"
		}
	}

	approvalRequired := settings.RequireApproval || template.ApprovalRequired || policy.ApprovalRequired
	spec := map[string]interface{}{
		"service_name":           input.ServiceName,
		"resource_type":          input.ResourceType,
		"resource_ref":           input.ResourceRef,
		"template_id":            template.ID,
		"service_policy":         policy.ServiceName,
		"handle_name":            handleName,
		"key_name":               keyName,
		"algorithm":              algorithm,
		"key_type":               keyType,
		"purpose":                purpose,
		"iv_mode":                ivMode,
		"export_allowed":         policy.ExportAllowed || template.ExportAllowed,
		"ops_limit":              opsLimit,
		"ops_limit_window":       opsWindow,
		"approval_required":      approvalRequired,
		"approval_policy_id":     firstNonEmpty(policy.ApprovalPolicyID, template.ApprovalPolicyID, settings.DefaultPolicyID),
		"policy_matched":         policyMatched,
		"policy_mismatch_reason": mismatchReason,
		"tags":                   tags,
		"labels":                 labels,
	}
	return resolvedProvisionSpec{
		Template:             template,
		Policy:               policy,
		HandleName:           handleName,
		KeyName:              keyName,
		ApprovalRequired:     approvalRequired,
		PolicyMatched:        policyMatched,
		PolicyMismatchReason: mismatchReason,
		Spec:                 spec,
		KeyCreate: KeyCoreCreateKeyRequest{
			TenantID:       input.TenantID,
			Name:           keyName,
			Algorithm:      algorithm,
			KeyType:        keyType,
			Purpose:        purpose,
			Tags:           tags,
			Labels:         labels,
			ExportAllowed:  policy.ExportAllowed || template.ExportAllowed,
			ActivationMode: "immediate",
			IVMode:         ivMode,
			CreatedBy:      firstNonEmpty(input.RequesterID, input.RequesterEmail, "autokey"),
			OpsLimit:       opsLimit,
			OpsLimitWindow: opsWindow,
		},
	}, nil
}

func (s *Service) selectTemplate(ctx context.Context, tenantID string, input CreateAutokeyRequestInput, settings AutokeySettings, policy AutokeyServicePolicy) (AutokeyTemplate, error) {
	if input.TemplateID != "" {
		if !settings.AllowTemplateOverride && input.TemplateID != policy.DefaultTemplateID && policy.DefaultTemplateID != "" {
			return AutokeyTemplate{}, newServiceError(403, "template_override_blocked", "autokey template overrides are disabled for this tenant")
		}
		return s.store.GetTemplate(ctx, tenantID, input.TemplateID)
	}
	if policy.DefaultTemplateID != "" {
		return s.store.GetTemplate(ctx, tenantID, policy.DefaultTemplateID)
	}
	templates, err := s.store.ListTemplates(ctx, tenantID)
	if err != nil {
		return AutokeyTemplate{}, err
	}
	for _, item := range templates {
		if !item.Enabled {
			continue
		}
		if item.ServiceName == input.ServiceName && item.ResourceType == input.ResourceType {
			return item, nil
		}
	}
	for _, item := range templates {
		if !item.Enabled {
			continue
		}
		if item.ServiceName == input.ServiceName {
			return item, nil
		}
	}
	return AutokeyTemplate{}, newServiceError(404, "template_not_found", "no autokey template matches the requested service/resource")
}

func (s *Service) reconcilePendingRequests(ctx context.Context, tenantID string, limit int) error {
	if s.governance == nil {
		return nil
	}
	items, err := s.store.ListRequests(ctx, tenantID, "pending_approval", limit)
	if err != nil {
		return err
	}
	for _, item := range items {
		if strings.TrimSpace(item.GovernanceRequestID) == "" {
			continue
		}
		govReq, getErr := s.governance.GetApprovalRequest(ctx, tenantID, item.GovernanceRequestID)
		if getErr != nil {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(govReq.Status))
		switch status {
		case "approved":
			if _, provErr := s.provisionRequest(ctx, item); provErr != nil {
				item.Status = "failed"
				item.FailureReason = provErr.Error()
				_ = s.store.UpdateRequest(ctx, item)
				_ = publishAudit(ctx, s.events, "audit.autokey.request_failed", item.TenantID, map[string]interface{}{
					"request_id":     item.ID,
					"failure_reason": provErr.Error(),
				})
			}
		case "denied", "expired":
			item.Status = "denied"
			item.FailureReason = "governance request " + status
			_ = s.store.UpdateRequest(ctx, item)
			_ = publishAudit(ctx, s.events, "audit.autokey.request_denied", item.TenantID, map[string]interface{}{
				"request_id":            item.ID,
				"governance_request_id": item.GovernanceRequestID,
				"status":                status,
			})
		}
	}
	return nil
}

func (s *Service) provisionRequest(ctx context.Context, request AutokeyRequest) (AutokeyRequest, error) {
	if request.Status == "provisioned" && request.HandleID != "" && request.KeyID != "" {
		return request, nil
	}
	if s.keycore == nil {
		return AutokeyRequest{}, newServiceError(424, "keycore_unavailable", "keycore is not configured")
	}
	settings, err := s.ensureSettings(ctx, request.TenantID)
	if err != nil {
		return AutokeyRequest{}, err
	}
	input := CreateAutokeyRequestInput{
		TenantID:           request.TenantID,
		ServiceName:        request.ServiceName,
		ResourceType:       request.ResourceType,
		ResourceRef:        request.ResourceRef,
		TemplateID:         request.TemplateID,
		HandleName:         request.HandleName,
		KeyName:            request.KeyName,
		RequestedAlgorithm: request.RequestedAlgorithm,
		RequestedKeyType:   request.RequestedKeyType,
		RequestedPurpose:   request.RequestedPurpose,
		RequesterID:        request.RequesterID,
		RequesterEmail:     request.RequesterEmail,
		RequesterIP:        request.RequesterIP,
		Justification:      request.Justification,
	}
	resolved, err := s.resolveProvisionSpec(ctx, settings, input)
	if err != nil {
		return AutokeyRequest{}, err
	}
	if existing, getErr := s.store.GetHandleByBinding(ctx, request.TenantID, request.ServiceName, request.ResourceType, request.ResourceRef); getErr == nil {
		request.Status = "provisioned"
		request.HandleID = existing.ID
		request.KeyID = existing.KeyID
		request.PolicyMatched = existing.PolicyMatched
		request.FulfilledAt = s.now()
		if updateErr := s.store.UpdateRequest(ctx, request); updateErr != nil {
			return AutokeyRequest{}, updateErr
		}
		return s.store.GetRequest(ctx, request.TenantID, request.ID)
	}
	createdKey, err := s.keycore.CreateKey(ctx, resolved.KeyCreate)
	if err != nil {
		return AutokeyRequest{}, err
	}
	handle := AutokeyHandle{
		ID:            newID("akh"),
		TenantID:      request.TenantID,
		ServiceName:   request.ServiceName,
		ResourceType:  request.ResourceType,
		ResourceRef:   request.ResourceRef,
		HandleName:    resolved.HandleName,
		KeyID:         createdKey.KeyID,
		TemplateID:    resolved.Template.ID,
		RequestID:     request.ID,
		Status:        "active",
		Managed:       true,
		PolicyMatched: resolved.PolicyMatched,
		Spec:          resolved.Spec,
	}
	savedHandle, err := s.store.UpsertHandle(ctx, handle)
	if err != nil {
		return AutokeyRequest{}, err
	}
	request.Status = "provisioned"
	request.HandleID = savedHandle.ID
	request.KeyID = createdKey.KeyID
	request.PolicyMatched = resolved.PolicyMatched
	request.PolicyMismatchReason = resolved.PolicyMismatchReason
	request.ResolvedSpec = resolved.Spec
	request.FulfilledAt = s.now()
	if err := s.store.UpdateRequest(ctx, request); err != nil {
		return AutokeyRequest{}, err
	}
	_ = publishAudit(ctx, s.events, "audit.autokey.request_provisioned", request.TenantID, map[string]interface{}{
		"request_id":      request.ID,
		"handle_id":       savedHandle.ID,
		"key_id":          createdKey.KeyID,
		"service_name":    request.ServiceName,
		"resource_type":   request.ResourceType,
		"resource_ref":    request.ResourceRef,
		"requested_by":    request.RequesterID,
		"policy_matched":  request.PolicyMatched,
		"approval_source": firstNonEmpty(request.GovernanceRequestID, "direct"),
	})
	return s.store.GetRequest(ctx, request.TenantID, request.ID)
}

func errorsIsNotFound(err error) bool { return errorsIs(err, errNotFound) }

func errorsIs(err error, target error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), strings.ToLower(target.Error())) || target == err
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
