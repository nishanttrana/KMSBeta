package main

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"
)

type Service struct {
	store      Store
	governance GovernanceClient
	now        func() time.Time
}

func NewService(store Store, governance GovernanceClient) *Service {
	return &Service{
		store:      store,
		governance: governance,
		now:        func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) ensureSettings(ctx context.Context, tenantID string) (KeyAccessSettings, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return KeyAccessSettings{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	item, err := s.store.GetSettings(ctx, tenantID)
	if err == nil {
		return normalizeSettings(item), nil
	}
	if !errorsIsNotFound(err) {
		return KeyAccessSettings{}, err
	}
	return s.store.UpsertSettings(ctx, defaultSettings(tenantID))
}

func errorsIsNotFound(err error) bool { return err == errNotFound }

func (s *Service) GetSettings(ctx context.Context, tenantID string) (KeyAccessSettings, error) {
	item, err := s.ensureSettings(ctx, tenantID)
	if err != nil {
		return KeyAccessSettings{}, err
	}
	return item, nil
}

func (s *Service) UpdateSettings(ctx context.Context, in KeyAccessSettings) (KeyAccessSettings, error) {
	item := normalizeSettings(in)
	if item.TenantID == "" {
		return KeyAccessSettings{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	saved, err := s.store.UpsertSettings(ctx, item)
	if err != nil {
		return KeyAccessSettings{}, err
	}
	return saved, nil
}

func (s *Service) ListRules(ctx context.Context, tenantID string) ([]KeyAccessRule, error) {
	if _, err := s.ensureSettings(ctx, tenantID); err != nil {
		return nil, err
	}
	items, err := s.store.ListRules(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *Service) UpsertRule(ctx context.Context, in KeyAccessRule) (KeyAccessRule, error) {
	item := normalizeRule(in)
	if item.TenantID == "" || item.Code == "" || item.Label == "" {
		return KeyAccessRule{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, code, and label are required")
	}
	if _, err := s.ensureSettings(ctx, item.TenantID); err != nil {
		return KeyAccessRule{}, err
	}
	saved, err := s.store.UpsertRule(ctx, item)
	if err != nil {
		return KeyAccessRule{}, err
	}
	return saved, nil
}

func (s *Service) DeleteRule(ctx context.Context, tenantID string, id string) error {
	if err := s.store.DeleteRule(ctx, tenantID, id); err != nil {
		return err
	}
	return nil
}

func (s *Service) GetSummary(ctx context.Context, tenantID string) (KeyAccessSummary, error) {
	settings, err := s.ensureSettings(ctx, tenantID)
	if err != nil {
		return KeyAccessSummary{}, err
	}
	rules, _ := s.store.ListRules(ctx, tenantID)
	decisions, _ := s.store.ListDecisions(ctx, tenantID, "", "", 1000)
	summary := KeyAccessSummary{
		TenantID:      tenantID,
		Enabled:       settings.Enabled,
		Mode:          settings.Mode,
		DefaultAction: settings.DefaultAction,
		RuleCount:     len(rules),
		Services:      []KeyAccessServiceSummary{},
	}
	cutoff := s.now().Add(-24 * time.Hour)
	serviceMap := map[string]*KeyAccessServiceSummary{}
	for _, item := range decisions {
		if !item.CreatedAt.IsZero() && item.CreatedAt.Before(cutoff) {
			continue
		}
		summary.TotalRequests24h++
		switch strings.ToLower(strings.TrimSpace(item.Decision)) {
		case "allow":
			summary.AllowCount24h++
		case "approval":
			summary.ApprovalCount24h++
		default:
			summary.DenyCount24h++
		}
		if item.BypassDetected {
			summary.BypassCount24h++
		}
		if strings.Contains(strings.ToLower(item.Reason), "justification") || strings.Contains(strings.ToLower(item.Reason), "unknown_code") || strings.Contains(strings.ToLower(item.Reason), "scope_mismatch") {
			summary.UnjustifiedCount24h++
		}
		key := firstNonEmpty(item.Service, "unknown")
		entry := serviceMap[key]
		if entry == nil {
			entry = &KeyAccessServiceSummary{Service: key}
			serviceMap[key] = entry
		}
		entry.Requests24h++
		switch strings.ToLower(strings.TrimSpace(item.Decision)) {
		case "allow":
			entry.AllowCount24h++
		case "approval":
			entry.ApprovalCount24h++
		default:
			entry.DenyCount24h++
		}
		if item.BypassDetected {
			entry.BypassCount24h++
		}
		if strings.Contains(strings.ToLower(item.Reason), "justification") || strings.Contains(strings.ToLower(item.Reason), "unknown_code") || strings.Contains(strings.ToLower(item.Reason), "scope_mismatch") {
			entry.UnjustifiedCount24h++
		}
	}
	for _, item := range serviceMap {
		summary.Services = append(summary.Services, *item)
	}
	sort.Slice(summary.Services, func(i, j int) bool { return summary.Services[i].Service < summary.Services[j].Service })
	return summary, nil
}

func (s *Service) ListDecisions(ctx context.Context, tenantID string, service string, action string, limit int) ([]KeyAccessDecision, error) {
	if _, err := s.ensureSettings(ctx, tenantID); err != nil {
		return nil, err
	}
	items, err := s.store.ListDecisions(ctx, tenantID, service, action, limit)
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (s *Service) Evaluate(ctx context.Context, in EvaluateKeyAccessInput) (EvaluateKeyAccessResult, error) {
	input := normalizeEvaluation(in)
	if input.TenantID == "" || input.Service == "" || input.Operation == "" {
		return EvaluateKeyAccessResult{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id, service, and operation are required")
	}
	settings, err := s.ensureSettings(ctx, input.TenantID)
	if err != nil {
		return EvaluateKeyAccessResult{}, err
	}
	rules, err := s.store.ListRules(ctx, input.TenantID)
	if err != nil {
		return EvaluateKeyAccessResult{}, err
	}

	result := EvaluateKeyAccessResult{
		DecisionID: newID("kadj"),
		Enabled:    settings.Enabled,
		Mode:       settings.Mode,
		Action:     "allow",
		Metadata:   map[string]interface{}{},
	}
	decision := KeyAccessDecision{
		ID:                result.DecisionID,
		TenantID:          input.TenantID,
		Service:           input.Service,
		Connector:         input.Connector,
		Operation:         input.Operation,
		KeyID:             input.KeyID,
		ResourceID:        input.ResourceID,
		TargetType:        input.TargetType,
		RequestID:         input.RequestID,
		RequesterID:       input.RequesterID,
		RequesterEmail:    input.RequesterEmail,
		RequesterIP:       input.RequesterIP,
		JustificationCode: input.JustificationCode,
		JustificationText: trimLimit(input.JustificationText, 512),
		PolicyMode:        settings.Mode,
		Metadata:          input.Metadata,
	}

	if !settings.Enabled {
		result.Reason = "tenant key-access justification policy is disabled"
		decision.Decision = "allow"
		decision.Reason = result.Reason
		if err := s.store.CreateDecision(ctx, decision); err != nil {
			return EvaluateKeyAccessResult{}, err
		}
		return result, nil
	}

	rule := matchRule(rules, input.JustificationCode)
	violationReason := ""
	switch {
	case settings.RequireJustificationCode && input.JustificationCode == "":
		violationReason = "missing_justification_code"
	case input.JustificationCode != "" && rule == nil:
		violationReason = "unknown_code"
	case rule != nil && len(rule.Services) > 0 && !containsScope(rule.Services, input.Service):
		violationReason = "service_scope_mismatch"
	case rule != nil && len(rule.Operations) > 0 && !containsScope(rule.Operations, input.Operation):
		violationReason = "operation_scope_mismatch"
	case (settings.RequireJustificationText || (rule != nil && rule.RequireText)) && input.JustificationText == "":
		violationReason = "justification_text_required"
	}

	if rule != nil {
		result.MatchedRuleID = rule.ID
		result.MatchedCode = rule.Code
		decision.MatchedRuleID = rule.ID
		decision.MatchedCode = rule.Code
	}

	action := settings.DefaultAction
	policyID := settings.ApprovalPolicyID
	if rule != nil {
		action = normalizeDecisionAction(rule.Action)
		if strings.TrimSpace(rule.ApprovalPolicyID) != "" {
			policyID = strings.TrimSpace(rule.ApprovalPolicyID)
		}
	}

	if violationReason != "" && settings.Mode == "audit" {
		result.Action = "allow"
		result.BypassDetected = true
		result.Reason = violationReason
		decision.Decision = "allow"
		decision.BypassDetected = true
		decision.Reason = violationReason
	} else {
		action = normalizeDecisionAction(action)
		result.Action = action
		result.Reason = violationReason
		decision.Decision = action
		decision.Reason = violationReason
	}

	if result.Action == "approval" {
		result.ApprovalRequired = true
		decision.ApprovalRequired = true
		if strings.TrimSpace(policyID) == "" || s.governance == nil {
			result.Action = "deny"
			result.ApprovalRequired = false
			result.Reason = "approval_policy_unavailable"
			decision.Decision = "deny"
			decision.ApprovalRequired = false
			decision.Reason = "approval_policy_unavailable"
		} else {
			approval, approveErr := s.governance.CreateApprovalRequest(ctx, GovernanceCreateApprovalRequest{
				TenantID:    input.TenantID,
				PolicyID:    policyID,
				Action:      "external_key_access",
				TargetType:  firstNonEmpty(input.TargetType, "external_key_access"),
				TargetID:    firstNonEmpty(input.KeyID, input.ResourceID, input.Service+":"+input.Operation),
				TargetDetails: map[string]interface{}{
					"service":            input.Service,
					"connector":          input.Connector,
					"operation":          input.Operation,
					"key_id":             input.KeyID,
					"resource_id":        input.ResourceID,
					"justification_code": input.JustificationCode,
					"justification_text": trimLimit(input.JustificationText, 512),
					"request_id":         input.RequestID,
					"metadata":           input.Metadata,
				},
				RequesterID:    input.RequesterID,
				RequesterEmail: input.RequesterEmail,
				RequesterIP:    input.RequesterIP,
			})
			if approveErr != nil {
				result.Action = "deny"
				result.ApprovalRequired = false
				result.Reason = "approval_request_failed: " + approveErr.Error()
				decision.Decision = "deny"
				decision.ApprovalRequired = false
				decision.Reason = result.Reason
			} else {
				result.ApprovalRequestID = approval.ID
				decision.ApprovalRequestID = approval.ID
			}
		}
	}

	if decision.Decision == "" {
		decision.Decision = "deny"
		result.Action = "deny"
	}
	if err := s.store.CreateDecision(ctx, decision); err != nil {
		return EvaluateKeyAccessResult{}, err
	}
	return result, nil
}

func matchRule(rules []KeyAccessRule, code string) *KeyAccessRule {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return nil
	}
	for i := range rules {
		rule := rules[i]
		if !rule.Enabled {
			continue
		}
		if strings.ToUpper(strings.TrimSpace(rule.Code)) == code {
			return &rule
		}
	}
	return nil
}
