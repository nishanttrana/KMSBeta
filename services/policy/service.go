package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"vecta-kms/pkg/clustersync"
)

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Service struct {
	store   Store
	events  EventPublisher
	cluster clustersync.Publisher
}

func NewService(store Store, events EventPublisher) *Service {
	return &Service{
		store:  store,
		events: events,
	}
}

func (s *Service) SetClusterSyncPublisher(pub clustersync.Publisher) {
	if pub == nil {
		return
	}
	s.cluster = pub
}

func (s *Service) CreatePolicy(ctx context.Context, req CreatePolicyRequest) (Policy, error) {
	doc, parsed, err := parsePolicyYAML(req.YAML)
	if err != nil {
		return Policy{}, err
	}
	tenantID, err := normalizeTenant(req.TenantID, doc.Metadata.Tenant)
	if err != nil {
		return Policy{}, err
	}
	doc.Metadata.Tenant = tenantID
	if req.Actor == "" {
		req.Actor = "system"
	}
	normalizedYAML, _ := json.Marshal(parsed)
	commit := newCommit("", tenantID, doc.Metadata.Name, string(normalizedYAML), req.Actor)

	p := Policy{
		ID:             newID("pol"),
		TenantID:       tenantID,
		Name:           doc.Metadata.Name,
		Description:    doc.Metadata.Description,
		Status:         "active",
		SpecType:       doc.Spec.Type,
		Labels:         doc.Metadata.Labels,
		RawYAML:        req.YAML,
		ParsedJSON:     parsed,
		CurrentVersion: 1,
		CurrentCommit:  commit,
		CreatedBy:      req.Actor,
		UpdatedBy:      req.Actor,
	}
	v := PolicyVersion{
		ID:            newID("pver"),
		TenantID:      tenantID,
		PolicyID:      p.ID,
		Version:       1,
		CommitHash:    commit,
		ChangeType:    "create",
		ChangeMessage: req.CommitMessage,
		RawYAML:       req.YAML,
		ParsedJSON:    parsed,
		CreatedBy:     req.Actor,
	}
	if err := s.store.CreatePolicy(ctx, p, v); err != nil {
		return Policy{}, err
	}
	_ = s.publishAudit(ctx, "audit.policy.created", tenantID, map[string]any{
		"policy_id":   p.ID,
		"name":        p.Name,
		"spec_type":   p.SpecType,
		"version":     p.CurrentVersion,
		"commit_hash": p.CurrentCommit,
	})
	return s.store.GetPolicy(ctx, tenantID, p.ID)
}

func (s *Service) UpdatePolicy(ctx context.Context, policyID string, req UpdatePolicyRequest) (Policy, error) {
	current, err := s.store.GetPolicy(ctx, req.TenantID, policyID)
	if err != nil {
		return Policy{}, err
	}
	doc, parsed, err := parsePolicyYAML(req.YAML)
	if err != nil {
		return Policy{}, err
	}
	tenantID, err := normalizeTenant(req.TenantID, doc.Metadata.Tenant)
	if err != nil {
		return Policy{}, err
	}
	if tenantID != current.TenantID {
		return Policy{}, errors.New("policy tenant cannot be changed")
	}
	if req.Actor == "" {
		req.Actor = "system"
	}
	parent := current.CurrentCommit
	normalizedYAML, _ := json.Marshal(parsed)
	commit := newCommit(parent, tenantID, doc.Metadata.Name, string(normalizedYAML), req.Actor)
	current.Description = doc.Metadata.Description
	current.SpecType = doc.Spec.Type
	current.Labels = doc.Metadata.Labels
	current.RawYAML = req.YAML
	current.ParsedJSON = parsed
	current.CurrentVersion++
	current.CurrentCommit = commit
	current.UpdatedBy = req.Actor
	current.Status = "active"

	v := PolicyVersion{
		ID:               newID("pver"),
		TenantID:         tenantID,
		PolicyID:         current.ID,
		Version:          current.CurrentVersion,
		CommitHash:       commit,
		ParentCommitHash: parent,
		ChangeType:       "update",
		ChangeMessage:    req.CommitMessage,
		RawYAML:          req.YAML,
		ParsedJSON:       parsed,
		CreatedBy:        req.Actor,
	}
	if err := s.store.UpdatePolicy(ctx, current, v); err != nil {
		return Policy{}, err
	}
	_ = s.publishAudit(ctx, "audit.policy.updated", tenantID, map[string]any{
		"policy_id":   current.ID,
		"version":     current.CurrentVersion,
		"commit_hash": current.CurrentCommit,
	})
	return s.store.GetPolicy(ctx, tenantID, current.ID)
}

func (s *Service) DeletePolicy(ctx context.Context, tenantID string, policyID string, actor string, message string) error {
	current, err := s.store.GetPolicy(ctx, tenantID, policyID)
	if err != nil {
		return err
	}
	if actor == "" {
		actor = "system"
	}
	commit := newCommit(current.CurrentCommit, tenantID, current.Name, "delete", actor)
	v := PolicyVersion{
		ID:               newID("pver"),
		TenantID:         tenantID,
		PolicyID:         policyID,
		Version:          current.CurrentVersion + 1,
		CommitHash:       commit,
		ParentCommitHash: current.CurrentCommit,
		ChangeType:       "delete",
		ChangeMessage:    message,
		RawYAML:          current.RawYAML,
		ParsedJSON:       current.ParsedJSON,
		CreatedBy:        actor,
	}
	if err := s.store.DeletePolicy(ctx, tenantID, policyID, actor, v); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.policy.deleted", tenantID, map[string]any{
		"policy_id": policyID,
	})
	return nil
}

func (s *Service) GetPolicy(ctx context.Context, tenantID string, policyID string) (Policy, error) {
	p, err := s.store.GetPolicy(ctx, tenantID, policyID)
	if err != nil {
		return Policy{}, err
	}
	_ = s.publishAudit(ctx, "audit.policy.read", tenantID, map[string]any{"policy_id": policyID})
	return p, nil
}

func (s *Service) ListPolicies(ctx context.Context, tenantID string, status string, limit int, offset int) ([]Policy, error) {
	items, err := s.store.ListPolicies(ctx, tenantID, status, limit, offset)
	if err != nil {
		return nil, err
	}
	_ = s.publishAudit(ctx, "audit.policy.listed", tenantID, map[string]any{"count": len(items), "status": status})
	return items, nil
}

func (s *Service) ListPolicyVersions(ctx context.Context, tenantID string, policyID string) ([]PolicyVersion, error) {
	return s.store.ListPolicyVersions(ctx, tenantID, policyID)
}

func (s *Service) GetPolicyVersion(ctx context.Context, tenantID string, policyID string, version int) (PolicyVersion, error) {
	return s.store.GetPolicyVersion(ctx, tenantID, policyID, version)
}

func (s *Service) Evaluate(ctx context.Context, req EvaluatePolicyRequest) (EvaluatePolicyResponse, error) {
	if strings.TrimSpace(req.TenantID) == "" {
		return EvaluatePolicyResponse{}, errors.New("tenant_id is required")
	}
	if strings.TrimSpace(req.Operation) == "" {
		return EvaluatePolicyResponse{}, errors.New("operation is required")
	}
	policies, err := s.store.ListActiveForEval(ctx, req.TenantID)
	if err != nil {
		return EvaluatePolicyResponse{}, err
	}

	result := EvaluatePolicyResponse{
		Decision: DecisionAllow,
		Outcomes: make([]RuleOutcome, 0),
	}
	for _, p := range policies {
		doc, _, err := parsePolicyYAML(p.RawYAML)
		if err != nil {
			continue
		}
		d, outcomes := evaluatePolicy(doc, p.ID, p.CurrentVersion, req)
		if len(outcomes) > 0 {
			result.Outcomes = append(result.Outcomes, outcomes...)
		}
		switch d {
		case DecisionDeny:
			result.Decision = DecisionDeny
		case DecisionWarn:
			if result.Decision == DecisionAllow {
				result.Decision = DecisionWarn
			}
		}
	}
	if len(result.Outcomes) > 0 {
		result.Reason = result.Outcomes[0].Message
	} else {
		result.Reason = "allowed by policy"
	}

	_ = s.store.InsertEvaluation(ctx, EvaluationRecord{
		ID:         newID("peval"),
		TenantID:   req.TenantID,
		PolicyID:   firstOutcomePolicyID(result.Outcomes),
		Operation:  req.Operation,
		KeyID:      req.KeyID,
		Decision:   result.Decision,
		Reason:     result.Reason,
		Request:    evaluateRequestMap(req),
		Outcomes:   result.Outcomes,
		OccurredAt: time.Now().UTC(),
	})

	_ = s.publishAudit(ctx, "audit.policy.evaluated", req.TenantID, map[string]any{
		"operation": req.Operation,
		"key_id":    req.KeyID,
		"decision":  result.Decision,
		"outcomes":  len(result.Outcomes),
	})
	if result.Decision == DecisionDeny {
		_ = s.publishAudit(ctx, "audit.policy.violated", req.TenantID, map[string]any{
			"operation": req.Operation,
			"key_id":    req.KeyID,
			"reason":    result.Reason,
		})
	}
	if result.Decision == DecisionWarn {
		_ = s.publishAudit(ctx, "audit.policy.warning", req.TenantID, map[string]any{
			"operation": req.Operation,
			"key_id":    req.KeyID,
			"reason":    result.Reason,
		})
	}
	return result, nil
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]any) error {
	var outErr error
	if s.events != nil {
		raw, err := json.Marshal(map[string]any{
			"tenant_id": tenantID,
			"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
			"service":   "policy",
			"action":    subject,
			"result":    "success",
			"data":      data,
		})
		if err != nil {
			outErr = err
		} else if err := s.events.Publish(ctx, subject, raw); err != nil {
			outErr = err
		}
	}
	if req, ok := policySyncRequest(subject, tenantID, data); ok && s.cluster != nil {
		if err := s.cluster.Publish(ctx, req); err != nil && outErr == nil {
			outErr = err
		}
	}
	return outErr
}

func normalizeTenant(requestTenant string, yamlTenant string) (string, error) {
	reqT := strings.TrimSpace(requestTenant)
	ymlT := strings.TrimSpace(yamlTenant)
	if reqT == "" {
		return "", errors.New("tenant_id is required")
	}
	if ymlT == "" {
		return reqT, nil
	}
	if ymlT == "*" {
		return "*", nil
	}
	if reqT != ymlT {
		return "", errors.New("tenant mismatch between request and yaml")
	}
	return reqT, nil
}

func evaluateRequestMap(req EvaluatePolicyRequest) map[string]any {
	return map[string]any{
		"tenant_id":           req.TenantID,
		"operation":           req.Operation,
		"key_id":              req.KeyID,
		"algorithm":           req.Algorithm,
		"purpose":             req.Purpose,
		"iv_mode":             req.IVMode,
		"ops_total":           req.OpsTotal,
		"ops_limit":           req.OpsLimit,
		"days_since_rotation": req.DaysSinceRotation,
		"key_status":          req.KeyStatus,
		"labels":              req.Labels,
	}
}

func firstOutcomePolicyID(outcomes []RuleOutcome) string {
	if len(outcomes) == 0 {
		return ""
	}
	return outcomes[0].PolicyID
}

func newCommit(parent string, tenant string, name string, body string, actor string) string {
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	sum := sha256.Sum256([]byte(parent + "|" + tenant + "|" + name + "|" + body + "|" + actor + "|" + ts))
	return hex.EncodeToString(sum[:16])
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}
