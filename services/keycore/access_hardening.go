package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

type KeyAccessSettings struct {
	TenantID                       string    `json:"tenant_id"`
	DenyByDefault                  bool      `json:"deny_by_default"`
	RequireApprovalForPolicyChange bool      `json:"require_approval_for_policy_change"`
	GrantDefaultTTLMinutes         int       `json:"grant_default_ttl_minutes"`
	GrantMaxTTLMinutes             int       `json:"grant_max_ttl_minutes"`
	EnforceSignedRequests          bool      `json:"enforce_signed_requests"`
	ReplayWindowSeconds            int       `json:"replay_window_seconds"`
	NonceTTLSeconds                int       `json:"nonce_ttl_seconds"`
	RequireInterfacePolicies       bool      `json:"require_interface_policies"`
	UpdatedBy                      string    `json:"updated_by,omitempty"`
	UpdatedAt                      time.Time `json:"updated_at,omitempty"`
}

type KeyInterfaceSubjectPolicy struct {
	ID            string            `json:"id"`
	TenantID      string            `json:"tenant_id"`
	InterfaceName string            `json:"interface_name"`
	SubjectType   AccessSubjectType `json:"subject_type"`
	SubjectID     string            `json:"subject_id"`
	Operations    []string          `json:"operations"`
	Enabled       bool              `json:"enabled"`
	CreatedBy     string            `json:"created_by,omitempty"`
	CreatedAt     time.Time         `json:"created_at,omitempty"`
	UpdatedAt     time.Time         `json:"updated_at,omitempty"`
}

type RESTClientSecurityObservation struct {
	AuthMode         string
	Verified         bool
	ReplayViolation  bool
	SignatureFailure bool
	UnsignedBlocked  bool
	ObservedAt       time.Time
}

type RESTClientSecurityBinding struct {
	AuthMode                  string `json:"auth_mode"`
	ReplayProtectionEnabled   bool   `json:"replay_protection_enabled"`
	HTTPSignatureKeyID        string `json:"http_signature_key_id,omitempty"`
	HTTPSignaturePublicKeyPEM string `json:"http_signature_public_key_pem,omitempty"`
}

func defaultKeyAccessSettings(tenantID string) KeyAccessSettings {
	return KeyAccessSettings{
		TenantID:                       strings.TrimSpace(tenantID),
		DenyByDefault:                  false,
		RequireApprovalForPolicyChange: false,
		GrantDefaultTTLMinutes:         0,
		GrantMaxTTLMinutes:             0,
		EnforceSignedRequests:          false,
		ReplayWindowSeconds:            300,
		NonceTTLSeconds:                900,
		RequireInterfacePolicies:       false,
	}
}

func normalizeKeyAccessSettings(in KeyAccessSettings) KeyAccessSettings {
	out := in
	out.TenantID = strings.TrimSpace(out.TenantID)
	if out.GrantDefaultTTLMinutes < 0 {
		out.GrantDefaultTTLMinutes = 0
	}
	if out.GrantDefaultTTLMinutes > 60*24*30 {
		out.GrantDefaultTTLMinutes = 60 * 24 * 30
	}
	if out.GrantMaxTTLMinutes < 0 {
		out.GrantMaxTTLMinutes = 0
	}
	if out.GrantMaxTTLMinutes > 60*24*90 {
		out.GrantMaxTTLMinutes = 60 * 24 * 90
	}
	if out.GrantMaxTTLMinutes > 0 && out.GrantDefaultTTLMinutes > out.GrantMaxTTLMinutes {
		out.GrantDefaultTTLMinutes = out.GrantMaxTTLMinutes
	}
	if out.ReplayWindowSeconds < 30 {
		out.ReplayWindowSeconds = 30
	}
	if out.ReplayWindowSeconds > 3600 {
		out.ReplayWindowSeconds = 3600
	}
	if out.NonceTTLSeconds < out.ReplayWindowSeconds {
		out.NonceTTLSeconds = out.ReplayWindowSeconds
	}
	if out.NonceTTLSeconds > 7200 {
		out.NonceTTLSeconds = 7200
	}
	out.UpdatedBy = strings.TrimSpace(out.UpdatedBy)
	return out
}

func normalizeInterfaceName(raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return "rest"
	}
	v = strings.ReplaceAll(v, "_", "-")
	switch v {
	case "dashboard", "dashboard-ui", "dashboard-ui-http":
		return "dashboard-ui"
	case "rest", "api":
		return "rest"
	case "rest-api":
		return "rest"
	case "ekm", "tde":
		return "ekm"
	case "ekm-data":
		return "ekm"
	case "payment", "paymenttcp", "payment-tcp", "paytcp":
		return "payment-tcp"
	case "kmip", "kmip-tls":
		return "kmip"
	case "hyok", "hyok-api":
		return "hyok"
	case "byok":
		return "byok"
	default:
		return v
	}
}

func normalizeInterfacePolicy(in KeyInterfaceSubjectPolicy) (KeyInterfaceSubjectPolicy, error) {
	out := in
	out.TenantID = strings.TrimSpace(out.TenantID)
	out.InterfaceName = normalizeInterfaceName(out.InterfaceName)
	subType, err := normalizeAccessSubjectType(out.SubjectType)
	if err != nil {
		return KeyInterfaceSubjectPolicy{}, err
	}
	out.SubjectType = subType
	out.SubjectID = strings.TrimSpace(out.SubjectID)
	if out.SubjectID == "" {
		return KeyInterfaceSubjectPolicy{}, errors.New("subject_id is required")
	}
	ops, err := normalizeAccessOperations(out.Operations)
	if err != nil {
		return KeyInterfaceSubjectPolicy{}, err
	}
	out.Operations = ops
	if strings.TrimSpace(out.ID) == "" {
		out.ID = newID("ifp")
	}
	out.CreatedBy = strings.TrimSpace(out.CreatedBy)
	return out, nil
}

func grantActiveAt(grant KeyAccessGrant, now time.Time) bool {
	if grant.NotBefore != nil && now.Before(grant.NotBefore.UTC()) {
		return false
	}
	if grant.ExpiresAt != nil && now.After(grant.ExpiresAt.UTC()) {
		return false
	}
	return true
}

func dedupeLower(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		item := strings.TrimSpace(v)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func (s *Service) enforceInterfaceSubjectPolicy(ctx context.Context, tenantID string, actor AccessActor, operation string, actorGroups []string) error {
	interfaceName := normalizeInterfaceName(actor.InterfaceName)
	policies, err := s.store.ListKeyInterfaceSubjectPolicies(ctx, tenantID, interfaceName)
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		return fmt.Errorf("access denied: no interface policy for interface %s", interfaceName)
	}
	userCandidates := dedupeLower([]string{actor.UserID, actor.Username, actor.SubjectID})
	groupCandidates := dedupeLower(actorGroups)
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		if !operationAllowed(policy.Operations, operation) {
			continue
		}
		switch policy.SubjectType {
		case AccessSubjectUser:
			for _, candidate := range userCandidates {
				if strings.EqualFold(strings.TrimSpace(policy.SubjectID), candidate) {
					return nil
				}
			}
		case AccessSubjectGroup:
			if slices.Contains(groupCandidates, strings.TrimSpace(policy.SubjectID)) {
				return nil
			}
		}
	}
	return errors.New("access denied: interface subject policy does not allow this operation")
}

func (s *Service) ensureAccessPolicyApproval(ctx context.Context, tenantID string, keyID string, updatedBy string, grants []KeyAccessGrant) error {
	if s.approval == nil {
		return errors.New("governance approval client is not configured")
	}
	raw, _ := json.Marshal(map[string]any{
		"key_id": keyID,
		"grants": grants,
	})
	sum := sha256.Sum256(raw)
	payloadHash := hex.EncodeToString(sum[:])
	approved, requestID, err := s.approval.ensureApproval(ctx, governanceApprovalInput{
		TenantID:       tenantID,
		KeyID:          keyID,
		Operation:      "update_access_policy",
		PayloadHash:    payloadHash,
		RequesterID:    strings.TrimSpace(updatedBy),
		RequesterEmail: "",
		RequesterIP:    "",
		PolicyID:       "",
	})
	if err != nil {
		return err
	}
	if !approved {
		if strings.TrimSpace(requestID) == "" {
			return errors.New("governance approval request was not created")
		}
		return approvalRequiredError{RequestID: requestID}
	}
	return nil
}

func (s *Service) GetKeyAccessSettings(ctx context.Context, tenantID string) (KeyAccessSettings, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return KeyAccessSettings{}, errors.New("tenant_id is required")
	}
	settings, err := s.store.GetKeyAccessSettings(ctx, tenantID)
	if err != nil {
		return KeyAccessSettings{}, err
	}
	if strings.TrimSpace(settings.TenantID) == "" {
		settings = defaultKeyAccessSettings(tenantID)
	}
	return normalizeKeyAccessSettings(settings), nil
}

func (s *Service) UpdateKeyAccessSettings(ctx context.Context, settings KeyAccessSettings) (KeyAccessSettings, error) {
	settings = normalizeKeyAccessSettings(settings)
	if settings.TenantID == "" {
		return KeyAccessSettings{}, errors.New("tenant_id is required")
	}
	out, err := s.store.UpsertKeyAccessSettings(ctx, settings)
	if err != nil {
		return KeyAccessSettings{}, err
	}
	return out, nil
}

func (s *Service) ListKeyInterfaceSubjectPolicies(ctx context.Context, tenantID string, interfaceName string) ([]KeyInterfaceSubjectPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	return s.store.ListKeyInterfaceSubjectPolicies(ctx, tenantID, normalizeInterfaceName(interfaceName))
}

func (s *Service) UpsertKeyInterfaceSubjectPolicy(ctx context.Context, policy KeyInterfaceSubjectPolicy) (KeyInterfaceSubjectPolicy, error) {
	policy, err := normalizeInterfacePolicy(policy)
	if err != nil {
		return KeyInterfaceSubjectPolicy{}, err
	}
	out, err := s.store.UpsertKeyInterfaceSubjectPolicy(ctx, policy)
	if err != nil {
		return KeyInterfaceSubjectPolicy{}, err
	}
	return out, nil
}

func (s *Service) DeleteKeyInterfaceSubjectPolicy(ctx context.Context, tenantID string, id string) error {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return errors.New("tenant_id and id are required")
	}
	return s.store.DeleteKeyInterfaceSubjectPolicy(ctx, tenantID, id)
}
