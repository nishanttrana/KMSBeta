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

type KeyInterfacePort struct {
	TenantID      string    `json:"tenant_id"`
	InterfaceName string    `json:"interface_name"`
	BindAddress   string    `json:"bind_address"`
	Port          int       `json:"port"`
	Enabled       bool      `json:"enabled"`
	Description   string    `json:"description,omitempty"`
	UpdatedBy     string    `json:"updated_by,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

func defaultInterfacePorts(tenantID string) []KeyInterfacePort {
	return []KeyInterfacePort{
		{TenantID: tenantID, InterfaceName: "rest", BindAddress: "0.0.0.0", Port: 443, Enabled: true, Description: "REST API"},
		{TenantID: tenantID, InterfaceName: "ekm", BindAddress: "0.0.0.0", Port: 5696, Enabled: true, Description: "EKM / TDE"},
		{TenantID: tenantID, InterfaceName: "payment-tcp", BindAddress: "0.0.0.0", Port: 9170, Enabled: true, Description: "Payment Crypto TCP"},
		{TenantID: tenantID, InterfaceName: "pkcs11", BindAddress: "0.0.0.0", Port: 8101, Enabled: true, Description: "PKCS#11 gRPC bridge"},
		{TenantID: tenantID, InterfaceName: "jca", BindAddress: "0.0.0.0", Port: 8102, Enabled: true, Description: "JCA/JCE bridge"},
		{TenantID: tenantID, InterfaceName: "kmip", BindAddress: "0.0.0.0", Port: 5698, Enabled: true, Description: "KMIP"},
		{TenantID: tenantID, InterfaceName: "hyok", BindAddress: "0.0.0.0", Port: 9444, Enabled: true, Description: "HYOK"},
		{TenantID: tenantID, InterfaceName: "byok", BindAddress: "0.0.0.0", Port: 9445, Enabled: true, Description: "BYOK"},
	}
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
	case "rest", "api":
		return "rest"
	case "ekm", "tde":
		return "ekm"
	case "payment", "paymenttcp", "payment-tcp", "paytcp":
		return "payment-tcp"
	case "pkcs11", "pkcs-11":
		return "pkcs11"
	case "jca", "jce":
		return "jca"
	case "kmip":
		return "kmip"
	case "hyok":
		return "hyok"
	case "byok":
		return "byok"
	default:
		return v
	}
}

func normalizePortConfig(in KeyInterfacePort) (KeyInterfacePort, error) {
	out := in
	out.TenantID = strings.TrimSpace(out.TenantID)
	out.InterfaceName = normalizeInterfaceName(out.InterfaceName)
	out.BindAddress = strings.TrimSpace(out.BindAddress)
	if out.BindAddress == "" {
		out.BindAddress = "0.0.0.0"
	}
	if out.Port < 1 || out.Port > 65535 {
		return KeyInterfacePort{}, errors.New("port must be between 1 and 65535")
	}
	out.Description = strings.TrimSpace(out.Description)
	out.UpdatedBy = strings.TrimSpace(out.UpdatedBy)
	return out, nil
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
	_ = s.publishAudit(ctx, "audit.key.access_settings_updated", settings.TenantID, map[string]any{
		"deny_by_default":                    out.DenyByDefault,
		"require_approval_for_policy_change": out.RequireApprovalForPolicyChange,
		"grant_default_ttl_minutes":          out.GrantDefaultTTLMinutes,
		"grant_max_ttl_minutes":              out.GrantMaxTTLMinutes,
		"enforce_signed_requests":            out.EnforceSignedRequests,
		"replay_window_seconds":              out.ReplayWindowSeconds,
		"nonce_ttl_seconds":                  out.NonceTTLSeconds,
		"require_interface_policies":         out.RequireInterfacePolicies,
		"updated_by":                         out.UpdatedBy,
	})
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
	_ = s.publishAudit(ctx, "audit.key.interface_policy_upserted", out.TenantID, map[string]any{
		"id":             out.ID,
		"interface_name": out.InterfaceName,
		"subject_type":   out.SubjectType,
		"subject_id":     out.SubjectID,
		"operations":     out.Operations,
		"enabled":        out.Enabled,
	})
	return out, nil
}

func (s *Service) DeleteKeyInterfaceSubjectPolicy(ctx context.Context, tenantID string, id string) error {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return errors.New("tenant_id and id are required")
	}
	if err := s.store.DeleteKeyInterfaceSubjectPolicy(ctx, tenantID, id); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.key.interface_policy_deleted", tenantID, map[string]any{"id": id})
	return nil
}

func (s *Service) ListKeyInterfacePorts(ctx context.Context, tenantID string) ([]KeyInterfacePort, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, errors.New("tenant_id is required")
	}
	items, err := s.store.ListKeyInterfacePorts(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return defaultInterfacePorts(tenantID), nil
	}
	return items, nil
}

func (s *Service) UpsertKeyInterfacePort(ctx context.Context, in KeyInterfacePort) (KeyInterfacePort, error) {
	p, err := normalizePortConfig(in)
	if err != nil {
		return KeyInterfacePort{}, err
	}
	out, err := s.store.UpsertKeyInterfacePort(ctx, p)
	if err != nil {
		return KeyInterfacePort{}, err
	}
	_ = s.publishAudit(ctx, "audit.key.interface_port_upserted", out.TenantID, map[string]any{
		"interface_name": out.InterfaceName,
		"bind_address":   out.BindAddress,
		"port":           out.Port,
		"enabled":        out.Enabled,
		"description":    out.Description,
	})
	return out, nil
}

func (s *Service) DeleteKeyInterfacePort(ctx context.Context, tenantID string, interfaceName string) error {
	tenantID = strings.TrimSpace(tenantID)
	interfaceName = normalizeInterfaceName(interfaceName)
	if tenantID == "" || interfaceName == "" {
		return errors.New("tenant_id and interface_name are required")
	}
	if err := s.store.DeleteKeyInterfacePort(ctx, tenantID, interfaceName); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.key.interface_port_deleted", tenantID, map[string]any{"interface_name": interfaceName})
	return nil
}
