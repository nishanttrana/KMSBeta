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
	Protocol      string    `json:"protocol,omitempty"`
	CertSource    string    `json:"certificate_source,omitempty"`
	CAID          string    `json:"ca_id,omitempty"`
	CertificateID string    `json:"certificate_id,omitempty"`
	Enabled       bool      `json:"enabled"`
	Description   string    `json:"description,omitempty"`
	UpdatedBy     string    `json:"updated_by,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

type KeyInterfaceTLSConfig struct {
	TenantID      string    `json:"tenant_id"`
	CertSource    string    `json:"certificate_source"`
	CAID          string    `json:"ca_id,omitempty"`
	CertificateID string    `json:"certificate_id,omitempty"`
	UpdatedBy     string    `json:"updated_by,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
}

func defaultInterfacePorts(tenantID string) []KeyInterfacePort {
	return []KeyInterfacePort{
		{TenantID: tenantID, InterfaceName: "dashboard-ui", BindAddress: "0.0.0.0", Port: 5173, Protocol: "http", CertSource: "none", Enabled: true, Description: "Direct Web Dashboard UI"},
		{TenantID: tenantID, InterfaceName: "rest", BindAddress: "0.0.0.0", Port: 443, Protocol: "https", CertSource: "internal_ca", Enabled: true, Description: "REST API"},
		{TenantID: tenantID, InterfaceName: "kmip", BindAddress: "0.0.0.0", Port: 5696, Protocol: "mtls", CertSource: "internal_ca", Enabled: true, Description: "KMIP Protocol Interface"},
		{TenantID: tenantID, InterfaceName: "ekm", BindAddress: "0.0.0.0", Port: 8130, Protocol: "http", CertSource: "none", Enabled: true, Description: "EKM / TDE Endpoint"},
		{TenantID: tenantID, InterfaceName: "payment-tcp", BindAddress: "0.0.0.0", Port: 9170, Protocol: "tcp", CertSource: "none", Enabled: true, Description: "Payment Crypto TCP"},
		{TenantID: tenantID, InterfaceName: "hyok", BindAddress: "0.0.0.0", Port: 8120, Protocol: "http", CertSource: "none", Enabled: true, Description: "HYOK API"},
	}
}

func defaultKeyInterfaceTLSConfig(tenantID string) KeyInterfaceTLSConfig {
	return KeyInterfaceTLSConfig{
		TenantID:   strings.TrimSpace(tenantID),
		CertSource: "internal_ca",
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

func normalizePortConfig(in KeyInterfacePort) (KeyInterfacePort, error) {
	out := applyInterfacePortDefaults(in)
	if out.Port < 1 || out.Port > 65535 {
		return KeyInterfacePort{}, errors.New("port must be between 1 and 65535")
	}
	switch out.CertSource {
	case "internal_ca", "none":
		out.CAID = ""
		out.CertificateID = ""
	case "pki_ca":
		out.CertificateID = ""
		if out.CAID == "" {
			return KeyInterfacePort{}, errors.New("ca_id is required when certificate_source is pki_ca")
		}
	case "uploaded_certificate":
		out.CAID = ""
		if out.CertificateID == "" {
			return KeyInterfacePort{}, errors.New("certificate_id is required when certificate_source is uploaded_certificate")
		}
	}
	out.Description = strings.TrimSpace(out.Description)
	out.UpdatedBy = strings.TrimSpace(out.UpdatedBy)
	return out, nil
}

func applyInterfacePortDefaults(in KeyInterfacePort) KeyInterfacePort {
	out := in
	out.TenantID = strings.TrimSpace(out.TenantID)
	out.InterfaceName = normalizeInterfaceName(out.InterfaceName)
	out.BindAddress = strings.TrimSpace(out.BindAddress)
	if out.BindAddress == "" {
		out.BindAddress = "0.0.0.0"
	}
	out.Protocol = normalizeInterfaceProtocol(out.InterfaceName, out.Protocol)
	out.CertSource = normalizeInterfaceCertSource(out.Protocol, out.CertSource)
	out.CAID = strings.TrimSpace(out.CAID)
	out.CertificateID = strings.TrimSpace(out.CertificateID)
	if !interfaceProtocolUsesCertificate(out.Protocol) {
		out.CertSource = "none"
		out.CAID = ""
		out.CertificateID = ""
	}
	out.Description = strings.TrimSpace(out.Description)
	out.UpdatedBy = strings.TrimSpace(out.UpdatedBy)
	return out
}

func normalizeInterfaceTLSConfig(in KeyInterfaceTLSConfig) (KeyInterfaceTLSConfig, error) {
	out := in
	out.TenantID = strings.TrimSpace(out.TenantID)
	out.CertSource = normalizeInterfaceCertSource("https", out.CertSource)
	out.CAID = strings.TrimSpace(out.CAID)
	out.CertificateID = strings.TrimSpace(out.CertificateID)
	switch out.CertSource {
	case "internal_ca":
		out.CAID = ""
		out.CertificateID = ""
	case "pki_ca":
		out.CertificateID = ""
		if out.CAID == "" {
			return KeyInterfaceTLSConfig{}, errors.New("ca_id is required when certificate_source is pki_ca")
		}
	case "uploaded_certificate":
		out.CAID = ""
		if out.CertificateID == "" {
			return KeyInterfaceTLSConfig{}, errors.New("certificate_id is required when certificate_source is uploaded_certificate")
		}
	default:
		return KeyInterfaceTLSConfig{}, errors.New("invalid certificate_source")
	}
	out.UpdatedBy = strings.TrimSpace(out.UpdatedBy)
	return out, nil
}

func normalizeInterfaceProtocol(interfaceName string, raw string) string {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "http":
		return "http"
	case "https":
		return "https"
	case "tls", "tls13", "tls-1.3", "tls_1_3":
		return "tls13"
	case "mtls", "m-tls", "mutual-tls":
		return "mtls"
	case "tcp":
		return "tcp"
	}
	switch normalizeInterfaceName(interfaceName) {
	case "rest":
		return "https"
	case "kmip":
		return "mtls"
	case "payment-tcp":
		return "tcp"
	default:
		return "http"
	}
}

func interfaceProtocolUsesCertificate(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "https", "tls13", "mtls":
		return true
	default:
		return false
	}
}

func normalizeInterfaceCertSource(protocol string, raw string) string {
	if !interfaceProtocolUsesCertificate(protocol) {
		return "none"
	}
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "", "internal", "internal-ca", "internal_ca", "auto":
		return "internal_ca"
	case "pki", "ca", "pki-ca", "pki_ca":
		return "pki_ca"
	case "uploaded", "certificate", "uploaded-certificate", "uploaded_certificate", "external":
		return "uploaded_certificate"
	default:
		return "internal_ca"
	}
}

func applyTLSConfigToPort(port KeyInterfacePort, cfg KeyInterfaceTLSConfig) KeyInterfacePort {
	out := port
	if !interfaceProtocolUsesCertificate(out.Protocol) {
		out.CertSource = "none"
		out.CAID = ""
		out.CertificateID = ""
		return out
	}
	out.CertSource = cfg.CertSource
	switch cfg.CertSource {
	case "pki_ca":
		out.CAID = cfg.CAID
		out.CertificateID = ""
	case "uploaded_certificate":
		out.CAID = ""
		out.CertificateID = cfg.CertificateID
	default:
		out.CAID = ""
		out.CertificateID = ""
	}
	return out
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
	cfg, err := s.store.GetKeyInterfaceTLSConfig(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	items, err := s.store.ListKeyInterfacePorts(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		items = defaultInterfacePorts(tenantID)
	}
	for i := range items {
		items[i] = applyInterfacePortDefaults(items[i])
		items[i] = applyTLSConfigToPort(items[i], cfg)
	}
	return items, nil
}

func (s *Service) GetKeyInterfaceTLSConfig(ctx context.Context, tenantID string) (KeyInterfaceTLSConfig, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return KeyInterfaceTLSConfig{}, errors.New("tenant_id is required")
	}
	cfg, err := s.store.GetKeyInterfaceTLSConfig(ctx, tenantID)
	if err != nil {
		return KeyInterfaceTLSConfig{}, err
	}
	return normalizeInterfaceTLSConfig(cfg)
}

func (s *Service) UpdateKeyInterfaceTLSConfig(ctx context.Context, in KeyInterfaceTLSConfig) (KeyInterfaceTLSConfig, error) {
	cfg, err := normalizeInterfaceTLSConfig(in)
	if err != nil {
		return KeyInterfaceTLSConfig{}, err
	}
	out, err := s.store.UpsertKeyInterfaceTLSConfig(ctx, cfg)
	if err != nil {
		return KeyInterfaceTLSConfig{}, err
	}
	items, err := s.store.ListKeyInterfacePorts(ctx, cfg.TenantID)
	if err != nil {
		return KeyInterfaceTLSConfig{}, err
	}
	for _, item := range items {
		item = applyInterfacePortDefaults(item)
		if !interfaceProtocolUsesCertificate(item.Protocol) {
			continue
		}
		next := applyTLSConfigToPort(item, out)
		next.UpdatedBy = cfg.UpdatedBy
		if _, err := s.store.UpsertKeyInterfacePort(ctx, next); err != nil {
			return KeyInterfaceTLSConfig{}, err
		}
	}
	_ = s.publishAudit(ctx, "audit.key.interface_tls_config_updated", out.TenantID, map[string]any{
		"certificate_source": out.CertSource,
		"ca_id":              out.CAID,
		"certificate_id":     out.CertificateID,
		"updated_by":         out.UpdatedBy,
	})
	return out, nil
}

func (s *Service) UpsertKeyInterfacePort(ctx context.Context, in KeyInterfacePort) (KeyInterfacePort, error) {
	p, err := normalizePortConfig(in)
	if err != nil {
		return KeyInterfacePort{}, err
	}
	cfg, err := s.store.GetKeyInterfaceTLSConfig(ctx, p.TenantID)
	if err != nil {
		return KeyInterfacePort{}, err
	}
	p = applyTLSConfigToPort(p, cfg)
	out, err := s.store.UpsertKeyInterfacePort(ctx, p)
	if err != nil {
		return KeyInterfacePort{}, err
	}
	_ = s.publishAudit(ctx, "audit.key.interface_port_upserted", out.TenantID, map[string]any{
		"interface_name": out.InterfaceName,
		"bind_address":   out.BindAddress,
		"port":           out.Port,
		"protocol":       out.Protocol,
		"cert_source":    out.CertSource,
		"ca_id":          out.CAID,
		"certificate_id": out.CertificateID,
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
