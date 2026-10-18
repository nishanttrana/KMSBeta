package main

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Certificate lifetime policy (CLM): the longest lifetime the tenant allows
// for a TLS leaf certificate it issues. Every value is the tenant's own: a
// tenant that has saved no policy has none (mode off, no limit), and the
// product applies no external schedule or preset (CLAUDE.md, "The customer
// decides what to migrate and when"; 13.22.0-beta removed the CA/B Forum
// SC-081 schedule and the 47-day default). "enforce" shortens a longer
// lifetime to the limit at issuance, "warn" issues it unchanged and audits
// it, "off" does neither.

const (
	CLMModeOff     = "off"
	CLMModeWarn    = "warn"
	CLMModeEnforce = "enforce"
)

// maxCLMValidityDays only rejects nonsense input (a hundred years); it is
// not a recommended lifetime.
const maxCLMValidityDays = 36500

type CLMPolicy struct {
	TenantID        string    `json:"tenant_id"`
	Mode            string    `json:"mode"`
	MaxValidityDays int64     `json:"max_validity_days"`
	UpdatedBy       string    `json:"updated_by"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// CLMStatus counts the tenant's active TLS leaf certificates against its own
// limit. OverLimitCerts is nil when the tenant has set no limit.
type CLMStatus struct {
	Policy          CLMPolicy `json:"policy"`
	ActiveTLSCerts  int64     `json:"active_tls_certs"`
	OverLimitCerts  *int64    `json:"over_limit_certs,omitempty"`
	LongestValidity int64     `json:"longest_validity_days"`
}

func (s *Service) GetCLMPolicy(ctx context.Context, tenantID string) (CLMPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return CLMPolicy{}, errors.New("tenant_id is required")
	}
	p, found, err := s.store.GetCLMPolicy(ctx, tenantID)
	if err != nil {
		return CLMPolicy{}, err
	}
	if !found {
		return CLMPolicy{TenantID: tenantID, Mode: CLMModeOff}, nil
	}
	return p, nil
}

func (s *Service) UpsertCLMPolicy(ctx context.Context, p CLMPolicy) (CLMPolicy, error) {
	p.TenantID = strings.TrimSpace(p.TenantID)
	p.Mode = strings.ToLower(strings.TrimSpace(p.Mode))
	if p.TenantID == "" {
		return CLMPolicy{}, errors.New("tenant_id is required")
	}
	switch p.Mode {
	case CLMModeOff:
		if p.MaxValidityDays < 0 || p.MaxValidityDays > maxCLMValidityDays {
			return CLMPolicy{}, errors.New("max_validity_days must be between 0 and 36500")
		}
	case CLMModeWarn, CLMModeEnforce:
		if p.MaxValidityDays < 1 || p.MaxValidityDays > maxCLMValidityDays {
			return CLMPolicy{}, errors.New("max_validity_days must be between 1 and 36500 in warn or enforce mode")
		}
	default:
		return CLMPolicy{}, errors.New("mode must be off, warn or enforce")
	}
	if p.UpdatedBy == "" {
		p.UpdatedBy = "system"
	}
	p.UpdatedAt = time.Now().UTC()
	if err := s.store.UpsertCLMPolicy(ctx, p); err != nil {
		return CLMPolicy{}, err
	}
	_ = s.publishAudit(ctx, "audit.cert.clm_policy_updated", p.TenantID, map[string]interface{}{
		"mode":              p.Mode,
		"max_validity_days": p.MaxValidityDays,
		"updated_by":        p.UpdatedBy,
	})
	return p, nil
}

// effectiveMaxValidityDays is the tenant's limit in force, or 0 for none.
func effectiveMaxValidityDays(p CLMPolicy) int64 {
	if p.Mode == CLMModeOff {
		return 0
	}
	return p.MaxValidityDays
}

// clmAppliesTo limits the policy to TLS leaf certificates; CA certificates
// and other types are exempt.
func clmAppliesTo(certType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(certType)), "tls")
}

// enforceCLM applies the tenant's lifecycle policy to a proposed notAfter.
// In enforce mode the expiry is clamped to the cap; in warn mode the original
// expiry is kept. Both outcomes emit a rich audit event so reporting and
// governance can track SC-081 readiness.
func (s *Service) enforceCLM(ctx context.Context, tenantID string, certType string, now time.Time, notAfter time.Time) time.Time {
	if !clmAppliesTo(certType) {
		return notAfter
	}
	policy, err := s.GetCLMPolicy(ctx, tenantID)
	if err != nil {
		return notAfter
	}
	cap := effectiveMaxValidityDays(policy)
	if cap <= 0 {
		return notAfter
	}
	limit := now.Add(time.Duration(cap) * 24 * time.Hour)
	if !notAfter.After(limit) {
		return notAfter
	}
	requestedDays := int64(notAfter.Sub(now).Hours() / 24)
	detail := map[string]interface{}{
		"cert_type":         certType,
		"requested_days":    requestedDays,
		"max_validity_days": cap,
		"mode":              policy.Mode,
	}
	if policy.Mode == CLMModeEnforce {
		_ = s.publishAudit(ctx, "audit.cert.clm_validity_clamped", tenantID, detail)
		return limit
	}
	_ = s.publishAudit(ctx, "audit.cert.clm_validity_warning", tenantID, detail)
	return notAfter
}

func (s *Service) GetCLMStatus(ctx context.Context, tenantID string) (CLMStatus, error) {
	policy, err := s.GetCLMPolicy(ctx, tenantID)
	if err != nil {
		return CLMStatus{}, err
	}
	cap := effectiveMaxValidityDays(policy)
	total, over, longest, err := s.store.CertValidityStats(ctx, tenantID, cap)
	if err != nil {
		return CLMStatus{}, err
	}
	st := CLMStatus{Policy: policy, ActiveTLSCerts: total, LongestValidity: longest}
	if cap > 0 {
		st.OverLimitCerts = &over
	}
	return st, nil
}
