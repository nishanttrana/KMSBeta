package main

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Certificate Lifecycle Management (CLM): short-validity enforcement aligned
// with the CA/Browser Forum SC-081 schedule, which steps the maximum TLS
// certificate lifetime down to 47 days by March 2029. The policy is
// per-tenant; "enforce" clamps issuance, "warn" only audits, "off" disables.

const (
	CLMModeOff     = "off"
	CLMModeWarn    = "warn"
	CLMModeEnforce = "enforce"
)

type CLMPolicy struct {
	TenantID        string    `json:"tenant_id"`
	Mode            string    `json:"mode"`
	MaxValidityDays int64     `json:"max_validity_days"`
	ScheduleAware   bool      `json:"schedule_aware"`
	RenewBeforeDays int64     `json:"renew_before_days"`
	UpdatedBy       string    `json:"updated_by"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type CABMilestone struct {
	EffectiveFrom   string `json:"effective_from"`
	MaxValidityDays int64  `json:"max_validity_days"`
	Active          bool   `json:"active"`
}

type CLMStatus struct {
	Policy           CLMPolicy      `json:"policy"`
	EffectiveMaxDays int64          `json:"effective_max_days"`
	CABScheduleDays  int64          `json:"cab_schedule_days"`
	Milestones       []CABMilestone `json:"milestones"`
	ActiveTLSCerts   int64          `json:"active_tls_certs"`
	OverLimitCerts   int64          `json:"over_limit_certs"`
	LongestValidity  int64          `json:"longest_validity_days"`
}

func defaultCLMPolicy(tenantID string) CLMPolicy {
	return CLMPolicy{
		TenantID:        tenantID,
		Mode:            CLMModeWarn,
		MaxValidityDays: 47,
		ScheduleAware:   true,
		RenewBeforeDays: 15,
	}
}

var cabMilestones = []struct {
	from time.Time
	days int64
}{
	{time.Date(2029, 3, 15, 0, 0, 0, 0, time.UTC), 47},
	{time.Date(2027, 3, 15, 0, 0, 0, 0, time.UTC), 100},
	{time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), 200},
	{time.Time{}, 398},
}

// cabForumMaxValidityDays returns the CA/B Forum SC-081 maximum TLS leaf
// certificate lifetime in effect at t.
func cabForumMaxValidityDays(t time.Time) int64 {
	for _, m := range cabMilestones {
		if !t.Before(m.from) {
			return m.days
		}
	}
	return 398
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
		return defaultCLMPolicy(tenantID), nil
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
	case CLMModeOff, CLMModeWarn, CLMModeEnforce:
	default:
		return CLMPolicy{}, errors.New("mode must be off, warn or enforce")
	}
	if p.MaxValidityDays < 1 || p.MaxValidityDays > 398 {
		return CLMPolicy{}, errors.New("max_validity_days must be between 1 and 398")
	}
	if p.RenewBeforeDays < 0 || p.RenewBeforeDays >= p.MaxValidityDays {
		return CLMPolicy{}, errors.New("renew_before_days must be non-negative and below max_validity_days")
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
		"schedule_aware":    p.ScheduleAware,
		"renew_before_days": p.RenewBeforeDays,
		"updated_by":        p.UpdatedBy,
	})
	return p, nil
}

// effectiveMaxValidityDays resolves the cap in force for a tenant now: the
// stricter of the tenant policy and (if schedule-aware) the CA/B schedule.
// Returns 0 when no cap applies.
func effectiveMaxValidityDays(p CLMPolicy, now time.Time) int64 {
	if p.Mode == CLMModeOff {
		return 0
	}
	cap := p.MaxValidityDays
	if p.ScheduleAware {
		if cab := cabForumMaxValidityDays(now); cap == 0 || cab < cap {
			cap = cab
		}
	}
	return cap
}

// clmAppliesTo limits lifecycle caps to TLS leaf certificates, matching the
// scope of the CA/B Forum ballot. CA certs and non-TLS types are exempt.
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
	cap := effectiveMaxValidityDays(policy, now)
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
		"schedule_aware":    policy.ScheduleAware,
		"cab_schedule_days": cabForumMaxValidityDays(now),
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
	now := time.Now().UTC()
	cap := effectiveMaxValidityDays(policy, now)
	statsCap := cap
	if statsCap <= 0 {
		statsCap = cabForumMaxValidityDays(now)
	}
	total, over, longest, err := s.store.CertValidityStats(ctx, tenantID, statsCap)
	if err != nil {
		return CLMStatus{}, err
	}
	milestones := make([]CABMilestone, 0, len(cabMilestones))
	active := cabForumMaxValidityDays(now)
	for i := len(cabMilestones) - 1; i >= 0; i-- {
		m := cabMilestones[i]
		from := "baseline"
		if !m.from.IsZero() {
			from = m.from.Format("2006-01-02")
		}
		milestones = append(milestones, CABMilestone{
			EffectiveFrom:   from,
			MaxValidityDays: m.days,
			Active:          m.days == active,
		})
	}
	return CLMStatus{
		Policy:           policy,
		EffectiveMaxDays: cap,
		CABScheduleDays:  active,
		Milestones:       milestones,
		ActiveTLSCerts:   total,
		OverLimitCerts:   over,
		LongestValidity:  longest,
	}, nil
}
