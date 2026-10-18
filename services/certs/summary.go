package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/route"
)

// Certificate counts for the dashboard (13.21.0-beta). The Command Center,
// Operations and Certificates pages each counted in the browser over a
// list the store caps at 500, with different filters, and showed 49, 500
// and 723 "expiring" for the same tenant. The service now counts the whole
// set once, and "expiring" is the expiry sweep's own rule.

// CertSummary is a tenant's certificates counted over the whole set.
type CertSummary struct {
	Total           int  `json:"total"`
	Active          int  `json:"active"`
	Revoked         int  `json:"revoked"`
	Expired         int  `json:"expired"`
	Expiring        int  `json:"expiring"`
	ExpiringWeek    int  `json:"expiring_7d"`
	AlertDays       int  `json:"alert_days"`
	IncludeExternal bool `json:"include_external"`
}

// certPageSize is the store's own per-call maximum.
const certPageSize = 500

// allCertificates pages through every certificate of a tenant matching
// status and class (empty for any). A single ListCertificates call is
// capped at 500, and asking for more returned 100: the expiry sweep,
// renewal intelligence, CA force delete and internal-certificate
// supersession saw only the newest 100 (13.21.0-beta). Collect first, then
// change: revoking while paging by offset would skip rows.
func (s *Service) allCertificates(ctx context.Context, tenantID, status, certClass string) ([]Certificate, error) {
	out := make([]Certificate, 0, certPageSize)
	for offset := 0; ; offset += certPageSize {
		page, err := s.store.ListCertificates(ctx, tenantID, status, certClass, certPageSize, offset)
		if err != nil {
			return nil, err
		}
		out = append(out, page...)
		if len(page) < certPageSize {
			return out, nil
		}
	}
}

// expiryDaysLeft reports whether a certificate is watched by the expiry
// alert policy and, if so, its whole days left. Revoked, deleted, expired
// and (unless the policy includes them) external certificates are not.
func expiryDaysLeft(cert Certificate, policy CertExpiryAlertPolicy, now time.Time) (int, bool) {
	status := strings.ToLower(strings.TrimSpace(cert.Status))
	if status != CertStatusActive {
		return 0, false
	}
	if !policy.IncludeExternal && strings.EqualFold(strings.TrimSpace(cert.CAID), "external-ca") {
		return 0, false
	}
	if now.After(cert.NotAfter.UTC()) {
		return 0, false
	}
	return int(cert.NotAfter.UTC().Sub(now).Hours() / 24), true
}

func (s *Service) CertSummary(ctx context.Context, tenantID string) (CertSummary, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return CertSummary{}, errors.New("tenant_id is required")
	}
	policy, err := s.GetCertExpiryAlertPolicy(ctx, tenantID)
	if err != nil {
		return CertSummary{}, err
	}
	all, err := s.allCertificates(ctx, tenantID, "", "")
	if err != nil {
		return CertSummary{}, err
	}
	out := CertSummary{Total: len(all), AlertDays: policy.DaysBefore, IncludeExternal: policy.IncludeExternal}
	now := time.Now().UTC()
	for _, cert := range all {
		switch strings.ToLower(strings.TrimSpace(cert.Status)) {
		case CertStatusActive:
			if now.After(cert.NotAfter.UTC()) {
				out.Expired++ // the sweep has not marked it yet
			} else {
				out.Active++
			}
		case CertStatusRevoked:
			out.Revoked++
		case CertStatusExpired:
			out.Expired++
		}
		if days, ok := expiryDaysLeft(cert, policy, now); ok {
			if days <= policy.DaysBefore {
				out.Expiring++
			}
			if days <= 7 {
				out.ExpiringWeek++
			}
		}
	}
	return out, nil
}

// RegisterSummaryRoutes adds GET /certs/summary. Reading it needs what
// listing certificates needs: a signed-in caller of the tenant.
func (h *Handler) RegisterSummaryRoutes(k *route.Router) {
	k.Handle("GET /certs/summary", route.Spec{
		Action: "summary_read", Permission: route.Authenticated, Resource: "certificate",
	}, h.handleSummary)
}

func (h *Handler) handleSummary(c *route.Call) {
	sum, err := h.svc.CertSummary(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "summary_unavailable", err.Error())
		return
	}
	c.Detail("total", sum.Total)
	c.Detail("expiring", sum.Expiring)
	c.JSON(http.StatusOK, map[string]interface{}{"summary": sum})
}
