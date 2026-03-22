package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

func (s *Service) GetACMESTARSummary(ctx context.Context, tenantID string) (ACMESTARSummary, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ACMESTARSummary{}, errors.New("tenant_id is required")
	}
	options, err := s.acmeOptions(ctx, tenantID)
	if err != nil {
		return ACMESTARSummary{}, err
	}
	items, err := s.store.ListACMESTARSubscriptions(ctx, tenantID, 5000)
	if err != nil {
		return ACMESTARSummary{}, err
	}
	out := ACMESTARSummary{
		TenantID:              tenantID,
		Enabled:               options.EnableSTAR,
		DelegationEnabled:     options.AllowSTARDelegation,
		Subscriptions:         items,
		RecommendedWindowHint: "Use short-lived STAR certs for gateways, ephemeral agents, and mesh workloads that should renew continuously inside central policy.",
	}
	now := time.Now().UTC()
	groupCounts := map[string]int{}
	groupBounds := map[string][2]time.Time{}
	groupSubs := map[string][]string{}
	groupDelegates := map[string][]string{}
	for _, item := range items {
		out.SubscriptionCount++
		if item.AutoRenew {
			out.AutoRenewCount++
		}
		if strings.TrimSpace(item.DelegatedSubscriber) != "" {
			out.DelegatedCount++
		}
		if strings.TrimSpace(item.LastError) != "" || strings.EqualFold(item.Status, "error") {
			out.ErrorCount++
		}
		if !item.NextRenewalAt.IsZero() && item.NextRenewalAt.Before(now.Add(24*time.Hour)) {
			out.DueSoonCount++
		}
		group := defaultString(strings.TrimSpace(item.RolloutGroup), starRolloutGroup(item.NextRenewalAt, item.DelegatedSubscriber))
		groupCounts[group]++
		b := groupBounds[group]
		if b[0].IsZero() || (!item.NextRenewalAt.IsZero() && item.NextRenewalAt.Before(b[0])) {
			b[0] = item.NextRenewalAt
		}
		end := item.NextRenewalAt.Add(time.Duration(maxInt(item.RenewBeforeMinutes, 1)) * time.Minute)
		if end.After(b[1]) {
			b[1] = end
		}
		groupBounds[group] = b
		groupSubs[group] = append(groupSubs[group], item.ID)
		if delegated := strings.TrimSpace(item.DelegatedSubscriber); delegated != "" && !containsString(groupDelegates[group], delegated) {
			groupDelegates[group] = append(groupDelegates[group], delegated)
		}
	}
	for group, count := range groupCounts {
		if count < maxInt(options.STARMassRolloutThreshold, 1) {
			continue
		}
		risk := ACMESTARMassRolloutRisk{
			RolloutGroup:     group,
			Count:            count,
			RiskLevel:        "medium",
			ScheduledStart:   groupBounds[group][0],
			ScheduledEnd:     groupBounds[group][1],
			SubscriptionIDs:  groupSubs[group],
			DelegatedTargets: groupDelegates[group],
		}
		if count >= maxInt(options.STARMassRolloutThreshold*2, options.STARMassRolloutThreshold+1) {
			risk.RiskLevel = "high"
		}
		out.MassRolloutRisks = append(out.MassRolloutRisks, risk)
	}
	out.MassRolloutRiskCount = len(out.MassRolloutRisks)
	sort.Slice(out.Subscriptions, func(i, j int) bool {
		return out.Subscriptions[i].UpdatedAt.After(out.Subscriptions[j].UpdatedAt)
	})
	sort.Slice(out.MassRolloutRisks, func(i, j int) bool {
		return out.MassRolloutRisks[i].Count > out.MassRolloutRisks[j].Count
	})
	_ = s.publishAudit(ctx, "audit.cert.star_summary_viewed", tenantID, map[string]interface{}{
		"subscription_count":     out.SubscriptionCount,
		"delegated_count":        out.DelegatedCount,
		"mass_rollout_risk_count": out.MassRolloutRiskCount,
	})
	return out, nil
}

func (s *Service) CreateACMESTARSubscription(ctx context.Context, in CreateACMESTARSubscriptionRequest) (ACMESTARSubscription, error) {
	item, options, err := s.normalizeACMESTARSubscription(ctx, in)
	if err != nil {
		return ACMESTARSubscription{}, err
	}
	existing, err := s.store.ListACMESTARSubscriptions(ctx, item.TenantID, 5000)
	if err != nil {
		return ACMESTARSubscription{}, err
	}
	if len(existing) >= maxInt(options.MaxSTARSubscriptions, 1) {
		return ACMESTARSubscription{}, fmt.Errorf("star subscription limit reached for tenant")
	}
	issued, err := s.issueSTARCertificate(ctx, item)
	if err != nil {
		item.Status = "error"
		item.LastError = err.Error()
		item.UpdatedAt = time.Now().UTC()
		_ = s.store.UpsertACMESTARSubscription(ctx, item)
		return ACMESTARSubscription{}, err
	}
	item.LatestCertID = issued.ID
	item.IssuanceCount = 1
	item.Status = "active"
	item.LastIssuedAt = time.Now().UTC()
	item.NextRenewalAt = starNextRenewalAt(issued.NotAfter.UTC(), item.RenewBeforeMinutes)
	item.LastError = ""
	item.UpdatedAt = item.LastIssuedAt
	if err := s.store.UpsertACMESTARSubscription(ctx, item); err != nil {
		return ACMESTARSubscription{}, err
	}
	_ = s.RefreshTenantRenewalIntelligence(ctx, item.TenantID)
	_ = s.publishAudit(ctx, "audit.cert.star_subscription_created", item.TenantID, map[string]interface{}{
		"subscription_id":       item.ID,
		"ca_id":                 item.CAID,
		"subject_cn":            item.SubjectCN,
		"latest_cert_id":        item.LatestCertID,
		"delegated_subscriber":  item.DelegatedSubscriber,
		"validity_hours":        item.ValidityHours,
		"renew_before_minutes":  item.RenewBeforeMinutes,
	})
	if strings.TrimSpace(item.DelegatedSubscriber) != "" {
		_ = s.publishAudit(ctx, "audit.cert.star_delegation_configured", item.TenantID, map[string]interface{}{
			"subscription_id":      item.ID,
			"delegated_subscriber": item.DelegatedSubscriber,
		})
	}
	_ = s.detectSTARRolloutHotspots(ctx, item.TenantID, options)
	return item, nil
}

func (s *Service) RefreshACMESTARSubscription(ctx context.Context, in RefreshACMESTARSubscriptionRequest, id string) (ACMESTARSubscription, error) {
	tenantID := strings.TrimSpace(in.TenantID)
	if tenantID == "" {
		return ACMESTARSubscription{}, errors.New("tenant_id is required")
	}
	item, err := s.store.GetACMESTARSubscription(ctx, tenantID, id)
	if err != nil {
		return ACMESTARSubscription{}, err
	}
	if !in.Force && !item.AutoRenew {
		return item, nil
	}
	if !in.Force && !item.NextRenewalAt.IsZero() && item.NextRenewalAt.After(time.Now().UTC()) {
		return item, nil
	}
	issued, issueErr := s.issueSTARCertificate(ctx, item)
	now := time.Now().UTC()
	if issueErr != nil {
		item.Status = "error"
		item.LastError = issueErr.Error()
		item.UpdatedAt = now
		_ = s.store.UpsertACMESTARSubscription(ctx, item)
		return item, issueErr
	}
	item.LatestCertID = issued.ID
	item.IssuanceCount++
	item.Status = "active"
	item.LastIssuedAt = now
	item.NextRenewalAt = starNextRenewalAt(issued.NotAfter.UTC(), item.RenewBeforeMinutes)
	item.LastError = ""
	item.UpdatedAt = now
	if err := s.store.UpsertACMESTARSubscription(ctx, item); err != nil {
		return ACMESTARSubscription{}, err
	}
	_ = s.RefreshTenantRenewalIntelligence(ctx, item.TenantID)
	_ = s.publishAudit(ctx, "audit.cert.star_subscription_renewed", item.TenantID, map[string]interface{}{
		"subscription_id": item.ID,
		"latest_cert_id":  item.LatestCertID,
		"issuance_count":  item.IssuanceCount,
		"requested_by":    strings.TrimSpace(in.RequestedBy),
	})
	options, _ := s.acmeOptions(ctx, item.TenantID)
	_ = s.detectSTARRolloutHotspots(ctx, item.TenantID, options)
	return item, nil
}

func (s *Service) RefreshTenantSTARSubscriptions(ctx context.Context, tenantID string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return errors.New("tenant_id is required")
	}
	items, err := s.store.ListACMESTARSubscriptions(ctx, tenantID, 5000)
	if err != nil {
		return err
	}
	for _, item := range items {
		if !item.AutoRenew || item.NextRenewalAt.IsZero() || item.NextRenewalAt.After(time.Now().UTC()) {
			continue
		}
		if _, refreshErr := s.RefreshACMESTARSubscription(ctx, RefreshACMESTARSubscriptionRequest{
			TenantID: tenantID,
		}, item.ID); refreshErr != nil {
			_ = s.publishAudit(ctx, "audit.cert.star_subscription_failed", tenantID, map[string]interface{}{
				"subscription_id": item.ID,
				"reason":          refreshErr.Error(),
			})
		}
	}
	return nil
}

func (s *Service) issueSTARCertificate(ctx context.Context, item ACMESTARSubscription) (Certificate, error) {
	notAfter := time.Now().UTC().Add(time.Duration(item.ValidityHours) * time.Hour)
	out, _, err := s.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:     item.TenantID,
		CAID:         item.CAID,
		ProfileID:    strings.TrimSpace(item.ProfileID),
		CertType:     defaultString(item.CertType, "tls-server"),
		Algorithm:    item.Algorithm,
		CertClass:    defaultString(item.CertClass, "star"),
		SubjectCN:    item.SubjectCN,
		SANs:         item.SANs,
		ServerKeygen: true,
		NotAfter:     notAfter.Format(time.RFC3339),
		Protocol:     "acme-star",
		MetadataJSON: item.MetadataJSON,
	})
	return out, err
}

func (s *Service) normalizeACMESTARSubscription(ctx context.Context, in CreateACMESTARSubscriptionRequest) (ACMESTARSubscription, ACMEProtocolOptions, error) {
	tenantID := strings.TrimSpace(in.TenantID)
	if tenantID == "" {
		return ACMESTARSubscription{}, ACMEProtocolOptions{}, errors.New("tenant_id is required")
	}
	options, err := s.acmeOptions(ctx, tenantID)
	if err != nil {
		return ACMESTARSubscription{}, ACMEProtocolOptions{}, err
	}
	if !options.EnableSTAR {
		return ACMESTARSubscription{}, ACMEProtocolOptions{}, errors.New("acme star is disabled for this tenant")
	}
	item := ACMESTARSubscription{
		ID:                 newID("star"),
		TenantID:           tenantID,
		Name:               defaultString(strings.TrimSpace(in.Name), strings.TrimSpace(in.SubjectCN)),
		AccountID:          strings.TrimSpace(in.AccountID),
		CAID:               strings.TrimSpace(in.CAID),
		ProfileID:          strings.TrimSpace(in.ProfileID),
		SubjectCN:          strings.TrimSpace(in.SubjectCN),
		SANs:               uniqueStrings(in.SANs),
		CertType:           defaultString(strings.TrimSpace(in.CertType), "tls-server"),
		CertClass:          defaultString(strings.TrimSpace(in.CertClass), "star"),
		Algorithm:          strings.TrimSpace(in.Algorithm),
		ValidityHours:      in.ValidityHours,
		RenewBeforeMinutes: in.RenewBeforeMinutes,
		AutoRenew:          in.AutoRenew == nil || *in.AutoRenew,
		AllowDelegation:    in.AllowDelegation == nil || *in.AllowDelegation,
		DelegatedSubscriber: strings.TrimSpace(in.DelegatedSubscriber),
		RolloutGroup:       strings.TrimSpace(in.RolloutGroup),
		CreatedBy:          defaultString(strings.TrimSpace(in.CreatedBy), "system"),
		MetadataJSON:       mustJSON(in.Metadata),
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}
	if item.CAID == "" || item.SubjectCN == "" {
		return ACMESTARSubscription{}, ACMEProtocolOptions{}, errors.New("ca_id and subject_cn are required")
	}
	if item.ValidityHours <= 0 {
		item.ValidityHours = options.DefaultSTARValidityHours
	}
	if item.ValidityHours > options.MaxSTARValidityHours {
		return ACMESTARSubscription{}, ACMEProtocolOptions{}, fmt.Errorf("validity_hours exceeds tenant acme star maximum")
	}
	if item.RenewBeforeMinutes <= 0 {
		item.RenewBeforeMinutes = maxInt((item.ValidityHours*60)/4, 30)
	}
	if item.RenewBeforeMinutes >= item.ValidityHours*60 {
		item.RenewBeforeMinutes = maxInt((item.ValidityHours*60)/3, 30)
	}
	if strings.TrimSpace(item.DelegatedSubscriber) != "" && !options.AllowSTARDelegation {
		return ACMESTARSubscription{}, ACMEProtocolOptions{}, errors.New("star delegation is disabled for this tenant")
	}
	if item.Algorithm == "" && item.ProfileID != "" {
		if profile, profileErr := s.store.GetProfile(ctx, tenantID, item.ProfileID); profileErr == nil {
			item.Algorithm = profile.Algorithm
			item.CertType = defaultString(strings.TrimSpace(profile.CertType), item.CertType)
			item.CertClass = defaultString(strings.TrimSpace(profile.CertClass), item.CertClass)
		}
	}
	if item.Algorithm == "" {
		item.Algorithm = "ECDSA-P256"
	}
	if item.RolloutGroup == "" {
		item.RolloutGroup = starRolloutGroup(time.Now().UTC().Add(time.Duration(item.ValidityHours)*time.Hour), item.DelegatedSubscriber)
	}
	return item, options, nil
}

func (s *Service) detectSTARRolloutHotspots(ctx context.Context, tenantID string, options ACMEProtocolOptions) error {
	summary, err := s.GetACMESTARSummary(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, item := range summary.MassRolloutRisks {
		_ = s.publishAudit(ctx, "audit.cert.star_mass_rollout_risk_detected", tenantID, map[string]interface{}{
			"rollout_group":      item.RolloutGroup,
			"count":              item.Count,
			"risk_level":         item.RiskLevel,
			"subscription_ids":   item.SubscriptionIDs,
			"delegated_targets":  item.DelegatedTargets,
			"scheduled_start":    item.ScheduledStart.Format(time.RFC3339),
			"scheduled_end":      item.ScheduledEnd.Format(time.RFC3339),
			"threshold":          options.STARMassRolloutThreshold,
		})
	}
	return nil
}

func starNextRenewalAt(notAfter time.Time, renewBeforeMinutes int) time.Time {
	if notAfter.IsZero() {
		return time.Time{}
	}
	if renewBeforeMinutes <= 0 {
		renewBeforeMinutes = 30
	}
	return notAfter.Add(-time.Duration(renewBeforeMinutes) * time.Minute)
}

func starRolloutGroup(nextRenewalAt time.Time, delegated string) string {
	bucket := "local"
	if !nextRenewalAt.IsZero() {
		bucket = nextRenewalAt.UTC().Format("2006-01-02")
	}
	if strings.TrimSpace(delegated) != "" {
		return strings.TrimSpace(delegated) + ":" + bucket
	}
	return bucket
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func containsString(items []string, needle string) bool {
	needle = strings.TrimSpace(needle)
	if needle == "" {
		return false
	}
	for _, item := range items {
		if strings.TrimSpace(item) == needle {
			return true
		}
	}
	return false
}
