package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	defaultARIPollHours                 = 24
	defaultARIWindowBiasPercent         = 35
	defaultEmergencyRotationThresholdHr = 48
	defaultMassRenewalRiskThreshold     = 8
	certRenewalRFCURL                   = "https://www.rfc-editor.org/rfc/rfc9773"
)

func (s *Service) GetRenewalInfo(ctx context.Context, tenantID string, certID string) (CertRenewalInfo, error) {
	tenantID = strings.TrimSpace(tenantID)
	certID = strings.TrimSpace(certID)
	if tenantID == "" || certID == "" {
		return CertRenewalInfo{}, errors.New("tenant_id and cert_id are required")
	}
	item, err := s.store.GetCertRenewalInfo(ctx, tenantID, certID)
	if errors.Is(err, errStoreNotFound) {
		if refreshErr := s.RefreshTenantRenewalIntelligence(ctx, tenantID); refreshErr != nil {
			return CertRenewalInfo{}, refreshErr
		}
		return s.store.GetCertRenewalInfo(ctx, tenantID, certID)
	}
	return item, err
}

func (s *Service) GetRenewalInfoByARIID(ctx context.Context, tenantID string, ariID string) (CertRenewalInfo, error) {
	tenantID = strings.TrimSpace(tenantID)
	ariID = strings.TrimSpace(ariID)
	if tenantID == "" || ariID == "" {
		return CertRenewalInfo{}, errors.New("tenant_id and ari_id are required")
	}
	item, err := s.store.GetCertRenewalInfoByARIID(ctx, tenantID, ariID)
	if errors.Is(err, errStoreNotFound) {
		if refreshErr := s.RefreshTenantRenewalIntelligence(ctx, tenantID); refreshErr != nil {
			return CertRenewalInfo{}, refreshErr
		}
		return s.store.GetCertRenewalInfoByARIID(ctx, tenantID, ariID)
	}
	return item, err
}

func (s *Service) GetRenewalSummary(ctx context.Context, tenantID string) (CertRenewalSummary, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return CertRenewalSummary{}, errors.New("tenant_id is required")
	}
	items, err := s.store.ListCertRenewalInfo(ctx, tenantID, 5000)
	if err != nil {
		return CertRenewalSummary{}, err
	}
	if len(items) == 0 {
		if refreshErr := s.RefreshTenantRenewalIntelligence(ctx, tenantID); refreshErr != nil {
			return CertRenewalSummary{}, refreshErr
		}
		items, err = s.store.ListCertRenewalInfo(ctx, tenantID, 5000)
		if err != nil {
			return CertRenewalSummary{}, err
		}
	}
	options, _ := s.acmeOptions(ctx, tenantID)
	out := buildCertRenewalSummary(tenantID, items, options)
	if star, err := s.GetACMESTARSummary(ctx, tenantID); err == nil {
		out.STARSubscriptionCount = star.SubscriptionCount
		out.STARDelegatedCount = star.DelegatedCount
		out.STARDueSoonCount = star.DueSoonCount
		out.STARMassRolloutRiskCount = star.MassRolloutRiskCount
	}
	return out, nil
}

func (s *Service) RefreshTenantRenewalIntelligence(ctx context.Context, tenantID string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return errors.New("tenant_id is required")
	}
	options, err := s.acmeOptions(ctx, tenantID)
	if err != nil {
		return err
	}
	certs, err := s.store.ListCertificates(ctx, tenantID, "", "", 5000, 0)
	if err != nil {
		return err
	}
	cas, err := s.store.ListCAs(ctx, tenantID)
	if err != nil {
		return err
	}
	existing, err := s.store.ListCertRenewalInfo(ctx, tenantID, 5000)
	if err != nil {
		return err
	}
	caNames := make(map[string]string, len(cas))
	for _, ca := range cas {
		caNames[strings.TrimSpace(ca.ID)] = defaultString(strings.TrimSpace(ca.Name), strings.TrimSpace(ca.ID))
	}
	existingByCert := make(map[string]CertRenewalInfo, len(existing))
	for _, item := range existing {
		existingByCert[strings.TrimSpace(item.CertID)] = item
	}
	now := time.Now().UTC()
	active := make([]CertRenewalInfo, 0, len(certs))
	activeIDs := make(map[string]struct{}, len(certs))
	for _, cert := range certs {
		certID := strings.TrimSpace(cert.ID)
		if certID == "" {
			continue
		}
		status := strings.ToLower(strings.TrimSpace(cert.Status))
		if status == CertStatusDeleted || status == CertStatusRevoked || cert.NotAfter.IsZero() {
			_ = s.store.DeleteCertRenewalInfo(ctx, tenantID, certID)
			continue
		}
		if now.After(cert.NotAfter.UTC()) {
			_ = s.store.DeleteCertRenewalInfo(ctx, tenantID, certID)
			continue
		}
		info := buildCertRenewalInfo(cert, caNames[cert.CAID], options, now)
		active = append(active, info)
		activeIDs[certID] = struct{}{}
	}
	bucketCounts := make(map[string]int)
	bucketBounds := make(map[string][2]time.Time)
	bucketCerts := make(map[string][]string)
	for _, item := range active {
		bucketCounts[item.MassRenewalBucket]++
		bound := bucketBounds[item.MassRenewalBucket]
		if bound[0].IsZero() || item.WindowStart.Before(bound[0]) {
			bound[0] = item.WindowStart
		}
		if item.WindowEnd.After(bound[1]) {
			bound[1] = item.WindowEnd
		}
		bucketBounds[item.MassRenewalBucket] = bound
		bucketCerts[item.MassRenewalBucket] = append(bucketCerts[item.MassRenewalBucket], item.CertID)
	}

	massThreshold := options.MassRenewalRiskThreshold
	if massThreshold <= 0 {
		massThreshold = defaultMassRenewalRiskThreshold
	}
	publishedBuckets := make(map[string]struct{})
	for i := range active {
		item := &active[i]
		old := existingByCert[item.CertID]
		count := bucketCounts[item.MassRenewalBucket]
		if count >= massThreshold && riskSeverityWeight(item.RiskLevel) < riskSeverityWeight("medium") {
			item.RiskLevel = "medium"
			item.RenewalState = "mass_renewal_risk"
			if _, ok := publishedBuckets[item.MassRenewalBucket]; !ok && riskSeverityWeight(old.RiskLevel) < riskSeverityWeight("medium") {
				bound := bucketBounds[item.MassRenewalBucket]
				_ = s.publishAudit(ctx, "audit.cert.mass_renewal_risk_detected", tenantID, map[string]interface{}{
					"target_id":        item.CAID,
					"ca_id":            item.CAID,
					"ca_name":          item.CAName,
					"bucket":           item.MassRenewalBucket,
					"count":            count,
					"cert_ids":         bucketCerts[item.MassRenewalBucket],
					"scheduled_start":  bound[0].UTC().Format(time.RFC3339),
					"scheduled_end":    bound[1].UTC().Format(time.RFC3339),
					"description":      fmt.Sprintf("Mass renewal hotspot detected for %s on %s (%d certificates)", defaultString(item.CAName, item.CAID), item.MassRenewalBucket, count),
				})
				publishedBuckets[item.MassRenewalBucket] = struct{}{}
			}
		}
		if old.MissedWindowAt.IsZero() && !item.MissedWindowAt.IsZero() {
			_ = s.publishAudit(ctx, "audit.cert.renewal_window_missed", tenantID, map[string]interface{}{
				"target_id":       item.CertID,
				"cert_id":         item.CertID,
				"subject_cn":      item.SubjectCN,
				"window_start":    item.WindowStart.UTC().Format(time.RFC3339),
				"window_end":      item.WindowEnd.UTC().Format(time.RFC3339),
				"scheduled_at":    item.ScheduledRenewalAt.UTC().Format(time.RFC3339),
				"description":     fmt.Sprintf("Certificate %s missed its coordinated renewal window", defaultString(item.SubjectCN, item.CertID)),
			})
		}
		if old.EmergencyRotationAt.IsZero() && !item.EmergencyRotationAt.IsZero() {
			_ = s.publishAudit(ctx, "audit.cert.emergency_rotation_started", tenantID, map[string]interface{}{
				"target_id":       item.CertID,
				"cert_id":         item.CertID,
				"subject_cn":      item.SubjectCN,
				"not_after":       item.NotAfter.UTC().Format(time.RFC3339),
				"description":     fmt.Sprintf("Certificate %s entered emergency rotation state", defaultString(item.SubjectCN, item.CertID)),
			})
		}
		if err := s.store.UpsertCertRenewalInfo(ctx, *item); err != nil {
			return err
		}
	}
	for certID := range existingByCert {
		if _, ok := activeIDs[certID]; !ok {
			_ = s.store.DeleteCertRenewalInfo(ctx, tenantID, certID)
		}
	}
	return nil
}

func buildCertRenewalSummary(tenantID string, items []CertRenewalInfo, options ACMEProtocolOptions) CertRenewalSummary {
	sort.Slice(items, func(i, j int) bool {
		return items[i].ScheduledRenewalAt.Before(items[j].ScheduledRenewalAt)
	})
	scheduleMap := make(map[string]*CertRenewalScheduleEntry)
	out := CertRenewalSummary{
		TenantID:             tenantID,
		ARIEnabled:           options.EnableARI,
		RecommendedPollHours: options.ARIPollHours,
		RenewalWindows:       items,
	}
	now := time.Now().UTC()
	for _, item := range items {
		if !item.MissedWindowAt.IsZero() {
			out.MissedWindowCount++
		}
		if !item.EmergencyRotationAt.IsZero() {
			out.EmergencyRotationCount++
		}
		if !item.ScheduledRenewalAt.IsZero() && item.ScheduledRenewalAt.Before(now.Add(72*time.Hour)) {
			out.DueSoonCount++
		}
		if riskSeverityWeight(item.RiskLevel) >= riskSeverityWeight("medium") {
			out.NonCompliantCount++
		}
		entry := scheduleMap[item.MassRenewalBucket]
		if entry == nil {
			entry = &CertRenewalScheduleEntry{
				Bucket:         item.MassRenewalBucket,
				CAID:           item.CAID,
				CAName:         item.CAName,
				RiskLevel:      item.RiskLevel,
				ScheduledStart: item.WindowStart,
				ScheduledEnd:   item.WindowEnd,
			}
			scheduleMap[item.MassRenewalBucket] = entry
		}
		entry.Count++
		entry.CertIDs = append(entry.CertIDs, item.CertID)
		if entry.ScheduledStart.IsZero() || item.WindowStart.Before(entry.ScheduledStart) {
			entry.ScheduledStart = item.WindowStart
		}
		if item.WindowEnd.After(entry.ScheduledEnd) {
			entry.ScheduledEnd = item.WindowEnd
		}
		if riskSeverityWeight(item.RiskLevel) > riskSeverityWeight(entry.RiskLevel) {
			entry.RiskLevel = item.RiskLevel
		}
	}
	for _, entry := range scheduleMap {
		out.CADirectedSchedule = append(out.CADirectedSchedule, *entry)
		if riskSeverityWeight(entry.RiskLevel) >= riskSeverityWeight("medium") {
			out.MassRenewalRisks = append(out.MassRenewalRisks, *entry)
		}
	}
	sort.Slice(out.CADirectedSchedule, func(i, j int) bool {
		return out.CADirectedSchedule[i].ScheduledStart.Before(out.CADirectedSchedule[j].ScheduledStart)
	})
	sort.Slice(out.MassRenewalRisks, func(i, j int) bool {
		return out.MassRenewalRisks[i].Count > out.MassRenewalRisks[j].Count
	})
	return out
}

func buildCertRenewalInfo(cert Certificate, caName string, options ACMEProtocolOptions, now time.Time) CertRenewalInfo {
	hash := renewalHash(cert)
	ariID := "ari_" + hash[:24]
	totalLifetime := cert.NotAfter.UTC().Sub(cert.NotBefore.UTC())
	if totalLifetime <= 0 {
		totalLifetime = 90 * 24 * time.Hour
	}
	biasPercent := options.ARIWindowBiasPercent
	if biasPercent <= 0 {
		biasPercent = defaultARIWindowBiasPercent
	}
	baseLead := time.Duration(float64(totalLifetime) * (float64(biasPercent) / 100.0))
	if baseLead < 24*time.Hour {
		baseLead = 24 * time.Hour
	}
	spreadSpan := totalLifetime / 8
	if spreadSpan < 24*time.Hour {
		spreadSpan = 24 * time.Hour
	}
	if spreadSpan > 7*24*time.Hour {
		spreadSpan = 7 * 24 * time.Hour
	}
	windowDuration := totalLifetime / 60
	if windowDuration < 4*time.Hour {
		windowDuration = 4 * time.Hour
	}
	if windowDuration > 24*time.Hour {
		windowDuration = 24 * time.Hour
	}
	baseStart := cert.NotAfter.UTC().Add(-baseLead)
	offsetRange := spreadSpan - windowDuration
	if offsetRange < 0 {
		offsetRange = 0
	}
	offset := renewalOffset(hash, offsetRange)
	windowStart := baseStart.Add(offset)
	windowEnd := windowStart.Add(windowDuration)
	scheduled := windowStart.Add(windowDuration / 2)
	pollHours := options.ARIPollHours
	if pollHours <= 0 {
		pollHours = defaultARIPollHours
	}
	retryAfter := pollHours * 3600
	emergencyHours := options.EmergencyRotationThresholdHours
	if emergencyHours <= 0 {
		emergencyHours = defaultEmergencyRotationThresholdHr
	}
	state := "scheduled"
	risk := "low"
	var missedWindowAt time.Time
	var emergencyAt time.Time
	switch {
	case now.After(cert.NotAfter.UTC().Add(-time.Duration(emergencyHours) * time.Hour)):
		state = "emergency_rotation"
		risk = "critical"
		emergencyAt = now
	case now.After(windowEnd):
		state = "missed_window"
		risk = "high"
		missedWindowAt = now
	case now.After(windowStart):
		state = "window_open"
		risk = "medium"
	case scheduled.Before(now.Add(72 * time.Hour)):
		state = "due_soon"
		risk = "medium"
	}
	meta := map[string]interface{}{
		"rfc":                            "9773",
		"certificate_serial":            cert.SerialNumber,
		"window_duration_hours":         int(windowDuration / time.Hour),
		"ca_directed_schedule_bucket":   scheduled.Format("2006-01-02"),
		"mass_renewal_threshold":        options.MassRenewalRiskThreshold,
		"ari_enabled":                   options.EnableARI,
	}
	return CertRenewalInfo{
		TenantID:            cert.TenantID,
		CertID:              cert.ID,
		ARIID:               ariID,
		CAID:                cert.CAID,
		CAName:              defaultString(caName, cert.CAID),
		SubjectCN:           defaultString(cert.SubjectCN, cert.ID),
		Protocol:            defaultString(cert.Protocol, "rest"),
		NotAfter:            cert.NotAfter.UTC(),
		WindowStart:         windowStart.UTC(),
		WindowEnd:           windowEnd.UTC(),
		ScheduledRenewalAt:  scheduled.UTC(),
		ExplanationURL:      certRenewalRFCURL,
		RetryAfterSeconds:   retryAfter,
		NextPollAt:          now.Add(time.Duration(pollHours) * time.Hour).UTC(),
		RenewalState:        state,
		RiskLevel:           risk,
		MissedWindowAt:      missedWindowAt.UTC(),
		EmergencyRotationAt: emergencyAt.UTC(),
		MassRenewalBucket:   scheduled.UTC().Format("2006-01-02"),
		WindowSource:        renewalWindowSource(options.EnableARI),
		MetadataJSON:        marshalRenewalMetadata(meta),
	}
}

func renewalHash(cert Certificate) string {
	raw := sha256.Sum256([]byte(strings.Join([]string{
		strings.TrimSpace(cert.TenantID),
		strings.TrimSpace(cert.ID),
		strings.TrimSpace(cert.SerialNumber),
		strings.TrimSpace(cert.SubjectCN),
	}, "|")))
	return hex.EncodeToString(raw[:])
}

func renewalOffset(hash string, max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	if len(hash) < 8 {
		return 0
	}
	raw, err := hex.DecodeString(hash[:8])
	if err != nil || len(raw) != 4 {
		return 0
	}
	value := int64(raw[0])<<24 | int64(raw[1])<<16 | int64(raw[2])<<8 | int64(raw[3])
	return time.Duration(value%int64(max.Seconds()+1)) * time.Second
}

func renewalWindowSource(ariEnabled bool) string {
	if ariEnabled {
		return "rfc9773_ari"
	}
	return "coordinated_local_policy"
}

func riskSeverityWeight(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium", "amber":
		return 2
	case "low", "info":
		return 1
	default:
		return 0
	}
}

func (s *Service) ACMERenewalInfo(ctx context.Context, tenantID string, certOrARIID string) (CertRenewalInfo, error) {
	item, err := s.GetRenewalInfo(ctx, tenantID, certOrARIID)
	if err == nil {
		return item, nil
	}
	if !errors.Is(err, errStoreNotFound) {
		return CertRenewalInfo{}, err
	}
	return s.GetRenewalInfoByARIID(ctx, tenantID, certOrARIID)
}

func (i CertRenewalInfo) RFCRenewalInfo() ACMERenewalInfoResponse {
	return ACMERenewalInfoResponse{
		SuggestedWindow: ACMERenewalWindow{
			Start: i.WindowStart.UTC().Format(time.RFC3339),
			End:   i.WindowEnd.UTC().Format(time.RFC3339),
		},
		ExplanationURL: i.ExplanationURL,
	}
}

func (i CertRenewalInfo) Metadata() map[string]interface{} {
	out := map[string]interface{}{}
	_ = json.Unmarshal([]byte(defaultString(i.MetadataJSON, "{}")), &out)
	return out
}
