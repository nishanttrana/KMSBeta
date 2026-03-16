package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

type Service struct {
	store   Store
	keycore KeyCoreClient
	policy  PolicyClient
	audit   AuditClient
	certs   CertsClient
	events  EventPublisher
}

func NewService(store Store, keycore KeyCoreClient, policy PolicyClient, audit AuditClient, certs CertsClient, events EventPublisher) *Service {
	return &Service{
		store:   store,
		keycore: keycore,
		policy:  policy,
		audit:   audit,
		certs:   certs,
		events:  events,
	}
}

func (s *Service) GetPosture(ctx context.Context, tenantID string, refresh bool) (PostureSnapshot, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return PostureSnapshot{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if refresh {
		return s.RecomputePosture(ctx, tenantID)
	}
	item, err := s.store.GetLatestPosture(ctx, tenantID)
	if err == nil {
		return item, nil
	}
	return s.RecomputePosture(ctx, tenantID)
}

func (s *Service) RecomputePosture(ctx context.Context, tenantID string) (PostureSnapshot, error) {
	keys, _ := s.fetchKeys(ctx, tenantID)
	certs, _ := s.fetchCerts(ctx, tenantID)
	policies, _ := s.fetchPolicies(ctx, tenantID)
	events, _ := s.fetchEvents(ctx, tenantID, 500)
	alertStats, _ := s.fetchAlertStats(ctx, tenantID)

	hygieneReport, keyHygieneScore := computeKeyHygiene(keys, policies)
	certReport, certScore, certMetrics := computeCertHygiene(certs)
	keyHygieneScore = clampScore(int(0.75*float64(keyHygieneScore) + 0.25*float64(certScore)))
	policyScore, policyMetrics := computePolicyCompliance(keys, policies, events, alertStats)
	accessScore, accessMetrics := computeAccessSecurity(events, alertStats)
	cryptoScore, pqcReadiness, qslAvg, cryptoMetrics := computeCryptoPosture(keys)
	cryptoScore = clampScore(int(0.80*float64(cryptoScore) + 0.20*float64(certScore)))

	overall := clampScore((keyHygieneScore + policyScore + accessScore + cryptoScore) / 4)
	frameworkAssessments := s.assessFrameworks(tenantID, keyHygieneScore, policyScore, accessScore, cryptoScore, pqcReadiness, qslAvg)

	frameworkScores := map[string]int{}
	totalGaps := 0
	for _, a := range frameworkAssessments {
		frameworkScores[a.FrameworkID] = a.Score
		totalGaps += len(a.Gaps)
	}

	metrics := map[string]float64{
		"approved_algorithm_pct": hygieneReport.ApprovedAlgorithmPct,
		"rotation_coverage_pct":  hygieneReport.RotationCoveragePct,
		"policy_coverage_pct":    hygieneReport.PolicyCoveragePct,
		"orphaned_count":         float64(hygieneReport.OrphanedCount),
		"deprecated_count":       float64(hygieneReport.DeprecatedCount),
		"mfa_adoption_pct":       accessMetrics["mfa_adoption_pct"],
		"failed_auth_rate_pct":   accessMetrics["failed_auth_rate_pct"],
		"policy_violation_count": policyMetrics["policy_violation_count"],
		"qsl_avg":                qslAvg,
		"pqc_ready_pct":          cryptoMetrics["pqc_ready_pct"],
		"cert_total":             float64(certReport.TotalCerts),
		"cert_active":            float64(certReport.ActiveCount),
		"cert_revoked":           float64(certReport.RevokedCount),
		"cert_expired":           float64(certReport.ExpiredCount),
		"cert_expiring_30d":      float64(certReport.Expiring30Days),
		"cert_weak_algorithms":   float64(certReport.WeakAlgorithmCount),
		"cert_pqc_class_pct":     certReport.PQCClassPct,
	}
	for k, v := range certMetrics {
		metrics[k] = v
	}

	prev, _ := s.store.GetLatestPosture(ctx, tenantID)
	snapshot := PostureSnapshot{
		ID:               newID("posture"),
		TenantID:         tenantID,
		OverallScore:     overall,
		KeyHygiene:       keyHygieneScore,
		PolicyCompliance: policyScore,
		AccessSecurity:   accessScore,
		CryptoPosture:    cryptoScore,
		PQCReadiness:     pqcReadiness,
		FrameworkScores:  frameworkScores,
		Metrics:          metrics,
		GapCount:         totalGaps,
	}
	if err := s.store.CreatePostureSnapshot(ctx, snapshot); err != nil {
		return PostureSnapshot{}, err
	}
	snapshot, _ = s.store.GetLatestPosture(ctx, tenantID)

	for _, item := range frameworkAssessments {
		item.TenantID = tenantID
		item.Gaps = withTenantGaps(tenantID, item.FrameworkID, item.Gaps)
		if err := s.store.UpsertFrameworkAssessment(ctx, item); err != nil {
			return PostureSnapshot{}, err
		}
		if err := s.store.ReplaceFrameworkGaps(ctx, tenantID, item.FrameworkID, item.Gaps); err != nil {
			return PostureSnapshot{}, err
		}
		_ = s.publishAudit(ctx, "audit.compliance.framework_assessed", tenantID, map[string]interface{}{
			"framework_id": item.FrameworkID,
			"score":        item.Score,
			"gap_count":    len(item.Gaps),
		})
	}

	_ = s.publishAudit(ctx, "audit.compliance.posture_calculated", tenantID, map[string]interface{}{
		"overall_score": snapshot.OverallScore,
		"gap_count":     snapshot.GapCount,
	})
	if !prev.CreatedAt.IsZero() && prev.OverallScore != snapshot.OverallScore {
		_ = s.publishAudit(ctx, "audit.compliance.posture_changed", tenantID, map[string]interface{}{
			"from":  prev.OverallScore,
			"to":    snapshot.OverallScore,
			"delta": snapshot.OverallScore - prev.OverallScore,
		})
	}
	return snapshot, nil
}

func (s *Service) GetPostureHistory(ctx context.Context, tenantID string, limit int) ([]PostureSnapshot, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	items, err := s.store.ListPostureHistory(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		item, err := s.RecomputePosture(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		items = []PostureSnapshot{item}
	}
	return items, nil
}

func (s *Service) GetPostureBreakdown(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	item, err := s.GetPosture(ctx, tenantID, false)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"overall_score": item.OverallScore,
		"categories": map[string]int{
			"key_hygiene":       item.KeyHygiene,
			"policy_compliance": item.PolicyCompliance,
			"access_security":   item.AccessSecurity,
			"crypto_posture":    item.CryptoPosture,
		},
		"framework_scores": item.FrameworkScores,
		"metrics":          item.Metrics,
		"gap_count":        item.GapCount,
		"pqc_readiness":    item.PQCReadiness,
		"calculated_at":    item.CreatedAt,
	}, nil
}

func (s *Service) StartScheduler(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = s.RunDueSchedules(context.Background())
			}
		}
	}()
}

func (s *Service) GetLatestAssessment(ctx context.Context, tenantID string, templateID string) (AssessmentResult, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return AssessmentResult{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	templateID = normalizeTemplateID(templateID)
	items, err := s.store.ListAssessmentRuns(ctx, tenantID, templateID, 20)
	if err != nil {
		return AssessmentResult{}, err
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Trigger), "auto") {
			continue
		}
		return item, nil
	}
	return AssessmentResult{}, newServiceError(http.StatusNotFound, "not_found", "compliance assessment has not been run yet")
}

func (s *Service) ListAssessmentRuns(ctx context.Context, tenantID string, templateID string, limit int) ([]AssessmentResult, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	templateID = normalizeTemplateID(templateID)
	return s.store.ListAssessmentRuns(ctx, tenantID, templateID, limit)
}

func (s *Service) RunAssessment(ctx context.Context, tenantID string, trigger string, recompute bool, templateID string) (AssessmentResult, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return AssessmentResult{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	trigger = strings.ToLower(strings.TrimSpace(trigger))
	if trigger == "" {
		trigger = "manual"
	}

	posture, err := s.GetPosture(ctx, tenantID, recompute)
	if err != nil {
		return AssessmentResult{}, err
	}
	templateID = normalizeTemplateID(templateID)
	templateName := "Built-in Baseline"
	frameworkScores := posture.FrameworkScores
	overallScore := posture.OverallScore
	template, err := s.resolveComplianceTemplate(ctx, tenantID, templateID)
	if err != nil {
		return AssessmentResult{}, err
	}
	if template != nil {
		templateName = template.Name
		frameworkScores, overallScore = scoreFromComplianceTemplate(*template, posture)
	}
	keys, _ := s.fetchKeys(ctx, tenantID)
	certs, _ := s.fetchCerts(ctx, tenantID)

	_, _, certMetrics := computeCertHygiene(certs)
	findings := buildAssessmentFindings(keys, certs, posture)
	pqc := summarizeAssessmentPQC(keys)

	out := AssessmentResult{
		ID:              newID("assess"),
		TenantID:        tenantID,
		Trigger:         trigger,
		TemplateID:      templateID,
		TemplateName:    templateName,
		OverallScore:    overallScore,
		FrameworkScores: frameworkScores,
		Findings:        findings,
		PQC:             pqc,
		CertMetrics:     certMetrics,
		Posture:         posture,
	}
	if err := s.store.CreateAssessmentRun(ctx, out); err != nil {
		return AssessmentResult{}, err
	}
	items, err := s.store.ListAssessmentRuns(ctx, tenantID, templateID, 1)
	if err == nil && len(items) > 0 {
		out = items[0]
	}
	_ = s.publishAudit(ctx, "audit.compliance.assessment_run", tenantID, map[string]interface{}{
		"assessment_id": out.ID,
		"trigger":       trigger,
		"template_id":   out.TemplateID,
		"template_name": out.TemplateName,
		"overall_score": out.OverallScore,
		"finding_count": len(out.Findings),
	})
	return out, nil
}

func (s *Service) GetAssessmentSchedule(ctx context.Context, tenantID string) (AssessmentSchedule, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return AssessmentSchedule{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	item, err := s.store.GetAssessmentSchedule(ctx, tenantID)
	if err != nil {
		return AssessmentSchedule{}, err
	}
	item.Frequency = normalizeAssessmentFrequency(item.Frequency)
	return item, nil
}

func (s *Service) UpsertAssessmentSchedule(ctx context.Context, req AssessmentSchedule) (AssessmentSchedule, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		return AssessmentSchedule{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	req.Frequency = normalizeAssessmentFrequency(req.Frequency)

	current, err := s.store.GetAssessmentSchedule(ctx, req.TenantID)
	if err != nil {
		return AssessmentSchedule{}, err
	}
	current.Enabled = req.Enabled
	current.Frequency = req.Frequency
	if current.Enabled {
		base := current.LastRunAt
		if base.IsZero() {
			base = time.Now().UTC()
		}
		current.NextRunAt = nextAssessmentRunTime(base, current.Frequency)
	} else {
		current.NextRunAt = time.Time{}
	}
	if err := s.store.UpsertAssessmentSchedule(ctx, current); err != nil {
		return AssessmentSchedule{}, err
	}
	updated, err := s.store.GetAssessmentSchedule(ctx, req.TenantID)
	if err != nil {
		return AssessmentSchedule{}, err
	}
	_ = s.publishAudit(ctx, "audit.compliance.assessment_schedule_updated", req.TenantID, map[string]interface{}{
		"enabled":   updated.Enabled,
		"frequency": updated.Frequency,
		"next_run":  updated.NextRunAt,
	})
	return updated, nil
}

func (s *Service) RunDueSchedules(ctx context.Context) error {
	now := time.Now().UTC()
	items, err := s.store.ListDueAssessmentSchedules(ctx, now, 100)
	if err != nil {
		return err
	}
	for _, item := range items {
		_, _ = s.RunAssessment(ctx, item.TenantID, "scheduled", true, "")
		next := nextAssessmentRunTime(now, item.Frequency)
		_ = s.store.UpdateAssessmentScheduleRun(ctx, item.TenantID, now, next)
	}
	return nil
}

func (s *Service) ListComplianceTemplates(ctx context.Context, tenantID string) ([]ComplianceTemplate, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	return s.store.ListComplianceTemplates(ctx, tenantID)
}

func (s *Service) GetComplianceTemplate(ctx context.Context, tenantID string, templateID string) (ComplianceTemplate, error) {
	tenantID = strings.TrimSpace(tenantID)
	templateID = normalizeTemplateID(templateID)
	if tenantID == "" || templateID == "" {
		return ComplianceTemplate{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and template_id are required")
	}
	if templateID == "default" {
		return defaultComplianceTemplate(tenantID), nil
	}
	item, err := s.store.GetComplianceTemplate(ctx, tenantID, templateID)
	if err != nil {
		return ComplianceTemplate{}, err
	}
	return normalizeComplianceTemplate(item, tenantID), nil
}

func (s *Service) UpsertComplianceTemplate(ctx context.Context, req ComplianceTemplate) (ComplianceTemplate, error) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		return ComplianceTemplate{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	newTemplate := strings.TrimSpace(req.ID) == ""
	req.ID = strings.ToLower(strings.TrimSpace(req.ID))
	if req.ID == "" {
		req.ID = newID("ctpl")
	}
	if req.ID == "baseline" || req.ID == "built-in" {
		req.ID = "default"
	}
	if req.ID == "default" {
		return ComplianceTemplate{}, newServiceError(http.StatusBadRequest, "bad_request", "default template is read-only")
	}
	if newTemplate && !req.Enabled {
		req.Enabled = true
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return ComplianceTemplate{}, newServiceError(http.StatusBadRequest, "bad_request", "name is required")
	}
	req = normalizeComplianceTemplate(req, req.TenantID)
	if err := s.store.UpsertComplianceTemplate(ctx, req); err != nil {
		return ComplianceTemplate{}, err
	}
	item, err := s.store.GetComplianceTemplate(ctx, req.TenantID, req.ID)
	if err != nil {
		return ComplianceTemplate{}, err
	}
	item = normalizeComplianceTemplate(item, req.TenantID)
	_ = s.publishAudit(ctx, "audit.compliance.template_upserted", req.TenantID, map[string]interface{}{
		"template_id":   item.ID,
		"template_name": item.Name,
		"enabled":       item.Enabled,
	})
	return item, nil
}

func (s *Service) DeleteComplianceTemplate(ctx context.Context, tenantID string, templateID string) error {
	tenantID = strings.TrimSpace(tenantID)
	templateID = normalizeTemplateID(templateID)
	if tenantID == "" || templateID == "" {
		return newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and template_id are required")
	}
	if templateID == "default" {
		return newServiceError(http.StatusBadRequest, "bad_request", "default template cannot be deleted")
	}
	if err := s.store.DeleteComplianceTemplate(ctx, tenantID, templateID); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.compliance.template_deleted", tenantID, map[string]interface{}{
		"template_id": templateID,
	})
	return nil
}

func (s *Service) ListFrameworks() []Framework {
	return frameworkCatalog()
}

func (s *Service) GetFrameworkControls(ctx context.Context, tenantID string, frameworkID string) ([]FrameworkControl, FrameworkAssessment, error) {
	tenantID = strings.TrimSpace(tenantID)
	frameworkID = normalizeFrameworkID(frameworkID)
	if tenantID == "" || frameworkID == "" {
		return nil, FrameworkAssessment{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and framework id are required")
	}
	item, err := s.store.GetFrameworkAssessment(ctx, tenantID, frameworkID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			if _, err := s.RecomputePosture(ctx, tenantID); err != nil {
				return nil, FrameworkAssessment{}, err
			}
			item, err = s.store.GetFrameworkAssessment(ctx, tenantID, frameworkID)
		}
	}
	if err != nil {
		return nil, FrameworkAssessment{}, err
	}
	return item.Controls, item, nil
}

func (s *Service) GetFrameworkGaps(ctx context.Context, tenantID string, frameworkID string) ([]ComplianceGap, error) {
	tenantID = strings.TrimSpace(tenantID)
	frameworkID = normalizeFrameworkID(frameworkID)
	if tenantID == "" || frameworkID == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id and framework id are required")
	}
	gaps, err := s.store.ListFrameworkGaps(ctx, tenantID, frameworkID)
	if err != nil {
		return nil, err
	}
	if len(gaps) == 0 {
		if _, err := s.RecomputePosture(ctx, tenantID); err != nil {
			return nil, err
		}
		return s.store.ListFrameworkGaps(ctx, tenantID, frameworkID)
	}
	return gaps, nil
}

func (s *Service) GetKeyHygieneReport(ctx context.Context, tenantID string) (KeyHygieneReport, error) {
	keys, _ := s.fetchKeys(ctx, tenantID)
	policies, _ := s.fetchPolicies(ctx, tenantID)
	report, _ := computeKeyHygiene(keys, policies)
	report.TenantID = tenantID
	return report, nil
}

func (s *Service) GetOrphanedKeys(ctx context.Context, tenantID string) ([]map[string]interface{}, error) {
	report, err := s.GetKeyHygieneReport(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return report.OrphanedKeys, nil
}

func (s *Service) GetExpiredKeys(ctx context.Context, tenantID string) ([]map[string]interface{}, error) {
	report, err := s.GetKeyHygieneReport(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return report.ExpiringKeys, nil
}

func (s *Service) GetAuditCorrelations(ctx context.Context, tenantID string, limit int) ([]CorrelationItem, error) {
	events, _ := s.fetchEvents(ctx, tenantID, 1000)
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	grouped := map[string]*CorrelationItem{}
	actionBuckets := map[string]map[string]int{}
	for _, ev := range events {
		corr := firstString(ev["correlation_id"], ev["session_id"], ev["id"])
		if corr == "" {
			continue
		}
		item, ok := grouped[corr]
		if !ok {
			item = &CorrelationItem{CorrelationID: corr}
			grouped[corr] = item
			actionBuckets[corr] = map[string]int{}
		}
		item.Count++
		ts := parseTimeString(firstString(ev["timestamp"], ev["created_at"]))
		if item.FirstSeen.IsZero() || (!ts.IsZero() && ts.Before(item.FirstSeen)) {
			item.FirstSeen = ts
		}
		if item.LastSeen.IsZero() || (!ts.IsZero() && ts.After(item.LastSeen)) {
			item.LastSeen = ts
		}
		act := firstString(ev["action"], ev["audit_action"])
		if act != "" {
			actionBuckets[corr][act]++
		}
	}
	out := make([]CorrelationItem, 0, len(grouped))
	for corr, item := range grouped {
		item.TopActions = topActions(actionBuckets[corr], 3)
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Service) GetAuditAnomalies(ctx context.Context, tenantID string) ([]AnomalyItem, error) {
	events, _ := s.fetchEvents(ctx, tenantID, 1000)
	stats, _ := s.fetchAlertStats(ctx, tenantID)
	now := time.Now().UTC()
	failedAuth := 0
	policyViolations := 0
	criticalActions := 0
	for _, ev := range events {
		action := strings.ToLower(firstString(ev["action"], ev["audit_action"]))
		result := strings.ToLower(firstString(ev["result"]))
		switch {
		case strings.Contains(action, "auth.login_failed"):
			failedAuth++
		case strings.Contains(action, "policy.violated"):
			policyViolations++
		case strings.Contains(action, "key.exported"), strings.Contains(action, "fips.violation"), strings.Contains(action, "chain"):
			criticalActions++
		case strings.Contains(action, "login") && result == "failure":
			failedAuth++
		}
	}

	out := make([]AnomalyItem, 0)
	if failedAuth >= 3 {
		out = append(out, AnomalyItem{
			ID:          newID("anom"),
			Type:        "failed_auth_spike",
			Severity:    "high",
			Description: "Repeated failed authentication attempts detected",
			Count:       failedAuth,
			DetectedAt:  now,
		})
	}
	if policyViolations > 0 {
		out = append(out, AnomalyItem{
			ID:          newID("anom"),
			Type:        "policy_violation",
			Severity:    "high",
			Description: "Policy violations detected in audit stream",
			Count:       policyViolations,
			DetectedAt:  now,
		})
	}
	critical := extractInt(stats["critical"]) + extractInt(stats["CRITICAL"])
	if critical > 0 || criticalActions > 0 {
		out = append(out, AnomalyItem{
			ID:          newID("anom"),
			Type:        "critical_activity",
			Severity:    "critical",
			Description: "Critical security-sensitive events detected",
			Count:       critical + criticalActions,
			DetectedAt:  now,
		})
	}
	return out, nil
}

func (s *Service) GenerateSBOM(_ context.Context, format string) (SBOMDocument, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "cyclonedx"
	}
	switch format {
	case "cyclonedx", "spdx":
	default:
		return SBOMDocument{}, newServiceError(http.StatusBadRequest, "bad_request", "unsupported sbom format")
	}
	services := listServiceNames()
	components := make([]map[string]interface{}, 0, len(services)+2)
	for _, name := range services {
		components = append(components, map[string]interface{}{
			"name":    "vecta/" + name,
			"type":    "service",
			"version": "dev",
		})
	}
	components = append(components,
		map[string]interface{}{"name": "go", "type": "runtime", "version": "1.x"},
		map[string]interface{}{"name": "postgresql", "type": "infrastructure", "version": "16"},
	)
	doc := SBOMDocument{
		Format:      format,
		SpecVersion: map[string]string{"cyclonedx": "1.6", "spdx": "2.3"}[format],
		GeneratedAt: time.Now().UTC(),
		Appliance:   "vecta-kms",
		Components:  components,
		Infrastructure: []map[string]interface{}{
			{"name": "postgresql", "version": "16"},
			{"name": "redis", "version": "7"},
			{"name": "nats", "version": "2.x"},
			{"name": "envoy", "version": "1.x"},
		},
		Licenses: []string{"Apache-2.0", "MIT", "BSD-3-Clause", "ISC", "MPL-2.0"},
	}
	return doc, nil
}

func (s *Service) SBOMServices(_ context.Context) ([]map[string]interface{}, error) {
	names := listServiceNames()
	out := make([]map[string]interface{}, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]interface{}{
			"name":             n,
			"component_count":  1,
			"format_supported": []string{"cyclonedx", "spdx"},
		})
	}
	return out, nil
}

func (s *Service) SBOMService(_ context.Context, name string) (map[string]interface{}, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "service name is required")
	}
	return map[string]interface{}{
		"name":            name,
		"version":         "dev",
		"language":        "go",
		"dependencies":    []string{"stdlib"},
		"licenses":        []string{"Apache-2.0"},
		"vulnerabilities": []map[string]interface{}{},
	}, nil
}

func (s *Service) SBOMVulnerabilities(ctx context.Context, tenantID string) ([]map[string]interface{}, error) {
	posture, err := s.GetPosture(ctx, tenantID, false)
	if err != nil {
		return nil, err
	}
	vulns := make([]map[string]interface{}, 0)
	if posture.CryptoPosture < 60 {
		vulns = append(vulns, map[string]interface{}{
			"id":          "CRYPTO-DEPRECATED-ALGO",
			"severity":    "high",
			"description": "Deprecated cryptographic algorithms detected in key inventory",
		})
	}
	return vulns, nil
}

func (s *Service) GenerateCBOM(ctx context.Context, tenantID string) (CBOMDocument, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return CBOMDocument{}, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	keys, _ := s.fetchKeys(ctx, tenantID)
	doc := buildCBOM(tenantID, keys)
	summaryJSON := mustJSON(map[string]interface{}{
		"algorithm_summary":     doc.AlgorithmSummary,
		"strength_histogram":    doc.StrengthHistogram,
		"deprecated_count":      doc.DeprecatedCount,
		"pqc_ready_count":       doc.PQCReadyCount,
		"total_asset_count":     doc.TotalAssetCount,
		"pqc_readiness_percent": doc.PQCReadinessPercent,
	}, "{}")
	documentJSON := mustJSON(doc, "{}")
	_ = s.store.SaveCBOMSnapshot(ctx, CBOMSnapshot{
		ID:           newID("cbom"),
		TenantID:     tenantID,
		SummaryJSON:  summaryJSON,
		DocumentJSON: documentJSON,
	})
	_ = s.publishAudit(ctx, "audit.cbom.generated", tenantID, map[string]interface{}{
		"asset_count": doc.TotalAssetCount,
	})
	return doc, nil
}

func (s *Service) CBOMSummary(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	doc, err := s.GenerateCBOM(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"algorithm_distribution": doc.AlgorithmSummary,
		"strength_histogram":     doc.StrengthHistogram,
		"deprecated_count":       doc.DeprecatedCount,
		"total_assets":           doc.TotalAssetCount,
		"pqc_ready_count":        doc.PQCReadyCount,
		"pqc_readiness_percent":  round2(doc.PQCReadinessPercent),
	}, nil
}

func (s *Service) CBOMPQCReadiness(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	doc, err := s.GenerateCBOM(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"tenant_id":             tenantID,
		"pqc_ready_count":       doc.PQCReadyCount,
		"total_assets":          doc.TotalAssetCount,
		"pqc_readiness_percent": round2(doc.PQCReadinessPercent),
		"status":                readinessStatus(doc.PQCReadinessPercent),
	}, nil
}

func (s *Service) CBOMDiff(ctx context.Context, tenantID string, from time.Time, to time.Time) (map[string]interface{}, error) {
	if from.IsZero() && to.IsZero() {
		to = time.Now().UTC()
		from = to.Add(-30 * 24 * time.Hour)
	}
	snapshots, err := s.store.ListCBOMSnapshots(ctx, tenantID, from, to, 200)
	if err != nil {
		return nil, err
	}
	if len(snapshots) == 0 {
		_, _ = s.GenerateCBOM(ctx, tenantID)
		snapshots, _ = s.store.ListCBOMSnapshots(ctx, tenantID, from, to, 200)
	}
	if len(snapshots) == 0 {
		return map[string]interface{}{
			"from":                from,
			"to":                  to,
			"algorithm_delta":     map[string]int{},
			"deprecated_delta":    0,
			"pqc_readiness_delta": 0.0,
			"note":                "no cbom snapshots available",
		}, nil
	}
	sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].GeneratedAt.Before(snapshots[j].GeneratedAt) })
	oldest := parseCBOMSummary(snapshots[0].SummaryJSON)
	latest := parseCBOMSummary(snapshots[len(snapshots)-1].SummaryJSON)
	return map[string]interface{}{
		"from":                snapshots[0].GeneratedAt,
		"to":                  snapshots[len(snapshots)-1].GeneratedAt,
		"algorithm_delta":     diffCountMap(oldest.AlgorithmSummary, latest.AlgorithmSummary),
		"deprecated_delta":    latest.DeprecatedCount - oldest.DeprecatedCount,
		"pqc_readiness_delta": round2(latest.PQCReadinessPercent - oldest.PQCReadinessPercent),
	}, nil
}

func (s *Service) assessFrameworks(tenantID string, keyHygiene int, policy int, access int, crypto int, pqcReadiness int, qslAvg float64) []FrameworkAssessment {
	frameworks := frameworkCatalog()
	out := make([]FrameworkAssessment, 0, len(frameworks))
	for _, fw := range frameworks {
		controls := make([]FrameworkControl, 0, len(fw.Controls))
		gaps := make([]ComplianceGap, 0)
		for _, c := range fw.Controls {
			score := controlScore(c.Category, keyHygiene, policy, access, crypto, pqcReadiness, qslAvg)
			status := controlStatus(score)
			evidence := "Derived from compliance posture metrics"
			ctrl := c
			ctrl.Score = score
			ctrl.Status = status
			ctrl.Evidence = evidence
			controls = append(controls, ctrl)
			if status != "compliant" {
				gaps = append(gaps, ComplianceGap{
					ID:          newID("gap"),
					TenantID:    tenantID,
					FrameworkID: fw.ID,
					ControlID:   c.ID,
					Severity:    gapSeverity(score),
					Title:       fw.Name + " control gap: " + c.Title,
					Description: "Control score below threshold",
					Status:      "open",
					DetectedAt:  time.Now().UTC(),
				})
			}
		}
		total := 0
		for _, c := range controls {
			total += c.Score
		}
		score := 0
		if len(controls) > 0 {
			score = clampScore(total / len(controls))
		}
		out = append(out, FrameworkAssessment{
			ID:          newID("fassess"),
			TenantID:    tenantID,
			FrameworkID: fw.ID,
			Score:       score,
			Status:      frameworkStatus(score),
			Controls:    controls,
			Gaps:        gaps,
			PQCReady:    pqcReadiness,
			QSLAvg:      qslAvg,
		})
	}
	return out
}

func (s *Service) resolveComplianceTemplate(ctx context.Context, tenantID string, templateID string) (*ComplianceTemplate, error) {
	templateID = normalizeTemplateID(templateID)
	if templateID == "" || templateID == "default" {
		return nil, nil
	}
	item, err := s.store.GetComplianceTemplate(ctx, tenantID, templateID)
	if err != nil {
		if errors.Is(err, errNotFound) {
			return nil, newServiceError(http.StatusNotFound, "not_found", "compliance template not found")
		}
		return nil, err
	}
	item = normalizeComplianceTemplate(item, tenantID)
	if !item.Enabled {
		return nil, newServiceError(http.StatusBadRequest, "bad_request", "selected compliance template is disabled")
	}
	return &item, nil
}

func normalizeTemplateID(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" || v == "default" || v == "baseline" || v == "built-in" {
		return "default"
	}
	return v
}

func defaultComplianceTemplate(tenantID string) ComplianceTemplate {
	return ComplianceTemplate{
		ID:          "default",
		TenantID:    tenantID,
		Name:        "Built-in Baseline",
		Description: "Default compliance scoring derived from posture categories and built-in frameworks.",
		Enabled:     true,
		Frameworks:  defaultTemplateFrameworks(),
	}
}

func defaultTemplateFrameworks() []ComplianceTemplateFramework {
	catalog := frameworkCatalog()
	out := make([]ComplianceTemplateFramework, 0, len(catalog))
	for _, fw := range catalog {
		controls := make([]ComplianceTemplateControl, 0, len(fw.Controls))
		for _, c := range fw.Controls {
			controls = append(controls, ComplianceTemplateControl{
				ID:          c.ID,
				Title:       c.Title,
				Category:    c.Category,
				Requirement: c.Requirement,
				Enabled:     true,
				Weight:      defaultWeight(c.Weight, 1),
				Threshold:   80,
			})
		}
		out = append(out, ComplianceTemplateFramework{
			FrameworkID: fw.ID,
			Label:       strings.TrimSpace(fw.Name + " " + fw.Version),
			Enabled:     true,
			Weight:      1,
			Controls:    controls,
		})
	}
	return out
}

func normalizeComplianceTemplate(in ComplianceTemplate, tenantID string) ComplianceTemplate {
	baseMap := map[string]ComplianceTemplateFramework{}
	for _, fw := range defaultTemplateFrameworks() {
		baseMap[fw.FrameworkID] = fw
	}
	in.TenantID = tenantID
	in.Description = strings.TrimSpace(in.Description)
	seen := map[string]struct{}{}
	outFrameworks := make([]ComplianceTemplateFramework, 0, len(baseMap))
	for _, fw := range in.Frameworks {
		fwID := normalizeFrameworkID(fw.FrameworkID)
		if fwID == "" {
			continue
		}
		if _, ok := seen[fwID]; ok {
			continue
		}
		seen[fwID] = struct{}{}
		base, ok := baseMap[fwID]
		if !ok {
			continue
		}
		fw.FrameworkID = fwID
		fw.Label = firstNonEmpty(fw.Label, base.Label)
		fw.Weight = defaultWeight(fw.Weight, 1)
		controlMap := map[string]ComplianceTemplateControl{}
		for _, c := range base.Controls {
			controlMap[c.ID] = c
		}
		normalizedControls := make([]ComplianceTemplateControl, 0, len(base.Controls))
		usedControls := map[string]struct{}{}
		for _, c := range fw.Controls {
			id := strings.TrimSpace(c.ID)
			baseCtrl, ok := controlMap[id]
			if !ok || id == "" {
				continue
			}
			if _, exists := usedControls[id]; exists {
				continue
			}
			usedControls[id] = struct{}{}
			c.ID = id
			c.Title = firstNonEmpty(c.Title, baseCtrl.Title)
			c.Category = firstNonEmpty(c.Category, baseCtrl.Category)
			c.Requirement = firstNonEmpty(c.Requirement, baseCtrl.Requirement)
			c.Weight = defaultWeight(c.Weight, 1)
			if c.Threshold <= 0 || c.Threshold > 100 {
				c.Threshold = 80
			}
			normalizedControls = append(normalizedControls, c)
		}
		for _, c := range base.Controls {
			if _, exists := usedControls[c.ID]; exists {
				continue
			}
			normalizedControls = append(normalizedControls, c)
		}
		fw.Controls = normalizedControls
		outFrameworks = append(outFrameworks, fw)
	}
	for fwID, fw := range baseMap {
		if _, ok := seen[fwID]; ok {
			continue
		}
		outFrameworks = append(outFrameworks, fw)
	}
	sort.Slice(outFrameworks, func(i, j int) bool {
		return outFrameworks[i].FrameworkID < outFrameworks[j].FrameworkID
	})
	in.Frameworks = outFrameworks
	if in.Name == "" {
		in.Name = "Custom Compliance Template"
	}
	return in
}

func scoreFromComplianceTemplate(tpl ComplianceTemplate, posture PostureSnapshot) (map[string]int, int) {
	frameworkScores := map[string]int{}
	totalWeight := 0.0
	weightedTotal := 0.0
	for _, fw := range tpl.Frameworks {
		if !fw.Enabled {
			continue
		}
		fwWeight := defaultWeight(fw.Weight, 1)
		ctrlWeightSum := 0.0
		ctrlWeightedTotal := 0.0
		for _, ctrl := range fw.Controls {
			if !ctrl.Enabled {
				continue
			}
			score := controlScore(
				ctrl.Category,
				posture.KeyHygiene,
				posture.PolicyCompliance,
				posture.AccessSecurity,
				posture.CryptoPosture,
				posture.PQCReadiness,
				posture.Metrics["qsl_avg"],
			)
			ctrlWeight := defaultWeight(ctrl.Weight, 1)
			ctrlWeightSum += ctrlWeight
			ctrlWeightedTotal += float64(score) * ctrlWeight
		}
		fwScore := posture.FrameworkScores[fw.FrameworkID]
		if ctrlWeightSum > 0 {
			fwScore = clampScore(int(ctrlWeightedTotal / ctrlWeightSum))
		}
		frameworkScores[fw.FrameworkID] = fwScore
		weightedTotal += float64(fwScore) * fwWeight
		totalWeight += fwWeight
	}
	if len(frameworkScores) == 0 {
		return posture.FrameworkScores, posture.OverallScore
	}
	overall := posture.OverallScore
	if totalWeight > 0 {
		overall = clampScore(int(weightedTotal / totalWeight))
	}
	return frameworkScores, overall
}

func defaultWeight(v float64, fallback float64) float64 {
	if v <= 0 {
		return fallback
	}
	return v
}

func (s *Service) fetchKeys(ctx context.Context, tenantID string) ([]map[string]interface{}, error) {
	if s.keycore == nil {
		return []map[string]interface{}{}, nil
	}
	items, err := s.keycore.ListKeys(ctx, tenantID, 2000)
	if err != nil {
		return []map[string]interface{}{}, nil
	}
	return items, nil
}

func (s *Service) fetchCerts(ctx context.Context, tenantID string) ([]map[string]interface{}, error) {
	if s.certs == nil {
		return []map[string]interface{}{}, nil
	}
	items, err := s.certs.ListCertificates(ctx, tenantID, 5000)
	if err != nil {
		return []map[string]interface{}{}, nil
	}
	return items, nil
}

func (s *Service) fetchPolicies(ctx context.Context, tenantID string) ([]map[string]interface{}, error) {
	if s.policy == nil {
		return []map[string]interface{}{}, nil
	}
	items, err := s.policy.ListPolicies(ctx, tenantID, 2000)
	if err != nil {
		return []map[string]interface{}{}, nil
	}
	return items, nil
}

func (s *Service) fetchEvents(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error) {
	if s.audit == nil {
		return []map[string]interface{}{}, nil
	}
	items, err := s.audit.ListEvents(ctx, tenantID, limit)
	if err != nil {
		return []map[string]interface{}{}, nil
	}
	return items, nil
}

func (s *Service) fetchAlertStats(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	if s.audit == nil {
		return map[string]interface{}{}, nil
	}
	stats, err := s.audit.AlertStats(ctx, tenantID)
	if err != nil {
		return map[string]interface{}{}, nil
	}
	return stats, nil
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "compliance",
		"action":    subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}

func computeKeyHygiene(keys []map[string]interface{}, policies []map[string]interface{}) (KeyHygieneReport, int) {
	report := KeyHygieneReport{
		AlgorithmDistribution: map[string]int{},
		OrphanedKeys:          []map[string]interface{}{},
		ExpiringKeys:          []map[string]interface{}{},
	}
	total := len(keys)
	if total == 0 {
		return report, 100
	}
	approved := 0
	rotationCovered := 0
	orphaned := 0
	unused := 0
	expiring := 0
	deprecated := 0
	pqcReady := 0

	for _, k := range keys {
		alg := normalizeAlgorithm(firstString(k["algorithm"]))
		report.AlgorithmDistribution[alg]++
		if isApprovedAlgorithm(alg) {
			approved++
		}
		if isDeprecatedAlgorithm(alg) {
			deprecated++
		}
		if isPQCAlgorithm(alg) {
			pqcReady++
		}
		version := extractInt(k["current_version"])
		ops := extractInt(k["ops_total"])
		status := strings.ToLower(firstString(k["status"]))
		if version >= 2 || ops > 0 {
			rotationCovered++
		}
		if status != "active" || ops == 0 {
			orphaned++
			report.OrphanedKeys = append(report.OrphanedKeys, k)
		}
		if ops == 0 {
			unused++
		}
		if isExpiringSoon(k) {
			expiring++
			report.ExpiringKeys = append(report.ExpiringKeys, k)
		}
	}

	report.TotalKeys = total
	report.ApprovedAlgorithmPct = round2(pct(approved, total))
	report.RotationCoveragePct = round2(pct(rotationCovered, total))
	report.PolicyCoveragePct = round2(policyCoverage(keys, policies))
	report.OrphanedCount = orphaned
	report.ExpiringCount = expiring
	report.DeprecatedCount = deprecated
	report.Unused90DaysCount = unused
	report.PQCReadyPct = round2(pct(pqcReady, total))

	orphanPenalty := 100 - int(round2(pct(orphaned, total)))
	unusedPenalty := 100 - int(round2(pct(unused, total)))
	score := clampScore(int(
		0.35*report.RotationCoveragePct +
			0.30*report.ApprovedAlgorithmPct +
			0.20*float64(orphanPenalty) +
			0.15*float64(unusedPenalty),
	))
	return report, score
}

func computePolicyCompliance(keys []map[string]interface{}, policies []map[string]interface{}, events []map[string]interface{}, alertStats map[string]interface{}) (int, map[string]float64) {
	totalKeys := len(keys)
	activePolicies := 0
	for _, p := range policies {
		if strings.ToLower(firstString(p["status"])) != "deleted" {
			activePolicies++
		}
	}
	coverage := policyCoverage(keys, policies)
	violations := 0
	for _, ev := range events {
		action := strings.ToLower(firstString(ev["action"]))
		if strings.Contains(action, "policy.violated") {
			violations++
		}
	}
	violations += extractInt(alertStats["high"])
	unresolvedApprovals := 0
	for _, k := range keys {
		if extractBool(k["approval_required"]) && strings.TrimSpace(firstString(k["approval_policy_id"])) == "" {
			unresolvedApprovals++
		}
	}
	base := 30.0
	if totalKeys == 0 {
		base = 100
	}
	score := clampScore(int(base + 0.45*coverage + 25*boolFloat(activePolicies > 0) - float64(violations*5) - float64(unresolvedApprovals*4)))
	return score, map[string]float64{
		"policy_coverage_pct":    round2(coverage),
		"active_policies":        float64(activePolicies),
		"policy_violation_count": float64(violations),
		"unresolved_approvals":   float64(unresolvedApprovals),
	}
}

func computeAccessSecurity(events []map[string]interface{}, alertStats map[string]interface{}) (int, map[string]float64) {
	totalAuth := 0
	failedAuth := 0
	mfaSuccess := 0
	loginSuccess := 0
	for _, ev := range events {
		action := strings.ToLower(firstString(ev["action"]))
		if strings.Contains(action, "auth.login") {
			totalAuth++
		}
		if strings.Contains(action, "auth.login_failed") {
			failedAuth++
		}
		if strings.Contains(action, "mfa") && strings.Contains(action, "success") {
			mfaSuccess++
		}
		if strings.Contains(action, "auth.login_success") {
			loginSuccess++
		}
	}
	failedRate := 0.0
	if totalAuth > 0 {
		failedRate = pct(failedAuth, totalAuth)
	}
	mfaAdoption := 0.0
	if loginSuccess > 0 {
		mfaAdoption = pct(mfaSuccess, loginSuccess)
	}
	critical := extractInt(alertStats["critical"]) + extractInt(alertStats["CRITICAL"])
	score := clampScore(int(100 - failedRate*1.2 + mfaAdoption*0.4 - float64(critical*3)))
	return score, map[string]float64{
		"failed_auth_rate_pct": failedRate,
		"mfa_adoption_pct":     mfaAdoption,
		"critical_alert_count": float64(critical),
	}
}

func computeCryptoPosture(keys []map[string]interface{}) (int, int, float64, map[string]float64) {
	total := len(keys)
	if total == 0 {
		return 100, 100, 100, map[string]float64{
			"pqc_ready_pct":        100,
			"deprecated_pct":       0,
			"cbom_completeness":    100,
			"qsl_avg":              100,
			"deprecated_key_count": 0,
		}
	}
	pqcReady := 0
	deprecated := 0
	qslTotal := 0.0
	for _, k := range keys {
		alg := normalizeAlgorithm(firstString(k["algorithm"]))
		if isPQCAlgorithm(alg) {
			pqcReady++
		}
		if isDeprecatedAlgorithm(alg) {
			deprecated++
		}
		qslTotal += algorithmQSL(alg)
	}
	qslAvg := qslTotal / float64(total)
	pqcPct := pct(pqcReady, total)
	deprecatedPct := pct(deprecated, total)
	cbomCompleteness := 100.0
	score := clampScore(int(0.35*pqcPct + 0.30*(100-deprecatedPct) + 0.20*cbomCompleteness + 0.15*qslAvg))
	return score, clampScore(int(pqcPct)), qslAvg, map[string]float64{
		"pqc_ready_pct":        round2(pqcPct),
		"deprecated_pct":       round2(deprecatedPct),
		"cbom_completeness":    cbomCompleteness,
		"qsl_avg":              round2(qslAvg),
		"deprecated_key_count": float64(deprecated),
	}
}

func policyCoverage(keys []map[string]interface{}, policies []map[string]interface{}) float64 {
	if len(keys) == 0 {
		return 100
	}
	if len(policies) == 0 {
		return 0
	}
	withPolicy := 0
	for _, k := range keys {
		if strings.TrimSpace(firstString(k["approval_policy_id"])) != "" || extractBool(k["approval_required"]) {
			withPolicy++
		}
	}
	if withPolicy == 0 {
		return 70
	}
	return pct(withPolicy, len(keys))
}

func frameworkCatalog() []Framework {
	return []Framework{
		{
			ID:          frameworkPCIDSS,
			Name:        "PCI DSS",
			Version:     "4.0",
			Description: "Payment card data security controls",
			Controls: []FrameworkControl{
				{ID: "pci-3.6.4", Title: "Cryptographic key rotation", Category: "key_hygiene", Requirement: "Keys are rotated on policy"},
				{ID: "pci-3.5.1", Title: "Strong key algorithms", Category: "crypto_posture", Requirement: "Approved algorithms enforced"},
				{ID: "pci-7.2.5", Title: "Access restrictions", Category: "access_security", Requirement: "Least privilege and MFA"},
				{ID: "pci-12.10", Title: "Policy governance", Category: "policy_compliance", Requirement: "Policy violations tracked"},
			},
		},
		{
			ID:          frameworkFIPS,
			Name:        "FIPS",
			Version:     "140-3",
			Description: "Cryptographic module and algorithm compliance",
			Controls: []FrameworkControl{
				{ID: "fips-alg-1", Title: "Approved algorithms only", Category: "crypto_posture", Requirement: "No disallowed algorithms"},
				{ID: "fips-key-1", Title: "Key lifecycle hygiene", Category: "key_hygiene", Requirement: "Key state and rotation managed"},
				{ID: "fips-access-1", Title: "Operator authentication", Category: "access_security", Requirement: "Authentication controls active"},
				{ID: "fips-policy-1", Title: "Security policy enforcement", Category: "policy_compliance", Requirement: "Controls codified in policy"},
			},
		},
		{
			ID:          frameworkNIST,
			Name:        "NIST",
			Version:     "800-57",
			Description: "Key management best practices",
			Controls: []FrameworkControl{
				{ID: "nist-5.3", Title: "Key establishment and lifecycle", Category: "key_hygiene", Requirement: "Lifecycle controls tracked"},
				{ID: "nist-5.6", Title: "Key usage controls", Category: "policy_compliance", Requirement: "Usage constrained by policy"},
				{ID: "nist-5.7", Title: "Access and accountability", Category: "access_security", Requirement: "Audit and auth controls"},
				{ID: "nist-pqc", Title: "Algorithm transition readiness", Category: "crypto_posture", Requirement: "PQC migration readiness"},
			},
		},
		{
			ID:          frameworkEIDAS,
			Name:        "eIDAS",
			Version:     "2.0",
			Description: "Trust services and signature assurance",
			Controls: []FrameworkControl{
				{ID: "eidas-crypto-1", Title: "Trusted cryptographic strength", Category: "crypto_posture", Requirement: "Strong modern algorithms"},
				{ID: "eidas-key-1", Title: "Key integrity controls", Category: "key_hygiene", Requirement: "Key management hygiene"},
				{ID: "eidas-access-1", Title: "Strong user authentication", Category: "access_security", Requirement: "MFA and auth resilience"},
				{ID: "eidas-policy-1", Title: "Policy and procedural compliance", Category: "policy_compliance", Requirement: "Governance policies enforced"},
			},
		},
	}
}

func controlScore(category string, keyHygiene int, policy int, access int, crypto int, pqcReadiness int, qslAvg float64) int {
	switch category {
	case "key_hygiene":
		return clampScore(keyHygiene)
	case "policy_compliance":
		return clampScore(policy)
	case "access_security":
		return clampScore(access)
	case "crypto_posture":
		return clampScore(int(0.7*float64(crypto) + 0.2*float64(pqcReadiness) + 0.1*qslAvg))
	default:
		return 0
	}
}

func controlStatus(score int) string {
	switch {
	case score >= 80:
		return "compliant"
	case score >= 60:
		return "partial"
	default:
		return "non_compliant"
	}
}

func gapSeverity(score int) string {
	switch {
	case score < 40:
		return "critical"
	case score < 60:
		return "high"
	default:
		return "medium"
	}
}

func frameworkStatus(score int) string {
	switch {
	case score >= 85:
		return "compliant"
	case score >= 65:
		return "at_risk"
	default:
		return "non_compliant"
	}
}

func withTenantGaps(tenantID string, frameworkID string, in []ComplianceGap) []ComplianceGap {
	out := make([]ComplianceGap, 0, len(in))
	for _, g := range in {
		g.TenantID = tenantID
		g.FrameworkID = frameworkID
		g.Status = "open"
		if g.ID == "" {
			g.ID = newID("gap")
		}
		if g.DetectedAt.IsZero() {
			g.DetectedAt = time.Now().UTC()
		}
		out = append(out, g)
	}
	return out
}

func topActions(m map[string]int, n int) []string {
	type kv struct {
		K string
		V int
	}
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{K: k, V: v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].V > items[j].V })
	if len(items) > n {
		items = items[:n]
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.K)
	}
	return out
}

func normalizeAlgorithm(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		return "UNKNOWN"
	}
	return v
}

func isApprovedAlgorithm(alg string) bool {
	switch {
	case strings.Contains(alg, "AES"),
		strings.Contains(alg, "RSA-4096"),
		strings.Contains(alg, "RSA-3072"),
		strings.Contains(alg, "ECDSA"),
		strings.Contains(alg, "ED25519"),
		isPQCAlgorithm(alg):
		return true
	default:
		return false
	}
}

func isDeprecatedAlgorithm(alg string) bool {
	switch {
	case strings.Contains(alg, "3DES"),
		strings.Contains(alg, "DES"),
		strings.Contains(alg, "RC4"),
		strings.Contains(alg, "SHA-1"),
		strings.Contains(alg, "RSA-1024"),
		strings.Contains(alg, "RSA-2048"):
		return true
	default:
		return false
	}
}

func isPQCAlgorithm(alg string) bool {
	switch {
	case strings.Contains(alg, "ML-KEM"),
		strings.Contains(alg, "KYBER"),
		strings.Contains(alg, "ML-DSA"),
		strings.Contains(alg, "DILITHIUM"),
		strings.Contains(alg, "FALCON"),
		strings.Contains(alg, "SPHINCS"):
		return true
	default:
		return false
	}
}

func algorithmQSL(alg string) float64 {
	switch {
	case isPQCAlgorithm(alg):
		return 100
	case strings.Contains(alg, "AES-256"):
		return 95
	case strings.Contains(alg, "AES-192"):
		return 85
	case strings.Contains(alg, "AES-128"):
		return 75
	case strings.Contains(alg, "RSA-4096"):
		return 88
	case strings.Contains(alg, "RSA-3072"):
		return 78
	case strings.Contains(alg, "RSA-2048"):
		return 45
	case strings.Contains(alg, "ECDSA"), strings.Contains(alg, "ED25519"):
		return 80
	case isDeprecatedAlgorithm(alg):
		return 20
	default:
		return 60
	}
}

func isExpiringSoon(key map[string]interface{}) bool {
	raw := firstString(key["expires_at"], key["expiry"], key["expire_at"])
	if strings.TrimSpace(raw) == "" {
		return false
	}
	ts := parseTimeString(raw)
	if ts.IsZero() {
		return false
	}
	days := ts.Sub(time.Now().UTC()).Hours() / 24
	return days >= 0 && days <= 30
}

func boolFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

func buildCBOM(tenantID string, keys []map[string]interface{}) CBOMDocument {
	assets := make([]map[string]interface{}, 0, len(keys))
	algoSummary := map[string]int{}
	strengthHistogram := map[string]int{
		"<128":     0,
		"128-255":  0,
		"256-3071": 0,
		">=3072":   0,
	}
	deprecated := 0
	pqcReady := 0
	for _, k := range keys {
		alg := normalizeAlgorithm(firstString(k["algorithm"]))
		bits := inferBits(alg)
		algoSummary[alg]++
		switch {
		case bits < 128:
			strengthHistogram["<128"]++
		case bits < 256:
			strengthHistogram["128-255"]++
		case bits < 3072:
			strengthHistogram["256-3071"]++
		default:
			strengthHistogram[">=3072"]++
		}
		if isDeprecatedAlgorithm(alg) {
			deprecated++
		}
		if isPQCAlgorithm(alg) {
			pqcReady++
		}
		assets = append(assets, map[string]interface{}{
			"id":                firstString(k["id"]),
			"name":              firstString(k["name"]),
			"algorithm":         alg,
			"strength_bits":     bits,
			"purpose":           firstString(k["purpose"]),
			"kcv":               firstString(k["kcv"]),
			"pqc_ready":         isPQCAlgorithm(alg),
			"qsl":               round2(algorithmQSL(alg)),
			"hsm_backed":        false,
			"compliance_status": controlStatus(clampScore(int(algorithmQSL(alg)))),
		})
	}
	total := len(assets)
	readyPct := 0.0
	if total > 0 {
		readyPct = pct(pqcReady, total)
	}
	return CBOMDocument{
		Format:              "cyclonedx-crypto",
		SpecVersion:         "1.6",
		GeneratedAt:         time.Now().UTC(),
		TenantID:            tenantID,
		Assets:              assets,
		AlgorithmSummary:    algoSummary,
		StrengthHistogram:   strengthHistogram,
		DeprecatedCount:     deprecated,
		PQCReadyCount:       pqcReady,
		TotalAssetCount:     total,
		PQCReadinessPercent: readyPct,
	}
}

type cbomSummary struct {
	AlgorithmSummary    map[string]int `json:"algorithm_summary"`
	DeprecatedCount     int            `json:"deprecated_count"`
	PQCReadinessPercent float64        `json:"pqc_readiness_percent"`
}

func parseCBOMSummary(raw string) cbomSummary {
	var out cbomSummary
	_ = json.Unmarshal([]byte(raw), &out)
	if out.AlgorithmSummary == nil {
		out.AlgorithmSummary = map[string]int{}
	}
	return out
}

func diffCountMap(a map[string]int, b map[string]int) map[string]int {
	out := map[string]int{}
	seen := map[string]struct{}{}
	for k := range a {
		seen[k] = struct{}{}
	}
	for k := range b {
		seen[k] = struct{}{}
	}
	for k := range seen {
		out[k] = b[k] - a[k]
	}
	return out
}

func inferBits(alg string) int {
	switch {
	case strings.Contains(alg, "AES-256"):
		return 256
	case strings.Contains(alg, "AES-192"):
		return 192
	case strings.Contains(alg, "AES-128"):
		return 128
	case strings.Contains(alg, "RSA-4096"):
		return 4096
	case strings.Contains(alg, "RSA-3072"):
		return 3072
	case strings.Contains(alg, "RSA-2048"):
		return 2048
	case strings.Contains(alg, "ML-KEM-1024"), strings.Contains(alg, "ML-DSA-87"):
		return 1024
	case strings.Contains(alg, "ML-KEM-768"), strings.Contains(alg, "ML-DSA-65"):
		return 768
	case strings.Contains(alg, "ML-KEM-512"), strings.Contains(alg, "ML-DSA-44"):
		return 512
	default:
		return 256
	}
}

func readinessStatus(pct float64) string {
	switch {
	case pct >= 80:
		return "ready"
	case pct >= 50:
		return "in_progress"
	default:
		return "not_ready"
	}
}

func computeCertHygiene(certs []map[string]interface{}) (CertHygieneReport, int, map[string]float64) {
	report := CertHygieneReport{}
	if len(certs) == 0 {
		return report, 100, map[string]float64{
			"cert_score": 100,
		}
	}
	now := time.Now().UTC()
	for _, c := range certs {
		report.TotalCerts++
		status := strings.ToLower(strings.TrimSpace(firstString(c["status"])))
		algorithm := strings.ToUpper(strings.TrimSpace(firstString(c["algorithm"])))
		certClass := strings.ToLower(strings.TrimSpace(firstString(c["cert_class"])))
		notAfter := parseTimeString(firstString(c["not_after"], c["expires_at"]))

		if certClass == "pqc" || certClass == "hybrid" || isPQCAlgorithm(algorithm) {
			report.PQCClassCount++
		}
		if isWeakCertAlgorithm(algorithm) {
			report.WeakAlgorithmCount++
		}
		if status == "revoked" {
			report.RevokedCount++
		}
		expired := status == "expired" || (!notAfter.IsZero() && now.After(notAfter))
		if expired {
			report.ExpiredCount++
		}
		if status == "active" && !expired {
			report.ActiveCount++
		}
		if !notAfter.IsZero() && status == "active" {
			daysLeft := int(notAfter.Sub(now).Hours() / 24)
			if daysLeft >= 0 && daysLeft <= 30 {
				report.Expiring30Days++
			}
		}
	}

	report.PQCClassPct = round2(pct(report.PQCClassCount, report.TotalCerts))
	expiredPct := pct(report.ExpiredCount, report.TotalCerts)
	weakPct := pct(report.WeakAlgorithmCount, report.TotalCerts)
	expiringPct := pct(report.Expiring30Days, report.TotalCerts)
	revokedPct := pct(report.RevokedCount, report.TotalCerts)

	score := clampScore(int(100 - expiredPct*1.2 - weakPct*1.0 - expiringPct*0.6 - revokedPct*0.2 + report.PQCClassPct*0.15))
	metrics := map[string]float64{
		"cert_score":            float64(score),
		"cert_total":            float64(report.TotalCerts),
		"cert_active":           float64(report.ActiveCount),
		"cert_revoked":          float64(report.RevokedCount),
		"cert_expired":          float64(report.ExpiredCount),
		"cert_expiring_30d":     float64(report.Expiring30Days),
		"cert_weak_algorithms":  float64(report.WeakAlgorithmCount),
		"cert_pqc_class_pct":    report.PQCClassPct,
		"cert_expired_pct":      round2(expiredPct),
		"cert_weak_algo_pct":    round2(weakPct),
		"cert_expiring_30d_pct": round2(expiringPct),
	}
	return report, score, metrics
}

func isWeakCertAlgorithm(algorithm string) bool {
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.Contains(alg, "RSA-1024"),
		strings.Contains(alg, "RSA1024"),
		strings.Contains(alg, "SHA1"),
		strings.Contains(alg, "MD5"),
		strings.Contains(alg, "DSA-1024"):
		return true
	default:
		return false
	}
}

func summarizeAssessmentPQC(keys []map[string]interface{}) AssessmentPQC {
	total := len(keys)
	if total == 0 {
		return AssessmentPQC{
			ReadyPercent:   100,
			MLKEMMigrated:  0,
			MLDSAMigrated:  0,
			Pending:        0,
			TotalEvaluated: 0,
		}
	}
	out := AssessmentPQC{TotalEvaluated: total}
	for _, k := range keys {
		alg := strings.ToUpper(strings.TrimSpace(firstString(k["algorithm"])))
		switch {
		case strings.Contains(alg, "ML-KEM"), strings.Contains(alg, "KYBER"):
			out.MLKEMMigrated++
		case strings.Contains(alg, "ML-DSA"), strings.Contains(alg, "DILITHIUM"), strings.Contains(alg, "FALCON"), strings.Contains(alg, "SPHINCS"):
			out.MLDSAMigrated++
		}
	}
	migrated := out.MLKEMMigrated + out.MLDSAMigrated
	out.Pending = total - migrated
	if out.Pending < 0 {
		out.Pending = 0
	}
	out.ReadyPercent = round2(pct(migrated, total))
	return out
}

func buildAssessmentFindings(keys []map[string]interface{}, certs []map[string]interface{}, posture PostureSnapshot) []AssessmentFinding {
	findings := make([]AssessmentFinding, 0)

	rsa1024 := 0
	oldRotation := 0
	now := time.Now().UTC()
	for _, k := range keys {
		alg := strings.ToUpper(strings.TrimSpace(firstString(k["algorithm"])))
		if strings.Contains(alg, "RSA-1024") || strings.Contains(alg, "RSA1024") {
			rsa1024++
		}
		status := strings.ToLower(strings.TrimSpace(firstString(k["status"])))
		if status != "active" {
			continue
		}
		rotatedAt := parseTimeString(firstString(k["updated_at"], k["created_at"]))
		if rotatedAt.IsZero() {
			continue
		}
		if now.Sub(rotatedAt) > 365*24*time.Hour {
			oldRotation++
		}
	}

	certExpiring := 0
	certExpired := 0
	certWeak := 0
	for _, c := range certs {
		status := strings.ToLower(strings.TrimSpace(firstString(c["status"])))
		alg := strings.ToUpper(strings.TrimSpace(firstString(c["algorithm"])))
		if isWeakCertAlgorithm(alg) {
			certWeak++
		}
		notAfter := parseTimeString(firstString(c["not_after"], c["expires_at"]))
		if status == "expired" || (!notAfter.IsZero() && now.After(notAfter)) {
			certExpired++
			continue
		}
		if status == "active" && !notAfter.IsZero() {
			daysLeft := int(notAfter.Sub(now).Hours() / 24)
			if daysLeft >= 0 && daysLeft <= 30 {
				certExpiring++
			}
		}
	}

	if rsa1024 > 0 {
		findings = append(findings, AssessmentFinding{
			ID:       newID("finding"),
			Severity: "critical",
			Title:    strconvItoa(rsa1024) + " keys using RSA-1024",
			Fix:      "Rotate to RSA-3072+ or ECDSA-P384 immediately.",
			Count:    rsa1024,
		})
	}
	if certExpired > 0 {
		findings = append(findings, AssessmentFinding{
			ID:       newID("finding"),
			Severity: "critical",
			Title:    strconvItoa(certExpired) + " certificates expired",
			Fix:      "Renew/reissue and replace expired certificates.",
			Count:    certExpired,
		})
	}
	if oldRotation > 0 {
		findings = append(findings, AssessmentFinding{
			ID:       newID("finding"),
			Severity: "warning",
			Title:    strconvItoa(oldRotation) + " keys rotation > 365d",
			Fix:      "Set 90-day rotation or stricter policy.",
			Count:    oldRotation,
		})
	}
	if certExpiring > 0 {
		findings = append(findings, AssessmentFinding{
			ID:       newID("finding"),
			Severity: "warning",
			Title:    strconvItoa(certExpiring) + " certificates expiring in <= 30 days",
			Fix:      "Schedule renewal before expiry and validate chain deployment.",
			Count:    certExpiring,
		})
	}
	if certWeak > 0 {
		findings = append(findings, AssessmentFinding{
			ID:       newID("finding"),
			Severity: "high",
			Title:    strconvItoa(certWeak) + " certificates with weak signature/key algorithm",
			Fix:      "Re-issue using FIPS-approved algorithms.",
			Count:    certWeak,
		})
	}
	if posture.PQCReadiness < 50 {
		findings = append(findings, AssessmentFinding{
			ID:       newID("finding"),
			Severity: "high",
			Title:    "Low PQC readiness (" + strconvItoa(posture.PQCReadiness) + "%)",
			Fix:      "Prioritize migration of high-value keys to ML-KEM / ML-DSA profiles.",
			Count:    1,
		})
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return severityWeight(findings[i].Severity) > severityWeight(findings[j].Severity)
	})
	return findings
}

func severityWeight(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "warning":
		return 2
	case "medium":
		return 1
	default:
		return 0
	}
}

func normalizeAssessmentFrequency(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "hourly":
		return "hourly"
	case "weekly":
		return "weekly"
	default:
		return "daily"
	}
}

func nextAssessmentRunTime(now time.Time, frequency string) time.Time {
	base := now.UTC()
	switch normalizeAssessmentFrequency(frequency) {
	case "hourly":
		return base.Add(1 * time.Hour)
	case "weekly":
		return base.Add(7 * 24 * time.Hour)
	default:
		return base.Add(24 * time.Hour)
	}
}

func listServiceNames() []string {
	entries, err := os.ReadDir("services")
	if err != nil {
		return []string{"auth", "keycore", "audit", "policy", "payment", "compliance"}
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}
