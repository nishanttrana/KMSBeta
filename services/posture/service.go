package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type Service struct {
	store      Store
	audit      AuditClient
	event      EventPublisher
	governance GovernanceControlClient

	engineInterval time.Duration
	hotRetention   time.Duration
	auditSyncLimit int
	autoRemediate  bool

	mu sync.Mutex
}

func NewService(store Store, audit AuditClient, event EventPublisher) *Service {
	return &Service{
		store:          store,
		audit:          audit,
		event:          event,
		engineInterval: time.Minute,
		hotRetention:   72 * time.Hour,
		auditSyncLimit: 500,
		autoRemediate:  false,
	}
}

func (s *Service) SetGovernanceControlClient(client GovernanceControlClient) {
	s.governance = client
}

func (s *Service) Configure(interval time.Duration, hotRetention time.Duration, auditSyncLimit int, autoRemediate bool) {
	if interval > 0 {
		s.engineInterval = interval
	}
	if hotRetention > 0 {
		s.hotRetention = hotRetention
	}
	if auditSyncLimit > 0 {
		s.auditSyncLimit = auditSyncLimit
	}
	s.autoRemediate = autoRemediate
}

func (s *Service) StartScheduler(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.engineInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.RunScanAllTenants(context.Background(), true); err != nil {
					logger.Printf("scheduled posture scan failed: %v", err)
				}
				_, _ = s.store.PurgeHotEventsBefore(context.Background(), nowUTC().Add(-s.hotRetention), 25000)
			}
		}
	}()
}

func (s *Service) IngestEvents(ctx context.Context, events []NormalizedEvent) (int, error) {
	normalized := make([]NormalizedEvent, 0, len(events))
	for _, raw := range events {
		ev, err := s.normalizeEvent(raw)
		if err != nil {
			return 0, err
		}
		normalized = append(normalized, ev)
	}
	inserted, err := s.store.IngestEvents(ctx, normalized)
	if err != nil {
		return 0, err
	}
	if inserted > 0 {
		_ = s.publish(ctx, "audit.posture.events_ingested", "root", map[string]interface{}{
			"inserted": inserted,
		})
	}
	return inserted, nil
}

func (s *Service) SyncFromAudit(ctx context.Context, tenantID string, limit int) (int, error) {
	if strings.TrimSpace(tenantID) == "" {
		return 0, newServiceError(400, "tenant_required", "tenant_id is required")
	}
	if s.audit == nil {
		return 0, nil
	}
	if limit <= 0 || limit > 5000 {
		limit = s.auditSyncLimit
	}
	rawEvents, err := s.audit.ListEvents(ctx, tenantID, limit)
	if err != nil {
		return 0, err
	}
	events := make([]NormalizedEvent, 0, len(rawEvents))
	lastEventTS := time.Time{}
	for _, raw := range rawEvents {
		ev := s.auditToNormalized(tenantID, raw)
		if ev.Timestamp.After(lastEventTS) {
			lastEventTS = ev.Timestamp
		}
		events = append(events, ev)
	}
	inserted, err := s.IngestEvents(ctx, events)
	if err != nil {
		return 0, err
	}
	_ = s.store.UpdateEngineState(ctx, tenantID, nowUTC(), lastEventTS, time.Time{})
	return inserted, nil
}

func (s *Service) RunScanAllTenants(ctx context.Context, syncAudit bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return err
	}
	if len(tenants) == 0 {
		tenants = []string{"root"}
	}
	results := make([]RiskSnapshot, 0, len(tenants))
	for _, tenantID := range tenants {
		tenantID = strings.TrimSpace(tenantID)
		if tenantID == "" {
			continue
		}
		if syncAudit {
			if _, err := s.SyncFromAudit(ctx, tenantID, s.auditSyncLimit); err != nil {
				logger.Printf("audit sync failed tenant=%s: %v", tenantID, err)
			}
		}
		snap, runErr := s.runTenantScan(ctx, tenantID)
		if runErr != nil {
			logger.Printf("tenant posture scan failed tenant=%s: %v", tenantID, runErr)
			continue
		}
		results = append(results, snap)
		_ = s.store.UpdateEngineState(ctx, tenantID, time.Time{}, time.Time{}, nowUTC())
	}
	if len(results) > 0 {
		_ = s.store.CreateRiskSnapshot(ctx, aggregateGlobalRisk(results))
	}
	return nil
}

func (s *Service) RunScanTenant(ctx context.Context, tenantID string, syncAudit bool) (RiskSnapshot, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return RiskSnapshot{}, newServiceError(400, "tenant_required", "tenant_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if syncAudit {
		if _, err := s.SyncFromAudit(ctx, tenantID, s.auditSyncLimit); err != nil {
			return RiskSnapshot{}, err
		}
	}
	snap, err := s.runTenantScan(ctx, tenantID)
	if err != nil {
		return RiskSnapshot{}, err
	}
	_ = s.store.UpdateEngineState(ctx, tenantID, time.Time{}, time.Time{}, nowUTC())
	return snap, nil
}

func (s *Service) runTenantScan(ctx context.Context, tenantID string) (RiskSnapshot, error) {
	now := nowUTC()
	current24, err := s.store.GetSignalSummary(ctx, tenantID, now.Add(-24*time.Hour), now)
	if err != nil {
		return RiskSnapshot{}, err
	}
	prev24, err := s.store.GetSignalSummary(ctx, tenantID, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if err != nil {
		return RiskSnapshot{}, err
	}
	current7d, err := s.store.GetSignalSummary(ctx, tenantID, now.Add(-7*24*time.Hour), now)
	if err != nil {
		return RiskSnapshot{}, err
	}
	prev7d, err := s.store.GetSignalSummary(ctx, tenantID, now.Add(-14*24*time.Hour), now.Add(-7*24*time.Hour))
	if err != nil {
		return RiskSnapshot{}, err
	}

	type engineOut struct {
		name       string
		score      int
		findings   []FindingCandidate
		actions    []ActionCandidate
		err        error
		signalData map[string]interface{}
	}
	outCh := make(chan engineOut, 3)
	go func() {
		findings, score, signalData := s.predictiveEngine(tenantID, current24, prev24, current7d, prev7d)
		outCh <- engineOut{name: "predictive", score: score, findings: findings, signalData: signalData}
	}()
	go func() {
		findings, score, signalData := s.preventiveEngine(tenantID, current24, prev24)
		outCh <- engineOut{name: "preventive", score: score, findings: findings, signalData: signalData}
	}()
	go func() {
		findings, actions, score, signalData := s.correctiveEngine(ctx, tenantID, now)
		outCh <- engineOut{name: "corrective", score: score, findings: findings, actions: actions, signalData: signalData}
	}()

	engineFindings := make([]FindingCandidate, 0, 24)
	engineActions := make([]ActionCandidate, 0, 24)
	predictiveScore := 0
	preventiveScore := 0
	correctiveScore := 0
	topSignals := map[string]interface{}{}
	for i := 0; i < 3; i++ {
		out := <-outCh
		if out.err != nil {
			logger.Printf("engine %s failed tenant=%s: %v", out.name, tenantID, out.err)
			continue
		}
		engineFindings = append(engineFindings, out.findings...)
		engineActions = append(engineActions, out.actions...)
		switch out.name {
		case "predictive":
			predictiveScore = out.score
		case "preventive":
			preventiveScore = out.score
		case "corrective":
			correctiveScore = out.score
		}
		for k, v := range out.signalData {
			topSignals[k] = v
		}
	}

	findingByFingerprint := map[string]Finding{}
	for _, candidate := range engineFindings {
		candidate.Severity = normalizeSeverity(candidate.Severity)
		candidate.RiskScore = clampRisk(candidate.RiskScore)
		item, err := s.store.UpsertFindingByFingerprint(ctx, tenantID, candidate, now)
		if err != nil {
			logger.Printf("finding upsert failed tenant=%s fp=%s: %v", tenantID, candidate.Fingerprint, err)
			continue
		}
		findingByFingerprint[candidate.Fingerprint] = item
		if err := s.applyPreventiveEnforcement(ctx, tenantID, candidate, item); err != nil {
			logger.Printf("preventive enforcement apply failed tenant=%s finding=%s type=%s: %v", tenantID, item.ID, candidate.FindingType, err)
		}
	}

	for _, candidate := range engineActions {
		fp := strings.TrimSpace(candidate.FindingFingerprint)
		if fp == "" {
			continue
		}
		finding, ok := findingByFingerprint[fp]
		if !ok {
			var err error
			finding, err = s.store.GetFindingByFingerprint(ctx, tenantID, fp)
			if err != nil {
				continue
			}
		}
		action, err := s.store.CreateActionIfAbsent(ctx, tenantID, finding.ID, candidate)
		if err != nil {
			logger.Printf("action create failed tenant=%s finding=%s action=%s: %v", tenantID, finding.ID, candidate.ActionType, err)
			continue
		}
		if s.autoRemediate && !action.ApprovalRequired && action.Status == "suggested" {
			_ = s.ExecuteAction(ctx, tenantID, action.ID, "posture-engine", "")
		}
	}

	risk24 := clampRisk((predictiveScore*45 + preventiveScore*30 + correctiveScore*25) / 100)
	if risk24 == 0 {
		risk24 = clampRisk(current24.TotalEvents / 200)
	}
	risk7 := clampRisk(risk24 + (current7d.TotalEvents-prev7d.TotalEvents)/50 + current7d.ExpiryBacklogCount)

	snap := RiskSnapshot{
		ID:              newID("risk"),
		TenantID:        tenantID,
		Risk24h:         risk24,
		Risk7d:          risk7,
		PredictiveScore: predictiveScore,
		PreventiveScore: preventiveScore,
		CorrectiveScore: correctiveScore,
		TopSignals: mergeTopSignals(topSignals, map[string]interface{}{
			"events_24h":              current24.TotalEvents,
			"failed_auth_24h":         current24.FailedAuthCount,
			"failed_crypto_24h":       current24.FailedCryptoCount,
			"policy_denies_24h":       current24.PolicyDenyCount,
			"key_deletes_24h":         current24.KeyDeleteCount,
			"cert_deletes_24h":        current24.CertDeleteCount,
			"hsm_latency_avg_ms_24h":  current24.HSMLatencyAvgMS,
			"cluster_lag_avg_ms_24h":  current24.ClusterLagAvgMS,
			"connector_flaps_24h":     current24.ConnectorAuthFlaps,
			"replication_retry_24h":   current24.ReplicationRetry,
			"expiry_backlog_24h":      current24.ExpiryBacklogCount,
			"non_approved_algo_24h":   current24.NonApprovedAlgoCount,
			"tenant_mismatch_24h":     current24.TenantMismatchCount,
			"quorum_bypass_24h":       current24.QuorumBypassCount,
			"cluster_drift_24h":       current24.ClusterDriftCount,
			"byok_events_24h":         current24.BYOKEvents,
			"byok_failures_24h":       current24.BYOKFailures,
			"hyok_events_24h":         current24.HYOKEvents,
			"hyok_failures_24h":       current24.HYOKFailures,
			"ekm_events_24h":          current24.EKMEvents,
			"ekm_failures_24h":        current24.EKMFailures,
			"kmip_events_24h":         current24.KMIPEvents,
			"kmip_failures_24h":       current24.KMIPFailures,
			"kmip_interop_failed_24h": current24.KMIPInteropFailures,
			"bitlocker_events_24h":    current24.BitLockerEvents,
			"bitlocker_failures_24h":  current24.BitLockerFailures,
			"sdk_events_24h":          current24.SDKEvents,
			"sdk_failures_24h":        current24.SDKFailures,
			"sdk_receipt_missing_24h": current24.SDKReceiptMissing,
			"domain_metrics":          buildDomainMetrics(current24),
			"risk_horizon_24h":        risk24,
			"risk_horizon_7d":         risk7,
		}),
		CapturedAt: now,
	}
	if err := s.store.CreateRiskSnapshot(ctx, snap); err != nil {
		return RiskSnapshot{}, err
	}
	_ = s.publish(ctx, "audit.posture.risk_snapshot", tenantID, map[string]interface{}{
		"risk_24h":         snap.Risk24h,
		"risk_7d":          snap.Risk7d,
		"predictive_score": snap.PredictiveScore,
		"preventive_score": snap.PreventiveScore,
		"corrective_score": snap.CorrectiveScore,
		"captured_at":      snap.CapturedAt.Format(time.RFC3339),
	})
	return snap, nil
}

func (s *Service) applyPreventiveEnforcement(ctx context.Context, tenantID string, candidate FindingCandidate, finding Finding) error {
	if s.governance == nil {
		return nil
	}
	if strings.TrimSpace(candidate.Engine) != "preventive" {
		return nil
	}
	patch := PostureControlPatch{
		UpdatedBy:       "posture-engine",
		Reason:          strings.TrimSpace(candidate.RecommendedAction),
		SourceFindingID: strings.TrimSpace(finding.ID),
	}
	switch strings.TrimSpace(candidate.FindingType) {
	case "force_quorum_destructive_ops":
		v := true
		patch.ForceQuorumDestructiveOps = &v
	case "step_up_auth_required":
		v := true
		patch.RequireStepUpAuth = &v
	case "disable_connector_sync_temporarily":
		v := true
		patch.PauseConnectorSync = &v
	case "guardrail_policy_autocreate":
		v := true
		patch.GuardrailPolicyRequired = &v
	default:
		return nil
	}
	if err := s.governance.ApplyPostureControls(ctx, patch); err != nil {
		return err
	}
	_ = s.publish(ctx, "audit.posture.preventive_controls_applied", tenantID, map[string]interface{}{
		"finding_id":   finding.ID,
		"finding_type": candidate.FindingType,
		"controls_patch": map[string]bool{
			"force_quorum_destructive_ops": patch.ForceQuorumDestructiveOps != nil && *patch.ForceQuorumDestructiveOps,
			"require_step_up_auth":         patch.RequireStepUpAuth != nil && *patch.RequireStepUpAuth,
			"pause_connector_sync":         patch.PauseConnectorSync != nil && *patch.PauseConnectorSync,
			"guardrail_policy_required":    patch.GuardrailPolicyRequired != nil && *patch.GuardrailPolicyRequired,
		},
	})
	return nil
}

func (s *Service) predictiveEngine(tenantID string, current24 SignalSummary, prev24 SignalSummary, current7d SignalSummary, prev7d SignalSummary) ([]FindingCandidate, int, map[string]interface{}) {
	findings := make([]FindingCandidate, 0, 10)
	score := 0
	signal := map[string]interface{}{
		"predictive_failed_auth":        current24.FailedAuthCount,
		"predictive_failed_crypto":      current24.FailedCryptoCount,
		"predictive_policy_denies":      current24.PolicyDenyCount,
		"predictive_hsm_latency_ms":     current24.HSMLatencyAvgMS,
		"predictive_cluster_lag_ms":     current24.ClusterLagAvgMS,
		"predictive_expiry_backlog":     current24.ExpiryBacklogCount,
		"predictive_connector_flaps":    current24.ConnectorAuthFlaps,
		"predictive_byok_failures":      current24.BYOKFailures,
		"predictive_hyok_failures":      current24.HYOKFailures,
		"predictive_ekm_failures":       current24.EKMFailures,
		"predictive_kmip_failures":      current24.KMIPFailures,
		"predictive_bitlocker_failures": current24.BitLockerFailures,
		"predictive_sdk_failures":       current24.SDKFailures,
	}

	if isSpike(current24.FailedAuthCount, prev24.FailedAuthCount, 25, 2.0) {
		risk := clampRisk(30 + current24.FailedAuthCount/2)
		score += risk / 3
		findings = append(findings, FindingCandidate{
			Engine:            "predictive",
			FindingType:       "auth_failure_spike",
			Title:             "Failed authentication spike detected",
			Description:       fmt.Sprintf("Auth failures increased from %d to %d in the last 24h.", prev24.FailedAuthCount, current24.FailedAuthCount),
			Severity:          severityHigh,
			RiskScore:         risk,
			RecommendedAction: "Raise step-up authentication and tighten rate limits for high-risk actors.",
			AutoActionAllowed: false,
			Fingerprint:       fingerprint(tenantID, "predictive", "auth_failure_spike"),
			Evidence: map[string]interface{}{
				"current_24h": current24.FailedAuthCount,
				"prev_24h":    prev24.FailedAuthCount,
			},
		})
	}

	if isSpike(current24.FailedCryptoCount, prev24.FailedCryptoCount, 10, 1.8) {
		risk := clampRisk(25 + current24.FailedCryptoCount)
		score += risk / 3
		findings = append(findings, FindingCandidate{
			Engine:            "predictive",
			FindingType:       "crypto_failure_spike",
			Title:             "Decrypt/unwrap failure spike detected",
			Description:       "Local and remote crypto failures indicate possible key drift, policy mismatch, or tampering attempts.",
			Severity:          severityHigh,
			RiskScore:         risk,
			RecommendedAction: "Check key state drift, connector integrity, and enforce fallback to centralized KMS path for affected operations.",
			AutoActionAllowed: false,
			Fingerprint:       fingerprint(tenantID, "predictive", "crypto_failure_spike"),
			Evidence: map[string]interface{}{
				"current_24h": current24.FailedCryptoCount,
				"prev_24h":    prev24.FailedCryptoCount,
			},
		})
	}

	if isSpike(current24.PolicyDenyCount, prev24.PolicyDenyCount, 20, 1.7) {
		risk := clampRisk(20 + current24.PolicyDenyCount/2)
		score += risk / 4
		findings = append(findings, FindingCandidate{
			Engine:            "predictive",
			FindingType:       "policy_deny_jump",
			Title:             "Policy deny rate is trending upward",
			Description:       "Sudden deny growth predicts near-term service friction and policy misconfiguration.",
			Severity:          severityWarning,
			RiskScore:         risk,
			RecommendedAction: "Pre-stage policy guardrail review and role alignment before deny volume causes outage.",
			AutoActionAllowed: false,
			Fingerprint:       fingerprint(tenantID, "predictive", "policy_deny_jump"),
			Evidence: map[string]interface{}{
				"current_24h": current24.PolicyDenyCount,
				"prev_24h":    prev24.PolicyDenyCount,
			},
		})
	}

	if current24.HSMLatencyAvgMS >= 250 && (current24.HSMLatencyAvgMS > prev24.HSMLatencyAvgMS*1.25 || prev24.HSMLatencyAvgMS == 0) {
		risk := clampRisk(35 + int(current24.HSMLatencyAvgMS/20))
		score += risk / 2
		findings = append(findings, FindingCandidate{
			Engine:            "predictive",
			FindingType:       "hsm_latency_rising",
			Title:             "HSM latency degradation trend",
			Description:       fmt.Sprintf("Average HSM latency is %.1f ms (previous %.1f ms).", current24.HSMLatencyAvgMS, prev24.HSMLatencyAvgMS),
			Severity:          severityHigh,
			RiskScore:         risk,
			RecommendedAction: "Prepare HSM failover profile and reduce high-cost key operations before throughput collapse.",
			AutoActionAllowed: false,
			Fingerprint:       fingerprint(tenantID, "predictive", "hsm_latency_rising"),
			Evidence: map[string]interface{}{
				"hsm_latency_avg_ms_current": current24.HSMLatencyAvgMS,
				"hsm_latency_avg_ms_prev":    prev24.HSMLatencyAvgMS,
			},
		})
	}

	if current24.ClusterLagAvgMS >= 120 && current24.ReplicationRetry >= 5 {
		risk := clampRisk(40 + current24.ReplicationRetry*2)
		score += risk / 2
		findings = append(findings, FindingCandidate{
			Engine:            "predictive",
			FindingType:       "cluster_sync_degradation",
			Title:             "Cluster sync degradation leading signal",
			Description:       "Replication retries and lag indicate near-term profile drift or follower staleness.",
			Severity:          severityHigh,
			RiskScore:         risk,
			RecommendedAction: "Throttle write burst, validate mTLS link health, and prioritize sync queue reconciliation.",
			AutoActionAllowed: false,
			Fingerprint:       fingerprint(tenantID, "predictive", "cluster_sync_degradation"),
			Evidence: map[string]interface{}{
				"cluster_lag_avg_ms_24h": current24.ClusterLagAvgMS,
				"replication_retry_24h":  current24.ReplicationRetry,
			},
		})
	}

	if isSpike(current24.ConnectorAuthFlaps, prev24.ConnectorAuthFlaps, 6, 1.5) {
		risk := clampRisk(30 + current24.ConnectorAuthFlaps*3)
		score += risk / 3
		findings = append(findings, FindingCandidate{
			Engine:            "predictive",
			FindingType:       "connector_auth_flap",
			Title:             "Connector authentication instability",
			Description:       "Auth flaps across external connectors predict sync failure and stale key inventory.",
			Severity:          severityWarning,
			RiskScore:         risk,
			RecommendedAction: "Temporarily gate connector sync and rotate connector credentials in maintenance window.",
			AutoActionAllowed: true,
			Fingerprint:       fingerprint(tenantID, "predictive", "connector_auth_flap"),
			Evidence: map[string]interface{}{
				"current_24h": current24.ConnectorAuthFlaps,
				"prev_24h":    prev24.ConnectorAuthFlaps,
			},
		})
	}

	domainFinding := func(domainID string, domainLabel string, currentEvents int, currentFailures int, previousEvents int, previousFailures int, recommendedAction string, extraEvidence map[string]interface{}) {
		if currentFailures <= 0 {
			return
		}
		failureRate := float64(currentFailures) / float64(max(1, currentEvents))
		previousFailureRate := float64(previousFailures) / float64(max(1, previousEvents))
		if currentFailures < 3 && failureRate < 0.15 {
			return
		}
		if !(failureRate >= 0.12 || isSpike(currentFailures, previousFailures, 3, 1.4)) {
			return
		}

		risk := clampRisk(28 + currentFailures*8 + int(failureRate*55))
		severity := severityWarning
		if failureRate >= 0.25 || currentFailures >= 10 {
			severity = severityHigh
		}
		score += risk / 3

		evidence := map[string]interface{}{
			"domain":                    domainID,
			"events_24h":                currentEvents,
			"failures_24h":              currentFailures,
			"failure_rate_24h":          failureRate,
			"events_prev_24h":           previousEvents,
			"failures_prev_24h":         previousFailures,
			"failure_rate_prev_24h":     previousFailureRate,
			"failure_rate_delta_points": (failureRate - previousFailureRate) * 100,
		}
		for k, v := range extraEvidence {
			evidence[k] = v
		}

		findings = append(findings, FindingCandidate{
			Engine:            "predictive",
			FindingType:       fmt.Sprintf("domain_%s_instability", domainID),
			Title:             fmt.Sprintf("%s posture instability", domainLabel),
			Description:       fmt.Sprintf("%s failures are elevated in the last 24h and can impact key operations and policy enforcement.", domainLabel),
			Severity:          severity,
			RiskScore:         risk,
			RecommendedAction: recommendedAction,
			AutoActionAllowed: true,
			Fingerprint:       fingerprint(tenantID, "predictive", fmt.Sprintf("domain_%s_instability", domainID)),
			Evidence:          evidence,
		})
	}

	domainFinding(
		"byok",
		"BYOK",
		current24.BYOKEvents,
		current24.BYOKFailures,
		prev24.BYOKEvents,
		prev24.BYOKFailures,
		"Validate cloud connector auth/region config and pause sync for unstable connectors until auth succeeds.",
		map[string]interface{}{"latency_avg_ms_24h": current24.BYOKLatencyAvgMS},
	)
	domainFinding(
		"hyok",
		"HYOK",
		current24.HYOKEvents,
		current24.HYOKFailures,
		prev24.HYOKEvents,
		prev24.HYOKFailures,
		"Review HYOK endpoint trust chain, denied requests, and fallback policy before unwrap/wrap backlog increases.",
		map[string]interface{}{"latency_avg_ms_24h": current24.HYOKLatencyAvgMS},
	)
	domainFinding(
		"ekm",
		"EKM",
		current24.EKMEvents,
		current24.EKMFailures,
		prev24.EKMEvents,
		prev24.EKMFailures,
		"Check EKM agent heartbeat/disconnect state and rotate affected TDE connector credentials.",
		map[string]interface{}{"latency_avg_ms_24h": current24.EKMLatencyAvgMS},
	)
	domainFinding(
		"kmip",
		"KMIP",
		current24.KMIPEvents,
		current24.KMIPFailures,
		prev24.KMIPEvents,
		prev24.KMIPFailures,
		"Run KMIP interop validation and enforce mTLS profile alignment for client profiles with failures.",
		map[string]interface{}{
			"latency_avg_ms_24h":  current24.KMIPLatencyAvgMS,
			"interop_failed_24h":  current24.KMIPInteropFailures,
			"interop_failed_prev": prev24.KMIPInteropFailures,
		},
	)
	domainFinding(
		"bitlocker",
		"BitLocker",
		current24.BitLockerEvents,
		current24.BitLockerFailures,
		prev24.BitLockerEvents,
		prev24.BitLockerFailures,
		"Reconcile BitLocker client heartbeat and job delivery state before protection posture degrades further.",
		map[string]interface{}{"latency_avg_ms_24h": current24.BitLockerLatencyAvgMS},
	)
	domainFinding(
		"sdk",
		"SDK / Wrapper",
		current24.SDKEvents,
		current24.SDKFailures,
		prev24.SDKEvents,
		prev24.SDKFailures,
		"Review wrapper lease/receipt pipeline and enforce remote fallback for SDK flows showing repeated failures.",
		map[string]interface{}{
			"latency_avg_ms_24h":  current24.SDKLatencyAvgMS,
			"receipt_missing_24h": current24.SDKReceiptMissing,
		},
	)

	if current24.KMIPInteropFailures > 0 {
		risk := clampRisk(52 + current24.KMIPInteropFailures*9)
		score += risk / 2
		findings = append(findings, FindingCandidate{
			Engine:            "predictive",
			FindingType:       "kmip_interop_validation_failures",
			Title:             "KMIP interoperability validations are failing",
			Description:       "DiscoverVersions/Query/mTLS or test key operations failed for one or more KMIP integration targets.",
			Severity:          severityHigh,
			RiskScore:         risk,
			RecommendedAction: "Run KMIP Interop Validation per target and block production onboarding for failed targets until verified.",
			AutoActionAllowed: false,
			Fingerprint:       fingerprint(tenantID, "predictive", "kmip_interop_validation_failures"),
			Evidence: map[string]interface{}{
				"interop_failed_24h": current24.KMIPInteropFailures,
				"kmip_failures_24h":  current24.KMIPFailures,
			},
		})
	}

	if current24.SDKReceiptMissing > 0 {
		risk := clampRisk(58 + current24.SDKReceiptMissing*10)
		score += risk / 2
		findings = append(findings, FindingCandidate{
			Engine:            "predictive",
			FindingType:       "sdk_missing_receipts",
			Title:             "SDK usage receipts missing for local crypto operations",
			Description:       "Wrapper lease receipts are missing, indicating potential offline/tampered local crypto activity.",
			Severity:          severityHigh,
			RiskScore:         risk,
			RecommendedAction: "Revoke stale leases, force remote KMS crypto path, and re-register affected wrappers.",
			AutoActionAllowed: false,
			Fingerprint:       fingerprint(tenantID, "predictive", "sdk_missing_receipts"),
			Evidence: map[string]interface{}{
				"receipt_missing_24h": current24.SDKReceiptMissing,
				"sdk_failures_24h":    current24.SDKFailures,
			},
		})
	}

	if current24.ExpiryBacklogCount >= 20 || current7d.ExpiryBacklogCount > prev7d.ExpiryBacklogCount+10 {
		risk := clampRisk(20 + current24.ExpiryBacklogCount*2)
		score += risk / 4
		findings = append(findings, FindingCandidate{
			Engine:            "predictive",
			FindingType:       "expiry_backlog_forecast",
			Title:             "Certificate/key expiry backlog forecast",
			Description:       "Expiry-related events predict policy breach within the next 7 days.",
			Severity:          severityWarning,
			RiskScore:         risk,
			RecommendedAction: "Open preemptive rotation windows by tenant/service and enforce renewal backlog burn-down.",
			AutoActionAllowed: true,
			Fingerprint:       fingerprint(tenantID, "predictive", "expiry_backlog_forecast"),
			Evidence: map[string]interface{}{
				"expiry_24h": current24.ExpiryBacklogCount,
				"expiry_7d":  current7d.ExpiryBacklogCount,
			},
		})
	}

	if current24.NonApprovedAlgoCount > 0 {
		risk := clampRisk(70 + current24.NonApprovedAlgoCount*5)
		score += risk / 2
		findings = append(findings, FindingCandidate{
			Engine:            "predictive",
			FindingType:       "non_approved_algo_fips_strict",
			Title:             "Non-approved algorithm usage under FIPS strict",
			Description:       "FIPS strict mode violation signals non-approved cryptographic algorithm attempts.",
			Severity:          severityCritical,
			RiskScore:         risk,
			RecommendedAction: "Block offending algorithm path, quarantine caller profile, and require governance approval for overrides.",
			AutoActionAllowed: false,
			Fingerprint:       fingerprint(tenantID, "predictive", "non_approved_algo_fips_strict"),
			Evidence: map[string]interface{}{
				"count_24h": current24.NonApprovedAlgoCount,
			},
		})
	}

	if isSpike(current24.KeyDeleteCount+current24.CertDeleteCount, prev24.KeyDeleteCount+prev24.CertDeleteCount, 5, 2.0) {
		totalCurrent := current24.KeyDeleteCount + current24.CertDeleteCount
		totalPrev := prev24.KeyDeleteCount + prev24.CertDeleteCount
		risk := clampRisk(45 + totalCurrent*4)
		score += risk / 2
		findings = append(findings, FindingCandidate{
			Engine:            "predictive",
			FindingType:       "deletion_velocity_anomaly",
			Title:             "Key/certificate deletion velocity anomaly",
			Description:       fmt.Sprintf("Deletion activity increased from %d to %d in the last 24h.", totalPrev, totalCurrent),
			Severity:          severityCritical,
			RiskScore:         risk,
			RecommendedAction: "Force quorum on destructive operations and freeze non-essential delete endpoints.",
			AutoActionAllowed: false,
			Fingerprint:       fingerprint(tenantID, "predictive", "deletion_velocity_anomaly"),
			Evidence: map[string]interface{}{
				"deleted_keys_24h":   current24.KeyDeleteCount,
				"deleted_certs_24h":  current24.CertDeleteCount,
				"deleted_total_prev": totalPrev,
			},
		})
	}

	if current24.QuorumBypassCount > 0 {
		risk := clampRisk(60 + current24.QuorumBypassCount*8)
		score += risk / 2
		findings = append(findings, FindingCandidate{
			Engine:            "predictive",
			FindingType:       "quorum_bypass_attempts",
			Title:             "Quorum bypass attempts detected",
			Description:       "Repeated denied votes or bypass attempts indicate control-plane abuse pressure.",
			Severity:          severityCritical,
			RiskScore:         risk,
			RecommendedAction: "Require AND-quorum with step-up auth and lock risky administrative flows pending review.",
			AutoActionAllowed: false,
			Fingerprint:       fingerprint(tenantID, "predictive", "quorum_bypass_attempts"),
			Evidence: map[string]interface{}{
				"count_24h": current24.QuorumBypassCount,
			},
		})
	}

	if current24.TenantMismatchCount > 0 {
		risk := clampRisk(80 + current24.TenantMismatchCount*4)
		score += risk / 2
		findings = append(findings, FindingCandidate{
			Engine:            "predictive",
			FindingType:       "tenant_isolation_violation_pattern",
			Title:             "Tenant isolation violation pattern",
			Description:       "tenant_id mismatch patterns indicate cross-tenant access anomalies.",
			Severity:          severityCritical,
			RiskScore:         risk,
			RecommendedAction: "Quarantine offending clients, enforce tenant-scoped token re-issue, and block suspect requests.",
			AutoActionAllowed: false,
			Fingerprint:       fingerprint(tenantID, "predictive", "tenant_isolation_violation_pattern"),
			Evidence: map[string]interface{}{
				"count_24h": current24.TenantMismatchCount,
			},
		})
	}

	if current24.ClusterDriftCount > 0 {
		risk := clampRisk(50 + current24.ClusterDriftCount*5)
		score += risk / 2
		findings = append(findings, FindingCandidate{
			Engine:            "predictive",
			FindingType:       "cluster_state_drift",
			Title:             "Cluster profile drift detected",
			Description:       "Leader/follower profile drift threatens consistency guarantees for selected component sync.",
			Severity:          severityHigh,
			RiskScore:         risk,
			RecommendedAction: "Run selective component drift reconciliation and validate sync envelope integrity.",
			AutoActionAllowed: false,
			Fingerprint:       fingerprint(tenantID, "predictive", "cluster_state_drift"),
			Evidence: map[string]interface{}{
				"count_24h": current24.ClusterDriftCount,
			},
		})
	}

	return findings, clampRisk(score), signal
}

func (s *Service) preventiveEngine(tenantID string, current24 SignalSummary, prev24 SignalSummary) ([]FindingCandidate, int, map[string]interface{}) {
	findings := make([]FindingCandidate, 0, 8)
	score := 0
	totalDeletes := current24.KeyDeleteCount + current24.CertDeleteCount
	if totalDeletes >= 5 {
		risk := clampRisk(45 + totalDeletes*3)
		score += risk / 2
		findings = append(findings, FindingCandidate{
			Engine:            "preventive",
			FindingType:       "force_quorum_destructive_ops",
			Title:             "Pre-block: destructive ops should require quorum",
			Description:       "Deletion volume crossed preventive guardrail threshold.",
			Severity:          severityHigh,
			RiskScore:         risk,
			RecommendedAction: "Enable force quorum for destructive actions in governance policy.",
			AutoActionAllowed: false,
			Fingerprint:       fingerprint(tenantID, "preventive", "force_quorum_destructive_ops"),
			Evidence: map[string]interface{}{
				"delete_volume_24h": totalDeletes,
			},
		})
	}

	if current24.FailedAuthCount >= 20 {
		risk := clampRisk(30 + current24.FailedAuthCount/2)
		score += risk / 3
		findings = append(findings, FindingCandidate{
			Engine:            "preventive",
			FindingType:       "step_up_auth_required",
			Title:             "Pre-block: require step-up authentication",
			Description:       "Authentication failure pressure suggests credential abuse or brute-force attempts.",
			Severity:          severityWarning,
			RiskScore:         risk,
			RecommendedAction: "Require step-up auth for admin/destructive/API high-risk operations.",
			AutoActionAllowed: true,
			Fingerprint:       fingerprint(tenantID, "preventive", "step_up_auth_required"),
			Evidence: map[string]interface{}{
				"failed_auth_24h": current24.FailedAuthCount,
			},
		})
	}

	if current24.ConnectorAuthFlaps >= 8 {
		risk := clampRisk(35 + current24.ConnectorAuthFlaps*3)
		score += risk / 3
		findings = append(findings, FindingCandidate{
			Engine:            "preventive",
			FindingType:       "disable_connector_sync_temporarily",
			Title:             "Pre-block: pause unstable connector sync",
			Description:       "Connector auth instability can create stale inventory and repeated failed jobs.",
			Severity:          severityWarning,
			RiskScore:         risk,
			RecommendedAction: "Temporarily disable connector sync, rotate connector credentials, then resume.",
			AutoActionAllowed: true,
			Fingerprint:       fingerprint(tenantID, "preventive", "disable_connector_sync_temporarily"),
			Evidence: map[string]interface{}{
				"connector_flaps_24h": current24.ConnectorAuthFlaps,
			},
		})
	}

	if current24.ExpiryBacklogCount >= 10 {
		risk := clampRisk(20 + current24.ExpiryBacklogCount*2)
		score += risk / 4
		findings = append(findings, FindingCandidate{
			Engine:            "preventive",
			FindingType:       "preemptive_rotation_window",
			Title:             "Preemptive rotation window required",
			Description:       "Expiry backlog indicates pending breach risk for key and certificate policies.",
			Severity:          severityWarning,
			RiskScore:         risk,
			RecommendedAction: "Schedule preemptive key/cert rotation windows before policy breach threshold.",
			AutoActionAllowed: true,
			Fingerprint:       fingerprint(tenantID, "preventive", "preemptive_rotation_window"),
			Evidence: map[string]interface{}{
				"expiry_backlog_24h": current24.ExpiryBacklogCount,
			},
		})
	}

	if isSpike(current24.PolicyDenyCount, prev24.PolicyDenyCount, 25, 1.6) {
		risk := clampRisk(25 + current24.PolicyDenyCount/2)
		score += risk / 4
		findings = append(findings, FindingCandidate{
			Engine:            "preventive",
			FindingType:       "guardrail_policy_autocreate",
			Title:             "Guardrail policy recommendation generated",
			Description:       "Policy-deny spike suggests policy drift; guardrail controls should be auto-generated for review.",
			Severity:          severityInfo,
			RiskScore:         risk,
			RecommendedAction: "Auto-create temporary guardrail policy set and route to governance approvals.",
			AutoActionAllowed: false,
			Fingerprint:       fingerprint(tenantID, "preventive", "guardrail_policy_autocreate"),
			Evidence: map[string]interface{}{
				"policy_denies_24h":  current24.PolicyDenyCount,
				"policy_denies_prev": prev24.PolicyDenyCount,
			},
		})
	}

	return findings, clampRisk(score), map[string]interface{}{
		"preventive_delete_volume_24h": totalDeletes,
		"preventive_failed_auth_24h":   current24.FailedAuthCount,
		"preventive_connector_flaps":   current24.ConnectorAuthFlaps,
		"preventive_expiry_backlog":    current24.ExpiryBacklogCount,
	}
}

func (s *Service) correctiveEngine(ctx context.Context, tenantID string, now time.Time) ([]FindingCandidate, []ActionCandidate, int, map[string]interface{}) {
	findings := make([]FindingCandidate, 0, 8)
	actions := make([]ActionCandidate, 0, 8)
	score := 0

	overdue, _ := s.store.ListOverdueFindings(ctx, tenantID, now, 50)
	for _, item := range overdue {
		risk := clampRisk(max(40, item.RiskScore+10))
		score += risk / 4
		fp := fingerprint(tenantID, "corrective", "overdue_sla", item.Fingerprint)
		findings = append(findings, FindingCandidate{
			Engine:            "corrective",
			FindingType:       "remediation_sla_breached",
			Title:             "Remediation SLA breached",
			Description:       fmt.Sprintf("Finding %s exceeded remediation SLA and needs escalation.", item.ID),
			Severity:          severityHigh,
			RiskScore:         risk,
			RecommendedAction: "Escalate remediation ticket and re-open with strict owner assignment.",
			AutoActionAllowed: false,
			Fingerprint:       fp,
			Evidence: map[string]interface{}{
				"source_finding_id": item.ID,
				"sla_due_at":        item.SLADueAt.Format(time.RFC3339),
				"current_status":    item.Status,
			},
		})
		actions = append(actions, ActionCandidate{
			FindingFingerprint: fp,
			ActionType:         "escalate_remediation",
			RecommendedAction:  "Escalate remediation with owner binding and due-date reset.",
			SafetyGate:         "manual",
			ApprovalRequired:   true,
			Evidence: map[string]interface{}{
				"source_finding_id": item.ID,
				"reason":            "sla_breach",
			},
		})
	}

	openFindings, _ := s.store.ListOpenFindings(ctx, tenantID, 200)
	for _, item := range openFindings {
		switch item.FindingType {
		case "connector_auth_flap":
			actions = append(actions, ActionCandidate{
				FindingFingerprint: item.Fingerprint,
				ActionType:         "restart_degraded_connector",
				RecommendedAction:  "Restart degraded connector and validate connector auth material.",
				SafetyGate:         "low-impact",
				ApprovalRequired:   false,
				Evidence: map[string]interface{}{
					"finding_id": item.ID,
				},
			})
			score += 6
		case "hsm_latency_rising":
			actions = append(actions, ActionCandidate{
				FindingFingerprint: item.Fingerprint,
				ActionType:         "failover_hsm_profile",
				RecommendedAction:  "Fail over to standby HSM profile.",
				SafetyGate:         "high-impact",
				ApprovalRequired:   true,
				Evidence: map[string]interface{}{
					"finding_id": item.ID,
				},
			})
			score += 10
		case "non_approved_algo_fips_strict":
			actions = append(actions, ActionCandidate{
				FindingFingerprint: item.Fingerprint,
				ActionType:         "quarantine_nonapproved_policy",
				RecommendedAction:  "Quarantine policy path that triggered non-approved algorithm usage.",
				SafetyGate:         "high-impact",
				ApprovalRequired:   true,
				Evidence: map[string]interface{}{
					"finding_id": item.ID,
				},
			})
			score += 10
		case "tenant_isolation_violation_pattern":
			actions = append(actions, ActionCandidate{
				FindingFingerprint: item.Fingerprint,
				ActionType:         "quarantine_compromised_client_profile",
				RecommendedAction:  "Quarantine compromised client profile and revoke active leases/sessions.",
				SafetyGate:         "high-impact",
				ApprovalRequired:   true,
				Evidence: map[string]interface{}{
					"finding_id": item.ID,
				},
			})
			score += 12
		case "deletion_velocity_anomaly":
			actions = append(actions, ActionCandidate{
				FindingFingerprint: item.Fingerprint,
				ActionType:         "rotate_affected_credentials",
				RecommendedAction:  "Rotate affected credentials and re-check delete permissions.",
				SafetyGate:         "manual",
				ApprovalRequired:   true,
				Evidence: map[string]interface{}{
					"finding_id": item.ID,
				},
			})
			score += 10
		}
	}

	if len(actions) > 1 {
		seen := map[string]struct{}{}
		deduped := make([]ActionCandidate, 0, len(actions))
		for _, item := range actions {
			key := item.FindingFingerprint + "|" + item.ActionType
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			deduped = append(deduped, item)
		}
		actions = deduped
	}

	return findings, actions, clampRisk(score), map[string]interface{}{
		"corrective_overdue_count": len(overdue),
		"corrective_actions":       len(actions),
	}
}

func (s *Service) ExecuteAction(ctx context.Context, tenantID string, actionID string, actor string, approvalRequestID string) error {
	item, err := s.store.GetAction(ctx, tenantID, actionID)
	if err != nil {
		return err
	}
	if item.Status == "executed" {
		return nil
	}
	if item.ApprovalRequired && strings.TrimSpace(approvalRequestID) == "" {
		return newServiceError(409, "approval_required", "approval_request_id is required before execution")
	}
	if strings.TrimSpace(actor) == "" {
		actor = "system"
	}
	_ = s.store.UpdateActionExecution(ctx, tenantID, actionID, "executing", actor, "execution started", approvalRequestID)

	status := "executed"
	result := "runbook dispatched"
	payload := map[string]interface{}{
		"tenant_id":         tenantID,
		"action_id":         actionID,
		"action_type":       item.ActionType,
		"finding_id":        item.FindingID,
		"approval_required": item.ApprovalRequired,
		"approval_id":       approvalRequestID,
		"executed_by":       actor,
		"evidence":          item.Evidence,
	}
	if err := s.publish(ctx, "audit.posture.runbook.execute", tenantID, payload); err != nil {
		status = "failed"
		result = "runbook publish failed: " + err.Error()
	}
	if err := s.store.UpdateActionExecution(ctx, tenantID, actionID, status, actor, result, approvalRequestID); err != nil {
		return err
	}
	return nil
}

func (s *Service) ListFindings(ctx context.Context, tenantID string, q FindingQuery) ([]Finding, error) {
	items, err := s.store.ListFindings(ctx, tenantID, q)
	if err != nil {
		return nil, err
	}
	history, _ := s.store.ListRiskSnapshots(ctx, tenantID, RiskQuery{Limit: 2})
	events := s.fetchRecentAuditEvents(ctx, tenantID, max(250, min(1200, q.Limit*6)))
	return s.enrichFindings(items, events, history), nil
}

func (s *Service) UpdateFindingStatus(ctx context.Context, tenantID string, id string, status string) error {
	return s.store.UpdateFindingStatus(ctx, tenantID, id, status)
}

func (s *Service) ListActions(ctx context.Context, tenantID string, q ActionQuery) ([]RemediationAction, error) {
	items, err := s.store.ListActions(ctx, tenantID, q)
	if err != nil {
		return nil, err
	}
	findings, _ := s.store.ListFindings(ctx, tenantID, FindingQuery{Limit: 500})
	history, _ := s.store.ListRiskSnapshots(ctx, tenantID, RiskQuery{Limit: 2})
	events := s.fetchRecentAuditEvents(ctx, tenantID, max(250, min(1200, q.Limit*6)))
	enrichedFindings := s.enrichFindings(findings, events, history)
	return s.enrichActions(items, enrichedFindings, events), nil
}

func (s *Service) LatestRisk(ctx context.Context, tenantID string) (RiskSnapshot, error) {
	return s.store.GetLatestRiskSnapshot(ctx, tenantID)
}

func (s *Service) RiskHistory(ctx context.Context, tenantID string, q RiskQuery) ([]RiskSnapshot, error) {
	return s.store.ListRiskSnapshots(ctx, tenantID, q)
}

func (s *Service) Dashboard(ctx context.Context, tenantID string) (PostureDashboard, error) {
	risk, err := s.store.GetLatestRiskSnapshot(ctx, tenantID)
	if err != nil {
		if tenantID == "" {
			tenantID = "*"
		}
		risk = RiskSnapshot{TenantID: tenantID}
	}
	history, _ := s.store.ListRiskSnapshots(ctx, tenantID, RiskQuery{Limit: 6})
	findings, err := s.store.ListFindings(ctx, tenantID, FindingQuery{Limit: 80})
	if err != nil {
		return PostureDashboard{}, err
	}
	actions, err := s.store.ListActions(ctx, tenantID, ActionQuery{Limit: 80})
	if err != nil {
		return PostureDashboard{}, err
	}
	events := s.fetchRecentAuditEvents(ctx, tenantID, 1200)
	enrichedFindings := s.enrichFindings(findings, events, history)
	enrichedActions := s.enrichActions(actions, enrichedFindings, events)
	openCount := 0
	criticalCount := 0
	for _, item := range enrichedFindings {
		status := strings.ToLower(strings.TrimSpace(item.Status))
		if status == "open" || status == "reopened" || status == "acknowledged" {
			openCount++
			if normalizeSeverity(item.Severity) == severityCritical {
				criticalCount++
			}
		}
	}
	out := PostureDashboard{
		Risk:               risk,
		RecentFindings:     enrichedFindings,
		PendingActions:     enrichedActions,
		OpenFindings:       openCount,
		CriticalFindings:   criticalCount,
		RiskDrivers:        buildRiskDriverExplainer(risk, history, enrichedFindings),
		RemediationCockpit: buildRemediationCockpit(enrichedActions),
		BlastRadius:        buildBlastRadiusHotspots(enrichedFindings),
		ScenarioSimulator:  buildScenarioSimulator(risk, enrichedActions, enrichedFindings),
		ValidationBadges:   buildValidationBadges(risk, events),
		SLAOverview:        buildSLAOverview(enrichedFindings),
	}
	_ = s.publish(ctx, "audit.posture.dashboard_viewed", tenantID, map[string]interface{}{
		"risk_24h":          out.Risk.Risk24h,
		"open_findings":     out.OpenFindings,
		"critical_findings": out.CriticalFindings,
		"risk_driver_count": len(out.RiskDrivers.Drivers),
		"blast_radius":      len(out.BlastRadius),
		"action_count":      len(out.PendingActions),
	})
	return out, nil
}

func (s *Service) fetchRecentAuditEvents(ctx context.Context, tenantID string, limit int) []map[string]interface{} {
	if s.audit == nil {
		return []map[string]interface{}{}
	}
	if limit <= 0 {
		limit = 500
	}
	items, err := s.audit.ListEvents(ctx, tenantID, limit)
	if err != nil {
		return []map[string]interface{}{}
	}
	sort.Slice(items, func(i, j int) bool {
		return eventTimestamp(items[i]).After(eventTimestamp(items[j]))
	})
	return items
}

func (s *Service) enrichFindings(items []Finding, events []map[string]interface{}, history []RiskSnapshot) []Finding {
	previousRisk := 0
	for _, snap := range history {
		if snap.Risk24h > 0 {
			previousRisk = snap.Risk24h
			break
		}
	}
	out := make([]Finding, 0, len(items))
	for _, item := range items {
		item.RiskDrivers = deriveFindingRiskDrivers(item, previousRisk)
		item.BlastRadius = deriveBlastRadius(item, events)
		out = append(out, item)
	}
	return out
}

func (s *Service) enrichActions(items []RemediationAction, findings []Finding, events []map[string]interface{}) []RemediationAction {
	byID := map[string]Finding{}
	byFingerprint := map[string]Finding{}
	for _, finding := range findings {
		if strings.TrimSpace(finding.ID) != "" {
			byID[finding.ID] = finding
		}
		if strings.TrimSpace(finding.Fingerprint) != "" {
			byFingerprint[finding.Fingerprint] = finding
		}
	}
	out := make([]RemediationAction, 0, len(items))
	for _, item := range items {
		finding, ok := byID[item.FindingID]
		if !ok {
			if fp := firstString(item.Evidence["finding_fingerprint"]); fp != "" {
				finding = byFingerprint[fp]
			}
		}
		if finding.ID == "" {
			finding = Finding{
				ID:          item.FindingID,
				TenantID:    item.TenantID,
				Fingerprint: firstString(item.Evidence["finding_fingerprint"]),
				Evidence:    item.Evidence,
			}
			finding.BlastRadius = deriveBlastRadius(finding, events)
		}
		item.BlastRadius = finding.BlastRadius
		item.ImpactEstimate = deriveActionImpact(item, finding)
		item.RollbackHint = deriveRollbackHint(item)
		item.Priority = deriveActionPriority(item, finding)
		out = append(out, item)
	}
	return out
}

func buildRiskDriverExplainer(risk RiskSnapshot, history []RiskSnapshot, findings []Finding) RiskDriverExplainer {
	current := risk.Risk24h
	previous := 0
	for _, snap := range history {
		if strings.TrimSpace(snap.ID) != "" && snap.ID == risk.ID {
			continue
		}
		if snap.Risk24h > 0 {
			previous = snap.Risk24h
			break
		}
	}
	drivers := make([]RiskDriverContribution, 0, 8)
	for _, finding := range findings {
		status := strings.ToLower(strings.TrimSpace(finding.Status))
		if status == "resolved" {
			continue
		}
		drivers = append(drivers, finding.RiskDrivers...)
	}
	sort.SliceStable(drivers, func(i, j int) bool {
		return drivers[i].DeltaPoints > drivers[j].DeltaPoints
	})
	if len(drivers) > 6 {
		drivers = drivers[:6]
	}
	netDelta := current - previous
	summary := "Risk is stable relative to the previous scan."
	if netDelta > 0 {
		summary = fmt.Sprintf("Risk increased by %d points since the previous scan because of the signals below.", netDelta)
	} else if netDelta < 0 {
		summary = fmt.Sprintf("Risk improved by %d points since the previous scan; remaining drivers are still contributing pressure.", -netDelta)
	}
	return RiskDriverExplainer{
		CurrentRisk24h:  current,
		PreviousRisk24h: previous,
		NetDelta:        netDelta,
		Summary:         summary,
		Drivers:         drivers,
	}
}

func deriveFindingRiskDrivers(item Finding, previousRisk int) []RiskDriverContribution {
	evidence := item.Evidence
	if evidence == nil {
		evidence = map[string]interface{}{}
	}
	domain := normalizeDomain(firstString(evidence["domain"]))
	drivers := make([]RiskDriverContribution, 0, 4)
	add := func(id string, label string, points int, explanation string, driverEvidence map[string]interface{}) {
		if points <= 0 || strings.TrimSpace(explanation) == "" {
			return
		}
		drivers = append(drivers, RiskDriverContribution{
			ID:          id,
			Label:       label,
			Domain:      domain,
			DeltaPoints: points,
			Severity:    normalizeSeverity(item.Severity),
			Explanation: explanation,
			Evidence:    driverEvidence,
		})
	}

	if delta := intAbs(int(extractFloat64(evidence["failure_rate_delta_points"]))); delta > 0 {
		points := min(30, max(6, delta))
		add("failure-rate", "Failure-rate drift", points, fmt.Sprintf("%s failure rate moved by %d points over the previous window.", domainLabel(domain, item.Title), delta), map[string]interface{}{
			"failure_rate_delta_points": extractFloat64(evidence["failure_rate_delta_points"]),
		})
	}
	if interop := extractInt64(evidence["interop_failed_24h"]); interop > 0 {
		points := min(28, int(interop)*6)
		add("kmip-interop", "KMIP interop failures", points, fmt.Sprintf("KMIP validation failed %d time(s) in the last 24h.", interop), map[string]interface{}{
			"interop_failed_24h": interop,
			"kmip_failures_24h":  extractInt64(evidence["kmip_failures_24h"]),
		})
	}
	if receipts := extractInt64(evidence["receipt_missing_24h"]); receipts > 0 {
		points := min(24, int(receipts)*4)
		add("sdk-receipts", "SDK receipt gaps", points, fmt.Sprintf("Wrapper receipts were missing %d time(s), which weakens local operation attestations.", receipts), map[string]interface{}{
			"receipt_missing_24h": receipts,
			"sdk_failures_24h":    extractInt64(evidence["sdk_failures_24h"]),
		})
	}
	if current24 := extractInt64(evidence["current_24h"]); current24 > 0 {
		prev24 := extractInt64(evidence["prev_24h"])
		growth := int(current24 - prev24)
		if growth > 0 {
			points := min(22, max(5, growth))
			add("recent-spike", "24h spike", points, fmt.Sprintf("Signal count increased from %d to %d over the last 24h.", prev24, current24), map[string]interface{}{
				"current_24h": current24,
				"prev_24h":    prev24,
			})
		}
	}
	if count24 := extractInt64(evidence["count_24h"]); count24 > 0 {
		points := min(26, max(6, int(count24)*2))
		add("blocked-attempts", "Blocked attempts", points, fmt.Sprintf("%d blocked or suspicious operation(s) contributed to this finding.", count24), map[string]interface{}{
			"count_24h": count24,
		})
	}
	if len(drivers) == 0 && item.RiskScore > 0 {
		points := max(4, item.RiskScore/4)
		add("risk-score", "Observed risk pressure", points, fmt.Sprintf("This finding currently contributes %d/100 of direct risk pressure.", item.RiskScore), map[string]interface{}{
			"risk_score":       item.RiskScore,
			"previous_risk":    previousRisk,
			"current_severity": item.Severity,
		})
	}
	sort.SliceStable(drivers, func(i, j int) bool {
		return drivers[i].DeltaPoints > drivers[j].DeltaPoints
	})
	return drivers
}

func deriveBlastRadius(item Finding, events []map[string]interface{}) BlastRadius {
	tenants := []string{}
	apps := []string{}
	services := []string{}
	resources := []string{}
	actors := []string{}
	count := 0
	lastSeen := time.Time{}
	for _, ev := range events {
		if !eventMatchesFinding(item, ev) {
			continue
		}
		count++
		ts := eventTimestamp(ev)
		if ts.After(lastSeen) {
			lastSeen = ts
		}
		appendUniqueString(&tenants, firstString(ev["tenant_id"], item.TenantID))
		appendUniqueString(&services, firstString(ev["service"]))
		appendUniqueString(&apps, firstString(ev["app"], ev["client_id"], ev["connector_id"], nestedMapString(ev, "details_json", "app")))
		appendUniqueString(&resources, firstString(ev["resource_id"], ev["target_id"]))
		appendUniqueString(&actors, firstString(ev["actor_id"], ev["user_id"]))
	}
	if len(tenants) == 0 && strings.TrimSpace(item.TenantID) != "" {
		tenants = append(tenants, item.TenantID)
	}
	summary := fmt.Sprintf("%d matched event(s)", count)
	if len(services) > 0 {
		summary = fmt.Sprintf("%d matched event(s) across %d service(s)", count, len(services))
	}
	return BlastRadius{
		Tenants:    tenants,
		Apps:       apps,
		Services:   services,
		Resources:  resources,
		Actors:     actors,
		EventCount: count,
		LastSeenAt: lastSeen,
		Summary:    summary,
	}
}

func buildBlastRadiusHotspots(findings []Finding) []BlastRadius {
	type hotspot struct {
		risk  int
		blast BlastRadius
	}
	hotspots := make([]hotspot, 0, len(findings))
	for _, finding := range findings {
		status := strings.ToLower(strings.TrimSpace(finding.Status))
		if status == "resolved" {
			continue
		}
		blast := finding.BlastRadius
		if blast.EventCount == 0 && len(blast.Services) == 0 && len(blast.Apps) == 0 {
			continue
		}
		blast.Summary = fmt.Sprintf("%s: %s", finding.Title, blast.Summary)
		hotspots = append(hotspots, hotspot{risk: finding.RiskScore, blast: blast})
	}
	sort.SliceStable(hotspots, func(i, j int) bool {
		return hotspots[i].risk > hotspots[j].risk
	})
	out := make([]BlastRadius, 0, min(5, len(hotspots)))
	for _, item := range hotspots {
		out = append(out, item.blast)
		if len(out) >= 5 {
			break
		}
	}
	return out
}

func buildRemediationCockpit(actions []RemediationAction) []RemediationCockpitGroup {
	groups := []RemediationCockpitGroup{
		{ID: "safe-auto-fix", Label: "Safe Auto-Fix", Description: "Low-impact actions that can be executed immediately."},
		{ID: "approval-required", Label: "Approval Required", Description: "High-impact actions that require an approval token before execution."},
		{ID: "manual", Label: "Manual", Description: "Operator-driven runbooks that need investigation or scheduling."},
	}
	addToGroup := func(groupID string, action RemediationAction) {
		for idx := range groups {
			if groups[idx].ID == groupID {
				groups[idx].Actions = append(groups[idx].Actions, action)
				groups[idx].Count++
				return
			}
		}
	}
	for _, action := range actions {
		status := strings.ToLower(strings.TrimSpace(action.Status))
		if status == "executed" {
			continue
		}
		switch {
		case action.ApprovalRequired:
			addToGroup("approval-required", action)
		case strings.EqualFold(action.SafetyGate, "low-impact"):
			addToGroup("safe-auto-fix", action)
		default:
			addToGroup("manual", action)
		}
	}
	return groups
}

func buildScenarioSimulator(risk RiskSnapshot, actions []RemediationAction, findings []Finding) []ScenarioSimulation {
	out := make([]ScenarioSimulation, 0, 6)
	seen := map[string]struct{}{}
	for _, action := range actions {
		status := strings.ToLower(strings.TrimSpace(action.Status))
		if status == "executed" {
			continue
		}
		if _, ok := seen[action.ActionType]; ok {
			continue
		}
		seen[action.ActionType] = struct{}{}
		reduction := max(4, action.ImpactEstimate.RiskReduction)
		projected := max(0, risk.Risk24h-reduction)
		out = append(out, ScenarioSimulation{
			ID:               action.ID,
			Label:            scenarioLabel(action),
			Category:         strings.ReplaceAll(strings.ToLower(strings.TrimSpace(action.SafetyGate)), "-", " "),
			ActionType:       action.ActionType,
			CurrentRisk24h:   risk.Risk24h,
			ProjectedRisk24h: projected,
			RiskDelta:        projected - risk.Risk24h,
			Summary:          fmt.Sprintf("If %s is executed, modeled 24h risk drops from %d to %d.", strings.ToLower(strings.TrimSpace(action.RecommendedAction)), risk.Risk24h, projected),
			ImpactEstimate:   fmt.Sprintf("Estimated reduction: %d points.", reduction),
			RollbackHint:     action.RollbackHint,
			ApprovalRequired: action.ApprovalRequired,
			BasedOn:          summarizeBasedOn(action, findings),
		})
		if len(out) >= 4 {
			break
		}
	}
	return out
}

func buildValidationBadges(risk RiskSnapshot, events []map[string]interface{}) []ValidationBadge {
	domains := []string{"byok", "hyok", "ekm", "kmip", "bitlocker", "sdk"}
	out := make([]ValidationBadge, 0, len(domains)*2)
	now := nowUTC()
	for _, domain := range domains {
		domainEvents := filterDomainEvents(events, domain)
		lastAuthSuccess := latestEventTime(domainEvents, func(ev map[string]interface{}) bool {
			return eventIsSuccess(ev) && eventLooksLikeAuth(ev)
		})
		lastKeySuccess := latestEventTime(domainEvents, func(ev map[string]interface{}) bool {
			return eventIsSuccess(ev) && eventLooksLikeKeyOp(ev)
		})
		failures24h := 0
		for _, ev := range domainEvents {
			if eventIsFailure(ev) && eventTimestamp(ev).After(now.Add(-24*time.Hour)) {
				failures24h++
			}
		}
		authStatus := "unknown"
		authDetail := "No successful connector auth seen recently."
		if !lastAuthSuccess.IsZero() {
			authAge := now.Sub(lastAuthSuccess)
			authStatus = "healthy"
			if authAge > 48*time.Hour {
				authStatus = "stale"
			}
			if failures24h > 0 && authAge > 24*time.Hour {
				authStatus = "failing"
			}
			authDetail = fmt.Sprintf("Last successful auth: %s", lastAuthSuccess.Format(time.RFC3339))
		}
		out = append(out, ValidationBadge{
			Domain:        domain,
			Kind:          "auth_freshness",
			Label:         domainLabel(domain, "") + " auth freshness",
			Status:        authStatus,
			Detail:        authDetail,
			LastCheckedAt: now,
			LastSuccessAt: lastAuthSuccess,
			Metric:        float64(failures24h),
		})

		keyStatus := "unknown"
		keyDetail := "No successful key operation observed recently."
		if !lastKeySuccess.IsZero() {
			keyAge := now.Sub(lastKeySuccess)
			keyStatus = "healthy"
			if keyAge > 72*time.Hour {
				keyStatus = "stale"
			}
			if failures24h > 0 && keyAge > 24*time.Hour {
				keyStatus = "failing"
			}
			keyDetail = fmt.Sprintf("Last successful key operation: %s", lastKeySuccess.Format(time.RFC3339))
		}
		out = append(out, ValidationBadge{
			Domain:        domain,
			Kind:          "last_key_op",
			Label:         domainLabel(domain, "") + " last successful key op",
			Status:        keyStatus,
			Detail:        keyDetail,
			LastCheckedAt: now,
			LastSuccessAt: lastKeySuccess,
			Metric:        float64(extractInt64(risk.TopSignals[domain+"_failures_24h"])),
		})
	}
	return out
}

func buildSLAOverview(findings []Finding) SLAOverview {
	now := nowUTC()
	out := SLAOverview{}
	totalAgeHours := 0.0
	for _, finding := range findings {
		status := strings.ToLower(strings.TrimSpace(finding.Status))
		if status == "resolved" {
			continue
		}
		out.OpenCount++
		if !finding.DetectedAt.IsZero() {
			totalAgeHours += now.Sub(finding.DetectedAt).Hours()
		}
		if !finding.SLADueAt.IsZero() {
			switch {
			case finding.SLADueAt.Before(now):
				out.OverdueCount++
				appendUniqueString(&out.BreachedIDs, finding.ID)
			case finding.SLADueAt.Before(now.Add(24 * time.Hour)):
				out.DueSoonCount++
			}
		}
	}
	if out.OpenCount > 0 {
		out.AverageAgeHours = totalAgeHours / float64(out.OpenCount)
	}
	return out
}

func deriveActionImpact(action RemediationAction, finding Finding) RemediationImpact {
	reduction := max(4, finding.RiskScore/3)
	if strings.EqualFold(action.SafetyGate, "low-impact") {
		reduction = max(5, finding.RiskScore/2)
	}
	if action.ApprovalRequired {
		reduction = max(reduction, 12)
	}
	cost := "low"
	switch strings.ToLower(strings.TrimSpace(action.SafetyGate)) {
	case "high-impact":
		cost = "high"
	case "manual":
		cost = "medium"
	}
	timeToApply := "15-30 minutes"
	if action.ApprovalRequired {
		timeToApply = "approval + maintenance window"
	} else if strings.EqualFold(action.SafetyGate, "low-impact") {
		timeToApply = "under 15 minutes"
	}
	return RemediationImpact{
		RiskReduction:   reduction,
		OperationalCost: cost,
		TimeToApply:     timeToApply,
	}
}

func deriveRollbackHint(action RemediationAction) string {
	switch strings.TrimSpace(action.ActionType) {
	case "restart_degraded_connector":
		return "Re-enable the connector profile and rerun connector auth validation."
	case "failover_hsm_profile":
		return "Switch traffic back to the primary HSM profile after latency stabilizes."
	case "quarantine_nonapproved_policy":
		return "Restore the quarantined policy path after replacing the non-approved algorithm callsite."
	case "quarantine_compromised_client_profile":
		return "Reissue the client profile after session revocation and actor review."
	case "rotate_affected_credentials":
		return "Restore previous credentials only if audit confirms the delete anomaly was a false positive."
	case "escalate_remediation":
		return "Re-open the original remediation item and clear the temporary escalation owner."
	default:
		return "Roll back by restoring the previous connector/profile state after verification."
	}
}

func deriveActionPriority(action RemediationAction, finding Finding) string {
	if action.ApprovalRequired || normalizeSeverity(finding.Severity) == severityCritical {
		return "urgent"
	}
	if strings.EqualFold(action.SafetyGate, "manual") || finding.RiskScore >= 60 {
		return "high"
	}
	return "normal"
}

func scenarioLabel(action RemediationAction) string {
	switch strings.TrimSpace(action.ActionType) {
	case "restart_degraded_connector":
		return "Restart degraded connector"
	case "failover_hsm_profile":
		return "Fail over HSM profile"
	case "quarantine_nonapproved_policy":
		return "Quarantine non-approved policy path"
	case "quarantine_compromised_client_profile":
		return "Quarantine compromised client"
	case "rotate_affected_credentials":
		return "Rotate affected credentials"
	case "escalate_remediation":
		return "Escalate overdue remediation"
	default:
		return strings.ReplaceAll(action.ActionType, "_", " ")
	}
}

func summarizeBasedOn(action RemediationAction, findings []Finding) []string {
	out := []string{}
	for _, finding := range findings {
		if finding.ID != action.FindingID {
			continue
		}
		appendUniqueString(&out, finding.Title)
		if finding.BlastRadius.EventCount > 0 {
			appendUniqueString(&out, fmt.Sprintf("%d matched event(s)", finding.BlastRadius.EventCount))
		}
		for _, driver := range finding.RiskDrivers {
			appendUniqueString(&out, fmt.Sprintf("%s (+%d)", driver.Label, driver.DeltaPoints))
			if len(out) >= 3 {
				return out
			}
		}
	}
	return out
}

func filterDomainEvents(events []map[string]interface{}, domain string) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(events))
	for _, ev := range events {
		if normalizeDomain(domainFromEvent(ev)) == domain {
			out = append(out, ev)
		}
	}
	return out
}

func latestEventTime(events []map[string]interface{}, match func(map[string]interface{}) bool) time.Time {
	latest := time.Time{}
	for _, ev := range events {
		if !match(ev) {
			continue
		}
		ts := eventTimestamp(ev)
		if ts.After(latest) {
			latest = ts
		}
	}
	return latest
}

func eventMatchesFinding(item Finding, ev map[string]interface{}) bool {
	domain := normalizeDomain(firstString(item.Evidence["domain"]))
	action := strings.ToLower(firstString(ev["action"], ev["subject"]))
	service := strings.ToLower(firstString(ev["service"]))
	if domain != "" {
		if strings.Contains(action, domain) || strings.Contains(service, domain) {
			return true
		}
	}
	switch strings.TrimSpace(item.FindingType) {
	case "auth_failure_spike":
		return strings.Contains(action, "auth.login_failed") || service == "auth"
	case "crypto_failure_spike":
		return strings.Contains(action, "decrypt") || strings.Contains(action, "unwrap")
	case "hsm_latency_rising":
		return strings.Contains(action, "hsm.") || service == "hsm"
	case "cluster_sync_degradation", "cluster_state_drift":
		return strings.Contains(action, "cluster.") || strings.Contains(service, "cluster")
	case "connector_auth_flap":
		return eventLooksLikeAuth(ev) && normalizeDomain(domainFromEvent(ev)) != ""
	case "sdk_missing_receipts":
		return strings.Contains(action, "receipt") || strings.Contains(action, "wrapper") || service == "sdk"
	case "kmip_interop_validation_failures":
		return strings.Contains(action, "kmip") || service == "kmip"
	}
	if strings.Contains(strings.ToLower(item.Title), "kmip") && (strings.Contains(action, "kmip") || service == "kmip") {
		return true
	}
	if strings.Contains(strings.ToLower(item.Title), "sdk") && (strings.Contains(action, "sdk") || strings.Contains(action, "wrapper") || service == "sdk") {
		return true
	}
	return false
}

func eventTimestamp(ev map[string]interface{}) time.Time {
	return parseTimeString(firstString(ev["timestamp"], ev["created_at"], ev["event_ts"]))
}

func eventIsFailure(ev map[string]interface{}) bool {
	result := strings.ToLower(firstString(ev["result"], ev["status"]))
	return result == "failure" || result == "failed" || result == "denied" || result == "error"
}

func eventIsSuccess(ev map[string]interface{}) bool {
	result := strings.ToLower(firstString(ev["result"], ev["status"]))
	return result == "" || result == "success" || result == "ok" || result == "passed" || result == "verified"
}

func eventLooksLikeAuth(ev map[string]interface{}) bool {
	action := strings.ToLower(firstString(ev["action"], ev["subject"]))
	return strings.Contains(action, "auth") || strings.Contains(action, "mtls") || strings.Contains(action, "token")
}

func eventLooksLikeKeyOp(ev map[string]interface{}) bool {
	action := strings.ToLower(firstString(ev["action"], ev["subject"]))
	return strings.Contains(action, "key.") || strings.Contains(action, "wrap") || strings.Contains(action, "unwrap") || strings.Contains(action, "encrypt") || strings.Contains(action, "decrypt") || strings.Contains(action, "sign") || strings.Contains(action, "rotate")
}

func domainFromEvent(ev map[string]interface{}) string {
	service := strings.ToLower(firstString(ev["service"]))
	action := strings.ToLower(firstString(ev["action"], ev["subject"]))
	switch {
	case strings.Contains(service, "cloud") || strings.Contains(action, "byok") || strings.Contains(action, "cloud."):
		return "byok"
	case strings.Contains(service, "hyok") || strings.Contains(action, "hyok."):
		return "hyok"
	case strings.Contains(service, "ekm") || strings.Contains(action, "ekm."):
		return "ekm"
	case strings.Contains(service, "kmip") || strings.Contains(action, "kmip."):
		return "kmip"
	case strings.Contains(service, "bitlocker") || strings.Contains(action, "bitlocker"):
		return "bitlocker"
	case strings.Contains(service, "sdk") || strings.Contains(action, "sdk.") || strings.Contains(action, "wrapper"):
		return "sdk"
	default:
		return ""
	}
}

func normalizeDomain(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "sdk / wrapper":
		return "sdk"
	default:
		return strings.ReplaceAll(v, " ", "")
	}
}

func domainLabel(domain string, fallback string) string {
	switch domain {
	case "byok":
		return "BYOK"
	case "hyok":
		return "HYOK"
	case "ekm":
		return "EKM"
	case "kmip":
		return "KMIP"
	case "bitlocker":
		return "BitLocker"
	case "sdk":
		return "SDK"
	default:
		if strings.TrimSpace(fallback) != "" {
			return fallback
		}
		return "This domain"
	}
}

func nestedMapString(ev map[string]interface{}, key string, nested string) string {
	if ev == nil {
		return ""
	}
	if raw, ok := ev[key].(map[string]interface{}); ok {
		return firstString(raw[nested])
	}
	return ""
}

func appendUniqueString(target *[]string, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	for _, item := range *target {
		if strings.EqualFold(strings.TrimSpace(item), value) {
			return
		}
	}
	*target = append(*target, value)
}

func extractFloat64(v interface{}) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	case string:
		var out float64
		_, _ = fmt.Sscanf(strings.TrimSpace(x), "%f", &out)
		return out
	default:
		return 0
	}
}

func extractInt64(v interface{}) int64 {
	switch x := v.(type) {
	case int:
		return int64(x)
	case int64:
		return x
	case float64:
		return int64(x)
	case float32:
		return int64(x)
	case json.Number:
		n, _ := x.Int64()
		return n
	case string:
		var out int64
		_, _ = fmt.Sscanf(strings.TrimSpace(x), "%d", &out)
		return out
	default:
		return 0
	}
}

func intAbs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func (s *Service) normalizeEvent(in NormalizedEvent) (NormalizedEvent, error) {
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.Service = strings.ToLower(strings.TrimSpace(in.Service))
	in.Action = strings.ToLower(strings.TrimSpace(in.Action))
	in.Result = strings.ToLower(strings.TrimSpace(in.Result))
	in.Actor = strings.TrimSpace(in.Actor)
	in.IP = strings.TrimSpace(in.IP)
	in.RequestID = strings.TrimSpace(in.RequestID)
	in.ResourceID = strings.TrimSpace(in.ResourceID)
	in.ErrorCode = strings.TrimSpace(in.ErrorCode)
	in.NodeID = strings.TrimSpace(in.NodeID)
	in.Severity = normalizeSeverity(firstNonEmpty(in.Severity, statusToSeverity(in.Result)))

	if in.TenantID == "" {
		return NormalizedEvent{}, newServiceError(400, "schema_violation", "tenant_id is required")
	}
	if in.Service == "" {
		return NormalizedEvent{}, newServiceError(400, "schema_violation", "service is required")
	}
	if in.Action == "" {
		return NormalizedEvent{}, newServiceError(400, "schema_violation", "action is required")
	}
	if in.Result == "" {
		in.Result = "success"
	}
	if in.Timestamp.IsZero() {
		in.Timestamp = nowUTC()
	}
	if in.Details == nil {
		in.Details = map[string]interface{}{}
	}
	return in, nil
}

func (s *Service) auditToNormalized(tenantID string, raw map[string]interface{}) NormalizedEvent {
	ts := parseTimeValue(raw["timestamp"])
	if ts.IsZero() {
		ts = nowUTC()
	}
	result := strings.ToLower(firstNonEmpty(
		firstString(raw["result"]),
		func() string {
			if parseInt(raw["status_code"]) >= 400 {
				return "failure"
			}
			return "success"
		}(),
	))
	errorCode := firstString(raw["error_code"])
	if errorCode == "" && parseInt(raw["status_code"]) >= 400 {
		errorCode = fmt.Sprintf("http_%d", parseInt(raw["status_code"]))
	}
	sev := normalizeSeverity(firstString(raw["severity"]))
	if sev == severityInfo {
		sev = normalizeSeverity(statusToSeverity(result))
	}

	details := map[string]interface{}{}
	if rawDetails, ok := raw["details"].(map[string]interface{}); ok && rawDetails != nil {
		for k, v := range rawDetails {
			details[k] = v
		}
	}
	if fipsStrict, ok := details["fips_strict"]; ok && parseBool(fipsStrict) {
		algo := strings.ToUpper(firstString(details["algorithm"], raw["algorithm"]))
		if algo != "" && !isFIPSApprovedAlgorithm(algo) {
			errorCode = "fips_non_approved_algorithm"
		}
	}
	if eventTenant := strings.TrimSpace(firstString(raw["tenant_id"])); eventTenant != "" && eventTenant != strings.TrimSpace(tenantID) {
		errorCode = "tenant_mismatch"
	}
	return NormalizedEvent{
		ID:         firstString(raw["id"]),
		Timestamp:  ts,
		TenantID:   strings.TrimSpace(firstNonEmpty(firstString(raw["tenant_id"]), tenantID)),
		Service:    firstNonEmpty(firstString(raw["service"]), "unknown"),
		Action:     firstNonEmpty(firstString(raw["action"]), "unknown.action"),
		Result:     firstNonEmpty(result, "success"),
		Severity:   sev,
		Actor:      firstString(raw["actor_id"], raw["user_id"]),
		IP:         firstString(raw["source_ip"], raw["ip"]),
		RequestID:  firstString(raw["request_id"], raw["correlation_id"], raw["id"]),
		ResourceID: firstString(raw["target_id"], raw["resource_id"]),
		ErrorCode:  errorCode,
		LatencyMS:  parseFloat(raw["duration_ms"]),
		NodeID:     firstString(raw["node_id"]),
		Details:    details,
	}
}

func isFIPSApprovedAlgorithm(algo string) bool {
	algo = strings.ToUpper(strings.TrimSpace(algo))
	if algo == "" {
		return true
	}
	allowed := []string{
		"AES", "RSA", "ECDSA", "ECDH", "HMAC", "SHA-256", "SHA-384", "SHA-512",
		"CTR_DRBG", "HMAC_DRBG",
	}
	for _, item := range allowed {
		if strings.Contains(algo, item) {
			return true
		}
	}
	return false
}

func isSpike(current int, previous int, absThreshold int, ratio float64) bool {
	if current < absThreshold {
		return false
	}
	if previous <= 0 {
		return current >= absThreshold
	}
	return float64(current) >= float64(previous)*ratio
}

func mergeTopSignals(parts ...map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for _, m := range parts {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func buildDomainMetrics(summary SignalSummary) map[string]interface{} {
	metrics := map[string]interface{}{}
	add := func(key string, events int, failures int, latency float64, extra map[string]interface{}) {
		rate := float64(0)
		if events > 0 {
			rate = float64(failures) / float64(events)
		}
		item := map[string]interface{}{
			"events_24h":         events,
			"failures_24h":       failures,
			"failure_rate_24h":   rate,
			"latency_avg_ms_24h": latency,
		}
		for k, v := range extra {
			item[k] = v
		}
		metrics[key] = item
	}
	add("byok", summary.BYOKEvents, summary.BYOKFailures, summary.BYOKLatencyAvgMS, nil)
	add("hyok", summary.HYOKEvents, summary.HYOKFailures, summary.HYOKLatencyAvgMS, nil)
	add("ekm", summary.EKMEvents, summary.EKMFailures, summary.EKMLatencyAvgMS, nil)
	add("kmip", summary.KMIPEvents, summary.KMIPFailures, summary.KMIPLatencyAvgMS, map[string]interface{}{
		"interop_failed_24h": summary.KMIPInteropFailures,
	})
	add("bitlocker", summary.BitLockerEvents, summary.BitLockerFailures, summary.BitLockerLatencyAvgMS, nil)
	add("sdk", summary.SDKEvents, summary.SDKFailures, summary.SDKLatencyAvgMS, map[string]interface{}{
		"receipt_missing_24h": summary.SDKReceiptMissing,
	})
	return metrics
}

func aggregateGlobalRisk(snaps []RiskSnapshot) RiskSnapshot {
	if len(snaps) == 0 {
		return RiskSnapshot{
			ID:              newID("risk"),
			TenantID:        "*",
			Risk24h:         0,
			Risk7d:          0,
			PredictiveScore: 0,
			PreventiveScore: 0,
			CorrectiveScore: 0,
			TopSignals:      map[string]interface{}{},
			CapturedAt:      nowUTC(),
		}
	}
	sort.Slice(snaps, func(i, j int) bool {
		return snaps[i].Risk24h > snaps[j].Risk24h
	})
	sum24 := 0
	sum7 := 0
	sumPred := 0
	sumPrev := 0
	sumCorr := 0
	topTenants := make([]map[string]interface{}, 0, min(5, len(snaps)))
	for i, item := range snaps {
		sum24 += item.Risk24h
		sum7 += item.Risk7d
		sumPred += item.PredictiveScore
		sumPrev += item.PreventiveScore
		sumCorr += item.CorrectiveScore
		if i < 5 {
			topTenants = append(topTenants, map[string]interface{}{
				"tenant_id": item.TenantID,
				"risk_24h":  item.Risk24h,
				"risk_7d":   item.Risk7d,
			})
		}
	}
	n := len(snaps)
	return RiskSnapshot{
		ID:              newID("risk"),
		TenantID:        "*",
		Risk24h:         clampRisk(sum24 / n),
		Risk7d:          clampRisk(sum7 / n),
		PredictiveScore: clampRisk(sumPred / n),
		PreventiveScore: clampRisk(sumPrev / n),
		CorrectiveScore: clampRisk(sumCorr / n),
		TopSignals: map[string]interface{}{
			"tenant_count": n,
			"top_tenants":  topTenants,
		},
		CapturedAt: nowUTC(),
	}
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func (s *Service) publish(ctx context.Context, subject string, tenantID string, payload map[string]interface{}) error {
	if s.event == nil {
		return nil
	}
	if payload == nil {
		payload = map[string]interface{}{}
	}
	payload["tenant_id"] = tenantID
	payload["timestamp"] = nowUTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return s.event.Publish(ctx, subject, raw)
}
