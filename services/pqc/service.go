package main

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Service struct {
	store     Store
	keycore   KeyCoreClient
	certs     CertsClient
	discovery DiscoveryClient
	events    EventPublisher
	now       func() time.Time
}

func NewService(store Store, keycore KeyCoreClient, certs CertsClient, discovery DiscoveryClient, events EventPublisher) *Service {
	return &Service{
		store:     store,
		keycore:   keycore,
		certs:     certs,
		discovery: discovery,
		events:    events,
		now:       func() time.Time { return time.Now().UTC() },
	}
}

type discoveredAsset struct {
	ID             string
	AssetType      string
	Name           string
	Source         string
	Algorithm      string
	Classification string
	QSL            float64
	Status         string
}

func (s *Service) StartReadinessScan(ctx context.Context, req ScanRequest) (ReadinessScan, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		return ReadinessScan{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	_ = s.publishAudit(ctx, "audit.pqc.scan_initiated", tenantID, map[string]interface{}{
		"trigger": defaultString(req.Trigger, "manual"),
	})

	assets, err := s.collectAssets(ctx, tenantID)
	if err != nil {
		return ReadinessScan{}, err
	}

	algorithmSummary := map[string]int{}
	qslSum := 0.0
	pqcReady := 0
	hybrid := 0
	classical := 0
	riskItems := make([]AssetRisk, 0)

	for _, asset := range assets {
		alg := normalizeAlgorithm(asset.Algorithm)
		algorithmSummary[alg]++
		qsl := asset.QSL
		if qsl <= 0 {
			qsl = algorithmQSL(alg)
		}
		qslSum += qsl

		switch {
		case isPQCAlgorithm(alg):
			pqcReady++
		case isHybridAlgorithm(alg):
			hybrid++
		default:
			classical++
		}

		if isPQCAlgorithm(alg) {
			continue
		}

		classification := strings.ToLower(strings.TrimSpace(asset.Classification))
		if classification == "" {
			classification = classifyAlgorithm(alg)
		}

		risk := AssetRisk{
			AssetID:         defaultString(asset.ID, newID("asset")),
			AssetType:       defaultString(asset.AssetType, "unknown"),
			Name:            defaultString(asset.Name, defaultString(asset.ID, "unknown")),
			Source:          defaultString(asset.Source, "unknown"),
			Algorithm:       alg,
			Classification:  classification,
			QSLScore:        round2(qsl),
			MigrationTarget: migrationTarget(alg, asset.AssetType),
			Priority:        riskPriority(alg, classification, qsl, asset.Source),
			Reason:          riskReason(alg, classification, qsl),
		}
		riskItems = append(riskItems, risk)
	}

	sort.Slice(riskItems, func(i, j int) bool {
		if riskItems[i].Priority == riskItems[j].Priority {
			return riskItems[i].QSLScore < riskItems[j].QSLScore
		}
		return riskItems[i].Priority > riskItems[j].Priority
	})
	if len(riskItems) > 250 {
		riskItems = riskItems[:250]
	}

	total := len(assets)
	avgQSL := 0.0
	if total > 0 {
		avgQSL = qslSum / float64(total)
	}
	readinessScore := clampScore(int(
		0.55*pct(pqcReady+hybrid, maxInt(total, 1)) +
			0.30*avgQSL +
			0.15*pct(hybrid, maxInt(total, 1)),
	))

	timelineStatus := s.timelineStatusMap(readinessScore)
	scan := ReadinessScan{
		ID:               newID("scan"),
		TenantID:         tenantID,
		Status:           "completed",
		TotalAssets:      total,
		PQCReadyAssets:   pqcReady,
		HybridAssets:     hybrid,
		ClassicalAssets:  classical,
		AverageQSL:       round2(avgQSL),
		ReadinessScore:   readinessScore,
		AlgorithmSummary: algorithmSummary,
		TimelineStatus:   timelineStatus,
		RiskItems:        riskItems,
		Metadata: map[string]interface{}{
			"trigger": defaultString(req.Trigger, "manual"),
		},
		CompletedAt: s.now(),
	}

	if err := s.store.CreateReadinessScan(ctx, scan); err != nil {
		return ReadinessScan{}, err
	}
	out, err := s.store.GetReadinessScan(ctx, tenantID, scan.ID)
	if err != nil {
		return ReadinessScan{}, err
	}
	_ = s.publishAudit(ctx, "audit.pqc.scan_completed", tenantID, map[string]interface{}{
		"scan_id":         out.ID,
		"readiness_score": out.ReadinessScore,
		"total_assets":    out.TotalAssets,
	})
	return out, nil
}

func (s *Service) ListReadinessScans(ctx context.Context, tenantID string, limit int, offset int) ([]ReadinessScan, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	return s.store.ListReadinessScans(ctx, tenantID, limit, offset)
}

func (s *Service) GetReadinessScan(ctx context.Context, tenantID string, id string) (ReadinessScan, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return ReadinessScan{}, newServiceError(400, "bad_request", "tenant_id and id are required")
	}
	return s.store.GetReadinessScan(ctx, tenantID, id)
}

func (s *Service) GetLatestReadiness(ctx context.Context, tenantID string) (ReadinessScan, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ReadinessScan{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	item, err := s.store.GetLatestReadinessScan(ctx, tenantID)
	if err == nil {
		return item, nil
	}
	if errorsIsNotFound(err) {
		return s.StartReadinessScan(ctx, ScanRequest{TenantID: tenantID, Trigger: "auto"})
	}
	return ReadinessScan{}, err
}

func (s *Service) GetPolicy(ctx context.Context, tenantID string) (PQCPolicy, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return PQCPolicy{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	item, err := s.store.GetPolicy(ctx, tenantID)
	if err == nil {
		out := normalizePQCPolicy(item)
		_ = s.publishAudit(ctx, "audit.pqc.policy_viewed", tenantID, map[string]interface{}{
			"profile_id":               out.ProfileID,
			"interface_default_mode":   out.InterfaceDefaultMode,
			"certificate_default_mode": out.CertificateDefaultMode,
		})
		return out, nil
	}
	if !errorsIsNotFound(err) {
		return PQCPolicy{}, err
	}
	out := defaultPQCPolicy(tenantID)
	_ = s.publishAudit(ctx, "audit.pqc.policy_viewed", tenantID, map[string]interface{}{
		"profile_id":               out.ProfileID,
		"interface_default_mode":   out.InterfaceDefaultMode,
		"certificate_default_mode": out.CertificateDefaultMode,
		"source":                   "default",
	})
	return out, nil
}

func (s *Service) UpdatePolicy(ctx context.Context, in PQCPolicy) (PQCPolicy, error) {
	out := normalizePQCPolicy(in)
	if out.TenantID == "" {
		return PQCPolicy{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	saved, err := s.store.UpsertPolicy(ctx, out)
	if err != nil {
		return PQCPolicy{}, err
	}
	saved = normalizePQCPolicy(saved)
	_ = s.publishAudit(ctx, "audit.pqc.policy_updated", saved.TenantID, map[string]interface{}{
		"profile_id":               saved.ProfileID,
		"default_kem":              saved.DefaultKEM,
		"default_signature":        saved.DefaultSignature,
		"interface_default_mode":   saved.InterfaceDefaultMode,
		"certificate_default_mode": saved.CertificateDefaultMode,
		"hqc_backup_enabled":       saved.HQCBackupEnabled,
		"flag_classical_usage":     saved.FlagClassicalUsage,
		"flag_classical_certs":     saved.FlagClassicalCerts,
		"flag_non_migrated_ifaces": saved.FlagNonMigratedIfaces,
		"require_pqc_for_new_keys": saved.RequirePQCForNewKeys,
		"updated_by":               saved.UpdatedBy,
	})
	return saved, nil
}

func (s *Service) GetInventory(ctx context.Context, tenantID string) (PQCInventory, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return PQCInventory{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	policy, err := s.GetPolicy(ctx, tenantID)
	if err != nil {
		return PQCInventory{}, err
	}

	keys, err := s.keycore.ListKeys(ctx, tenantID, 5000)
	if err != nil && s.keycore != nil {
		return PQCInventory{}, err
	}

	certs := []map[string]interface{}{}
	if s.certs != nil {
		if certItems, certErr := s.certs.ListCertificates(ctx, tenantID, 5000); certErr == nil {
			certs = certItems
		} else if len(keys) == 0 {
			return PQCInventory{}, certErr
		}
	}

	interfaces := []map[string]interface{}{}
	if s.keycore != nil {
		if portItems, portErr := s.keycore.ListInterfacePorts(ctx, tenantID); portErr == nil {
			interfaces = portItems
		} else if len(keys) == 0 && len(certs) == 0 {
			return PQCInventory{}, portErr
		}
	}

	keyBreakdown, classicalUsage := buildKeyInventory(keys, policy)
	certBreakdown, classicalCerts, nonMigratedCerts := buildCertificateInventory(certs, policy)
	interfaceBreakdown, nonMigratedIfaces := buildInterfaceInventory(interfaces, policy)
	classicalUsage = append(classicalUsage, classicalCerts...)
	sortClassicalUsage(classicalUsage)
	sortInterfacePQCItems(nonMigratedIfaces)
	sortCertificatePQCItems(nonMigratedCerts)

	weightedTotal := keyBreakdown.Total + certBreakdown.Total + interfaceBreakdown.Total
	weightedReady := float64(keyBreakdown.PQCOnly+certBreakdown.PQCOnly+interfaceBreakdown.PQCOnly) +
		0.7*float64(keyBreakdown.Hybrid+certBreakdown.Hybrid+interfaceBreakdown.Hybrid)
	readinessPercent := 0.0
	if weightedTotal > 0 {
		readinessPercent = round2(weightedReady * 100 / float64(weightedTotal))
	}
	readinessScore := clampScore(int(readinessPercent*0.85 + pct(weightedTotal-len(classicalUsage), maxInt(weightedTotal, 1))*0.15))

	inventory := PQCInventory{
		TenantID:                tenantID,
		GeneratedAt:             s.now(),
		Policy:                  policy,
		ReadinessScore:          readinessScore,
		QuantumReadinessPercent: readinessPercent,
		Keys:                    keyBreakdown,
		Certificates:            certBreakdown,
		Interfaces:              interfaceBreakdown,
		ClassicalUsage:          classicalUsage,
		NonMigratedInterfaces:   nonMigratedIfaces,
		NonMigratedCertificates: nonMigratedCerts,
		Recommendations:         buildPQCRecommendations(policy, classicalUsage, nonMigratedIfaces, nonMigratedCerts),
	}
	_ = s.publishAudit(ctx, "audit.pqc.inventory_viewed", tenantID, map[string]interface{}{
		"readiness_score":              inventory.ReadinessScore,
		"quantum_readiness_percent":    inventory.QuantumReadinessPercent,
		"classical_usage_count":        len(inventory.ClassicalUsage),
		"non_migrated_interface_count": len(inventory.NonMigratedInterfaces),
		"non_migrated_cert_count":      len(inventory.NonMigratedCertificates),
	})
	return inventory, nil
}

func (s *Service) GetMigrationReport(ctx context.Context, tenantID string) (PQCMigrationReport, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return PQCMigrationReport{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	inventory, err := s.GetInventory(ctx, tenantID)
	if err != nil {
		return PQCMigrationReport{}, err
	}
	readiness, err := s.GetLatestReadiness(ctx, tenantID)
	if err != nil {
		return PQCMigrationReport{}, err
	}
	timeline := s.buildTimelineMilestones(maxInt(inventory.ReadinessScore, readiness.ReadinessScore))
	topRisks := readiness.RiskItems
	if len(topRisks) > 8 {
		topRisks = topRisks[:8]
	}
	report := PQCMigrationReport{
		TenantID:        tenantID,
		GeneratedAt:     s.now(),
		Policy:          inventory.Policy,
		Inventory:       inventory,
		LatestReadiness: readiness,
		Timeline:        timeline,
		TopRisks:        topRisks,
		NextActions:     inventory.Recommendations,
	}
	_ = s.publishAudit(ctx, "audit.pqc.migration_report_viewed", tenantID, map[string]interface{}{
		"readiness_score": report.Inventory.ReadinessScore,
		"top_risk_count":  len(report.TopRisks),
		"timeline_count":  len(report.Timeline),
	})
	return report, nil
}

func (s *Service) CreateMigrationPlan(ctx context.Context, req PlanRequest) (MigrationPlan, error) {
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		return MigrationPlan{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	readiness, err := s.GetLatestReadiness(ctx, tenantID)
	if err != nil {
		return MigrationPlan{}, err
	}
	if strings.TrimSpace(req.Name) == "" {
		req.Name = "PQC migration plan " + s.now().Format("2006-01-02")
	}
	targetProfile := defaultString(req.TargetProfile, "hybrid-first")
	timelineStandard := defaultString(req.TimelineStandard, "cnsa2")
	deadline := parseTimeString(req.Deadline)
	if deadline.IsZero() {
		deadline = defaultDeadline(timelineStandard)
	}
	steps := make([]MigrationStep, 0, len(readiness.RiskItems))
	phaseCount := map[string]int{}
	for _, risk := range readiness.RiskItems {
		phase := migrationPhase(risk.Algorithm, risk.MigrationTarget)
		phaseCount[phase]++
		steps = append(steps, MigrationStep{
			ID:         newID("step"),
			AssetID:    risk.AssetID,
			AssetType:  risk.AssetType,
			Name:       risk.Name,
			CurrentAlg: risk.Algorithm,
			TargetAlg:  risk.MigrationTarget,
			Phase:      phase,
			Priority:   risk.Priority,
			Status:     "pending",
			Reason:     risk.Reason,
			Metadata: map[string]interface{}{
				"source":         risk.Source,
				"classification": risk.Classification,
				"qsl_score":      risk.QSLScore,
			},
		})
	}
	plan := MigrationPlan{
		ID:               newID("plan"),
		TenantID:         tenantID,
		Name:             req.Name,
		Status:           "planned",
		TargetProfile:    targetProfile,
		TimelineStandard: timelineStandard,
		Deadline:         deadline,
		Summary: map[string]interface{}{
			"readiness_score":        readiness.ReadinessScore,
			"total_steps":            len(steps),
			"classical_to_hybrid":    phaseCount["classical_to_hybrid"],
			"hybrid_to_pqc":          phaseCount["hybrid_to_pqc"],
			"classical_to_pqc":       phaseCount["classical_to_pqc"],
			"pqc_hardening":          phaseCount["pqc_hardening"],
			"estimated_risk_reduced": estimatedRiskReduction(steps),
		},
		Steps:     steps,
		CreatedBy: defaultString(req.CreatedBy, "system"),
	}
	if err := s.store.CreateMigrationPlan(ctx, plan); err != nil {
		return MigrationPlan{}, err
	}
	item, err := s.store.GetMigrationPlan(ctx, tenantID, plan.ID)
	if err != nil {
		return MigrationPlan{}, err
	}
	_ = s.publishAudit(ctx, "audit.pqc.migration_planned", tenantID, map[string]interface{}{
		"plan_id":    item.ID,
		"steps":      len(item.Steps),
		"deadline":   item.Deadline.Format(time.RFC3339),
		"target":     item.TargetProfile,
		"created_by": item.CreatedBy,
	})
	return item, nil
}

func (s *Service) ListMigrationPlans(ctx context.Context, tenantID string, limit int, offset int) ([]MigrationPlan, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	return s.store.ListMigrationPlans(ctx, tenantID, limit, offset)
}

func (s *Service) GetMigrationPlan(ctx context.Context, tenantID string, id string) (MigrationPlan, error) {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" || id == "" {
		return MigrationPlan{}, newServiceError(400, "bad_request", "tenant_id and id are required")
	}
	return s.store.GetMigrationPlan(ctx, tenantID, id)
}

func (s *Service) ExecuteMigrationPlan(ctx context.Context, tenantID string, planID string, req ExecuteRequest) (MigrationRun, error) {
	tenantID = strings.TrimSpace(tenantID)
	planID = strings.TrimSpace(planID)
	if tenantID == "" || planID == "" {
		return MigrationRun{}, newServiceError(400, "bad_request", "tenant_id and plan_id are required")
	}
	plan, err := s.store.GetMigrationPlan(ctx, tenantID, planID)
	if err != nil {
		return MigrationRun{}, err
	}
	actor := defaultString(req.Actor, "system")
	run := MigrationRun{
		ID:       newID("run"),
		TenantID: tenantID,
		PlanID:   planID,
		Status:   "running",
		DryRun:   req.DryRun,
		Summary: map[string]interface{}{
			"actor": actor,
		},
	}
	if err := s.store.CreateMigrationRun(ctx, run); err != nil {
		return MigrationRun{}, err
	}

	migrated := 0
	failed := 0
	skipped := 0
	for i := range plan.Steps {
		step := &plan.Steps[i]
		if !req.DryRun && step.Status == "completed" {
			skipped++
			continue
		}
		if req.DryRun {
			step.Status = "dry_run"
			if step.Metadata == nil {
				step.Metadata = map[string]interface{}{}
			}
			step.Metadata["dry_run"] = "true"
			migrated++
			continue
		}
		if err := s.applyMigrationStep(ctx, tenantID, *step, actor); err != nil {
			failed++
			step.Status = "failed"
			if step.Metadata == nil {
				step.Metadata = map[string]interface{}{}
			}
			step.Metadata["error"] = err.Error()
			_ = s.publishAudit(ctx, "audit.pqc.migration_failed", tenantID, map[string]interface{}{
				"plan_id":   planID,
				"step_id":   step.ID,
				"asset_id":  step.AssetID,
				"algorithm": step.CurrentAlg,
				"reason":    err.Error(),
			})
			continue
		}
		migrated++
		step.Status = "completed"
		step.ExecutedAt = s.now()
		_ = s.publishAudit(ctx, "audit.pqc.migration_executed", tenantID, map[string]interface{}{
			"plan_id":  planID,
			"step_id":  step.ID,
			"asset_id": step.AssetID,
			"from":     step.CurrentAlg,
			"to":       step.TargetAlg,
			"actor":    actor,
		})
	}

	if req.DryRun {
		plan.Status = "planned"
	} else if failed > 0 {
		plan.Status = "failed"
	} else {
		plan.Status = "completed"
		plan.ExecutedAt = s.now()
	}
	plan.Summary["migrated_steps"] = migrated
	plan.Summary["failed_steps"] = failed
	plan.Summary["skipped_steps"] = skipped
	plan.Summary["last_execution_actor"] = actor
	if err := s.store.UpdateMigrationPlan(ctx, plan); err != nil {
		return MigrationRun{}, err
	}

	run.Status = plan.Status
	if req.DryRun {
		run.Status = "dry_run_completed"
	}
	run.CompletedAt = s.now()
	run.Summary = map[string]interface{}{
		"migrated_steps": migrated,
		"failed_steps":   failed,
		"skipped_steps":  skipped,
		"actor":          actor,
		"plan_status":    plan.Status,
	}
	if err := s.store.UpdateMigrationRun(ctx, run); err != nil {
		return MigrationRun{}, err
	}

	if failed > 0 {
		_ = s.publishAudit(ctx, "audit.pqc.migration_failed", tenantID, map[string]interface{}{
			"plan_id":        planID,
			"failed_steps":   failed,
			"migrated_steps": migrated,
		})
	}
	if !req.DryRun && failed == 0 {
		_ = s.publishAudit(ctx, "audit.pqc.migration_executed", tenantID, map[string]interface{}{
			"plan_id":        planID,
			"migrated_steps": migrated,
		})
	}
	return run, nil
}

func (s *Service) RollbackMigrationPlan(ctx context.Context, tenantID string, planID string, actor string) (MigrationPlan, error) {
	tenantID = strings.TrimSpace(tenantID)
	planID = strings.TrimSpace(planID)
	if tenantID == "" || planID == "" {
		return MigrationPlan{}, newServiceError(400, "bad_request", "tenant_id and plan_id are required")
	}
	plan, err := s.store.GetMigrationPlan(ctx, tenantID, planID)
	if err != nil {
		return MigrationPlan{}, err
	}
	rolled := 0
	for i := range plan.Steps {
		if plan.Steps[i].Status != "completed" {
			continue
		}
		plan.Steps[i].Status = "rolled_back"
		plan.Steps[i].RolledBackAt = s.now()
		rolled++
	}
	plan.Status = "rolled_back"
	plan.Summary["rolled_back_steps"] = rolled
	plan.Summary["rollback_actor"] = defaultString(actor, "system")
	if err := s.store.UpdateMigrationPlan(ctx, plan); err != nil {
		return MigrationPlan{}, err
	}
	run := MigrationRun{
		ID:          newID("run"),
		TenantID:    tenantID,
		PlanID:      planID,
		Status:      "rolled_back",
		DryRun:      false,
		Summary:     map[string]interface{}{"rolled_back_steps": rolled, "actor": defaultString(actor, "system")},
		CompletedAt: s.now(),
	}
	_ = s.store.CreateMigrationRun(ctx, run)
	_ = s.publishAudit(ctx, "audit.pqc.migration_rolled_back", tenantID, map[string]interface{}{
		"plan_id":           planID,
		"rolled_back_steps": rolled,
		"actor":             defaultString(actor, "system"),
	})
	return s.store.GetMigrationPlan(ctx, tenantID, planID)
}

func (s *Service) ListMigrationRuns(ctx context.Context, tenantID string, planID string) ([]MigrationRun, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	return s.store.ListMigrationRuns(ctx, tenantID, planID)
}

func (s *Service) Timeline(ctx context.Context, tenantID string) ([]TimelineMilestone, ReadinessScan, error) {
	readiness, err := s.GetLatestReadiness(ctx, tenantID)
	if err != nil {
		return nil, ReadinessScan{}, err
	}
	milestones := s.buildTimelineMilestones(readiness.ReadinessScore)
	return milestones, readiness, nil
}

func (s *Service) ExportCBOM(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	assets, err := s.collectAssets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	components := make([]map[string]interface{}, 0, len(assets))
	for _, a := range assets {
		components = append(components, map[string]interface{}{
			"type":           defaultString(a.AssetType, "crypto-asset"),
			"name":           defaultString(a.Name, defaultString(a.ID, "asset")),
			"algorithm":      normalizeAlgorithm(a.Algorithm),
			"source":         defaultString(a.Source, "unknown"),
			"classification": defaultString(a.Classification, classifyAlgorithm(a.Algorithm)),
			"pqc_ready":      isPQCAlgorithm(a.Algorithm) || isHybridAlgorithm(a.Algorithm),
			"qsl_score":      round2(defaultFloat(a.QSL, algorithmQSL(a.Algorithm))),
		})
	}
	sort.Slice(components, func(i, j int) bool {
		left := firstString(components[i]["source"]) + "|" + firstString(components[i]["name"])
		right := firstString(components[j]["source"]) + "|" + firstString(components[j]["name"])
		return left < right
	})
	return map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.6",
		"version":     1,
		"metadata": map[string]interface{}{
			"timestamp": s.now().Format(time.RFC3339),
			"component": map[string]interface{}{"name": "vecta-kms-pqc", "type": "application"},
			"tenant_id": tenantID,
		},
		"components": components,
	}, nil
}

func defaultPQCPolicy(tenantID string) PQCPolicy {
	return pqcPolicyProfileDefaults("balanced_hybrid", tenantID)
}

func normalizePQCPolicy(in PQCPolicy) PQCPolicy {
	profileID := normalizePQCProfileID(in.ProfileID)
	base := pqcPolicyProfileDefaults(profileID, in.TenantID)
	if strings.TrimSpace(in.DefaultKEM) != "" {
		base.DefaultKEM = normalizeAlgorithm(in.DefaultKEM)
	}
	if strings.TrimSpace(in.DefaultSignature) != "" {
		base.DefaultSignature = normalizeAlgorithm(in.DefaultSignature)
	}
	switch strings.ToLower(strings.TrimSpace(in.InterfaceDefaultMode)) {
	case "", "inherit":
	case "classical", "legacy":
		base.InterfaceDefaultMode = "classical"
	case "hybrid":
		base.InterfaceDefaultMode = "hybrid"
	case "pqc", "pqc_only", "pqc-only":
		base.InterfaceDefaultMode = "pqc_only"
	}
	switch strings.ToLower(strings.TrimSpace(in.CertificateDefaultMode)) {
	case "", "inherit":
	case "classical", "legacy":
		base.CertificateDefaultMode = "classical"
	case "hybrid":
		base.CertificateDefaultMode = "hybrid"
	case "pqc", "pqc_only", "pqc-only":
		base.CertificateDefaultMode = "pqc_only"
	}
	if strings.TrimSpace(in.ProfileID) != "" || strings.TrimSpace(in.TenantID) != "" || strings.TrimSpace(in.UpdatedBy) != "" || !in.UpdatedAt.IsZero() {
		base.HQCBackupEnabled = in.HQCBackupEnabled
		base.FlagClassicalUsage = in.FlagClassicalUsage
		base.FlagClassicalCerts = in.FlagClassicalCerts
		base.FlagNonMigratedIfaces = in.FlagNonMigratedIfaces
		base.RequirePQCForNewKeys = in.RequirePQCForNewKeys
	}
	base.UpdatedBy = strings.TrimSpace(in.UpdatedBy)
	if !in.UpdatedAt.IsZero() {
		base.UpdatedAt = in.UpdatedAt.UTC()
	}
	return base
}

func normalizePQCProfileID(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "balanced", "balanced-hybrid", "balanced_hybrid":
		return "balanced_hybrid"
	case "quantum-first", "quantum_first", "pqc-first", "pqc_first":
		return "quantum_first"
	case "signing-first", "signing_first":
		return "signing_first"
	case "compliance-accelerated", "compliance_accelerated":
		return "compliance_accelerated"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func pqcPolicyProfileDefaults(profileID string, tenantID string) PQCPolicy {
	out := PQCPolicy{
		TenantID:               strings.TrimSpace(tenantID),
		ProfileID:              normalizePQCProfileID(profileID),
		DefaultKEM:             "ML-KEM-768",
		DefaultSignature:       "ML-DSA-65",
		InterfaceDefaultMode:   "hybrid",
		CertificateDefaultMode: "hybrid",
		HQCBackupEnabled:       true,
		FlagClassicalUsage:     true,
		FlagClassicalCerts:     true,
		FlagNonMigratedIfaces:  true,
		RequirePQCForNewKeys:   false,
	}
	switch out.ProfileID {
	case "quantum_first":
		out.DefaultKEM = "ML-KEM-1024"
		out.DefaultSignature = "ML-DSA-87"
		out.InterfaceDefaultMode = "pqc_only"
		out.CertificateDefaultMode = "pqc_only"
		out.RequirePQCForNewKeys = true
	case "signing_first":
		out.DefaultSignature = "SLH-DSA-SHAKE-256F"
	case "compliance_accelerated":
		out.DefaultKEM = "ML-KEM-1024"
		out.DefaultSignature = "ML-DSA-87"
		out.CertificateDefaultMode = "pqc_only"
		out.RequirePQCForNewKeys = true
	}
	return out
}

func buildKeyInventory(items []map[string]interface{}, policy PQCPolicy) (InventoryBreakdown, []ClassicalUsageItem) {
	breakdown := InventoryBreakdown{Algorithms: map[string]int{}}
	classicalUsage := make([]ClassicalUsageItem, 0)
	for _, item := range items {
		alg := normalizeAlgorithm(firstString(item["algorithm"]))
		if alg == "UNKNOWN" {
			continue
		}
		mode := keyInventoryMode(item)
		breakdown.Total++
		incrementInventoryMode(&breakdown, mode)
		breakdown.Algorithms[alg]++
		if policy.FlagClassicalUsage && mode == "classical" && isClassicalAsymmetricAlgorithm(alg) {
			classicalUsage = append(classicalUsage, ClassicalUsageItem{
				AssetType: "key",
				AssetID:   firstString(item["id"], item["key_id"]),
				Name:      firstString(item["name"], item["id"]),
				Algorithm: alg,
				Location:  "keycore",
				QSLScore:  round2(algorithmQSL(alg)),
				Reason:    "Classical RSA/ECC signature or key-agreement path is still active",
			})
		}
	}
	return breakdown, classicalUsage
}

func buildCertificateInventory(items []map[string]interface{}, policy PQCPolicy) (InventoryBreakdown, []ClassicalUsageItem, []CertificatePQCItem) {
	breakdown := InventoryBreakdown{Algorithms: map[string]int{}}
	classicalUsage := make([]ClassicalUsageItem, 0)
	nonMigrated := make([]CertificatePQCItem, 0)
	for _, item := range items {
		alg := normalizeAlgorithm(firstString(item["algorithm"], item["signature_algorithm"], item["cert_class"]))
		mode := certificateInventoryMode(item, policy)
		breakdown.Total++
		incrementInventoryMode(&breakdown, mode)
		breakdown.Algorithms[alg]++
		if policy.FlagClassicalCerts && mode == "classical" && isClassicalAsymmetricAlgorithm(alg) {
			classicalUsage = append(classicalUsage, ClassicalUsageItem{
				AssetType: "certificate",
				AssetID:   firstString(item["id"], item["cert_id"]),
				Name:      firstString(item["subject_cn"], item["id"]),
				Algorithm: alg,
				Location:  "certs",
				QSLScore:  round2(algorithmQSL(alg)),
				Reason:    "Certificate still uses RSA/ECC without hybrid or PQC class",
			})
		}
		if mode == "classical" {
			nonMigrated = append(nonMigrated, CertificatePQCItem{
				CertID:         firstString(item["id"], item["cert_id"]),
				SubjectCN:      firstString(item["subject_cn"], item["id"]),
				Algorithm:      alg,
				CertClass:      strings.ToLower(firstString(item["cert_class"])),
				Status:         strings.ToLower(firstString(item["status"], item["state"])),
				NotAfter:       parseTimeValue(item["not_after"]).Format(time.RFC3339),
				MigrationState: "classical_only",
			})
		}
	}
	return breakdown, classicalUsage, nonMigrated
}

func buildInterfaceInventory(items []map[string]interface{}, policy PQCPolicy) (InventoryBreakdown, []InterfacePQCItem) {
	breakdown := InventoryBreakdown{Algorithms: map[string]int{}}
	nonMigrated := make([]InterfacePQCItem, 0)
	for _, item := range items {
		protocol := strings.ToLower(strings.TrimSpace(firstString(item["protocol"])))
		mode := effectiveInterfaceMode(item, policy)
		breakdown.Total++
		incrementInventoryMode(&breakdown, mode)
		breakdown.Algorithms[protocol+"|"+mode]++
		if policy.FlagNonMigratedIfaces && mode == "classical" {
			nonMigrated = append(nonMigrated, InterfacePQCItem{
				InterfaceName:    firstString(item["interface_name"], item["name"]),
				Description:      firstString(item["description"]),
				BindAddress:      firstString(item["bind_address"]),
				Port:             extractInt(item["port"]),
				Protocol:         protocol,
				PQCMode:          strings.ToLower(strings.TrimSpace(firstString(item["pqc_mode"]))),
				EffectivePQCMode: mode,
				Enabled:          extractBool(item["enabled"]),
				Status:           defaultString(strings.ToLower(firstString(item["status"])), "configured"),
				CertSource:       firstString(item["certificate_source"]),
				CAID:             firstString(item["ca_id"]),
				CertificateID:    firstString(item["certificate_id"]),
			})
		}
	}
	return breakdown, nonMigrated
}

func incrementInventoryMode(b *InventoryBreakdown, mode string) {
	switch mode {
	case "pqc_only":
		b.PQCOnly++
	case "hybrid":
		b.Hybrid++
	default:
		b.Classical++
	}
}

func keyInventoryMode(item map[string]interface{}) string {
	alg := normalizeAlgorithm(firstString(item["algorithm"]))
	if strings.Contains(alg, "HYBRID") {
		return "hybrid"
	}
	labels, _ := item["labels"].(map[string]interface{})
	if labels != nil {
		hybridMode := strings.ToLower(strings.TrimSpace(firstString(labels["pqc_hybrid_mode"])))
		switch hybridMode {
		case "hybrid-ecdh", "hybrid-signature", "hybrid":
			return "hybrid"
		}
	}
	if isPQCAlgorithm(alg) {
		return "pqc_only"
	}
	return "classical"
}

func certificateInventoryMode(item map[string]interface{}, policy PQCPolicy) string {
	certClass := strings.ToLower(strings.TrimSpace(firstString(item["cert_class"])))
	switch certClass {
	case "hybrid":
		return "hybrid"
	case "pqc", "pqc_only":
		return "pqc_only"
	}
	alg := normalizeAlgorithm(firstString(item["algorithm"], item["signature_algorithm"], certClass))
	if strings.Contains(alg, "HYBRID") {
		return "hybrid"
	}
	if isPQCAlgorithm(alg) {
		return "pqc_only"
	}
	if policy.CertificateDefaultMode == "pqc_only" && certClass == "" {
		return "classical"
	}
	return "classical"
}

func effectiveInterfaceMode(item map[string]interface{}, policy PQCPolicy) string {
	protocol := strings.ToLower(strings.TrimSpace(firstString(item["protocol"])))
	if protocol == "" {
		protocol = "http"
	}
	if !interfaceProtocolSupportsPQC(protocol) {
		return "classical"
	}
	raw := strings.ToLower(strings.TrimSpace(firstString(item["pqc_mode"])))
	switch raw {
	case "", "inherit", "default":
		if policy.InterfaceDefaultMode == "" {
			return "hybrid"
		}
		return policy.InterfaceDefaultMode
	case "hybrid":
		return "hybrid"
	case "pqc", "pqc_only", "pqc-only":
		return "pqc_only"
	default:
		return "classical"
	}
}

func interfaceProtocolSupportsPQC(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "https", "tls13", "mtls":
		return true
	default:
		return false
	}
}

func buildPQCRecommendations(policy PQCPolicy, classicalUsage []ClassicalUsageItem, nonMigratedIfaces []InterfacePQCItem, nonMigratedCerts []CertificatePQCItem) []string {
	out := make([]string, 0, 6)
	if len(classicalUsage) > 0 {
		out = append(out, "Rotate RSA/ECC-only keys and certificates to hybrid or PQC-native algorithms, starting with the highest-QSL-risk assets.")
	}
	if len(nonMigratedIfaces) > 0 {
		out = append(out, "Move TLS-capable interfaces to hybrid or PQC-only mode and leave classical mode only for explicitly approved compatibility paths.")
	}
	if len(nonMigratedCerts) > 0 {
		out = append(out, "Issue hybrid or PQC-class certificates for externally exposed interfaces before moving them to PQC-only.")
	}
	if !policy.HQCBackupEnabled {
		out = append(out, "Track HQC as a backup KEM path in migration planning so future agility reviews have a documented fallback strategy.")
	}
	if policy.RequirePQCForNewKeys {
		out = append(out, "Keep new high-value asymmetric keys on ML-KEM / ML-DSA / SLH-DSA profiles and use classical algorithms only for approved compatibility exceptions.")
	}
	if len(out) == 0 {
		out = append(out, "Current tenant posture is aligned with the selected PQC policy profile.")
	}
	return out
}

func sortClassicalUsage(items []ClassicalUsageItem) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].QSLScore == items[j].QSLScore {
			return items[i].Name < items[j].Name
		}
		return items[i].QSLScore < items[j].QSLScore
	})
}

func sortInterfacePQCItems(items []InterfacePQCItem) {
	sort.Slice(items, func(i, j int) bool {
		left := items[i].InterfaceName + "|" + items[i].Protocol + "|" + items[i].BindAddress
		right := items[j].InterfaceName + "|" + items[j].Protocol + "|" + items[j].BindAddress
		return left < right
	})
}

func sortCertificatePQCItems(items []CertificatePQCItem) {
	sort.Slice(items, func(i, j int) bool {
		left := items[i].SubjectCN + "|" + items[i].Algorithm
		right := items[j].SubjectCN + "|" + items[j].Algorithm
		return left < right
	})
}

func isClassicalAsymmetricAlgorithm(alg string) bool {
	alg = normalizeAlgorithm(alg)
	return strings.Contains(alg, "RSA") ||
		strings.Contains(alg, "ECDSA") ||
		strings.Contains(alg, "ECDH") ||
		strings.Contains(alg, "ED25519") ||
		strings.Contains(alg, "ED448") ||
		strings.Contains(alg, "X25519") ||
		strings.Contains(alg, "X448")
}

func (s *Service) collectAssets(ctx context.Context, tenantID string) ([]discoveredAsset, error) {
	assets := make([]discoveredAsset, 0)
	seen := map[string]struct{}{}

	if s.discovery != nil {
		items, err := s.discovery.ListCryptoAssets(ctx, tenantID, 5000)
		if err == nil {
			for _, item := range items {
				a := discoveredAsset{
					ID:             firstString(item["id"], item["asset_id"]),
					AssetType:      firstString(item["asset_type"], item["type"]),
					Name:           firstString(item["name"], item["resource"]),
					Source:         firstString(item["source"]),
					Algorithm:      normalizeAlgorithm(firstString(item["algorithm"], item["cipher"], item["signature_algorithm"])),
					Classification: strings.ToLower(firstString(item["classification"])),
					QSL:            extractFloat(item["qsl_score"]),
					Status:         strings.ToLower(firstString(item["status"])),
				}
				if a.Algorithm == "" {
					a.Algorithm = "UNKNOWN"
				}
				key := strings.ToLower(strings.Join([]string{a.Source, a.ID, a.AssetType, a.Algorithm}, "|"))
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				assets = append(assets, a)
			}
		}
	}

	if s.keycore != nil {
		items, err := s.keycore.ListKeys(ctx, tenantID, 5000)
		if err != nil {
			if len(assets) == 0 {
				return nil, err
			}
		} else {
			for _, item := range items {
				alg := normalizeAlgorithm(firstString(item["algorithm"]))
				a := discoveredAsset{
					ID:             firstString(item["id"], item["key_id"]),
					AssetType:      "key",
					Name:           firstString(item["name"], item["id"]),
					Source:         "keycore",
					Algorithm:      alg,
					Classification: classifyAlgorithm(alg),
					QSL:            algorithmQSL(alg),
					Status:         strings.ToLower(firstString(item["status"])),
				}
				key := strings.ToLower(strings.Join([]string{a.Source, a.ID, a.AssetType, a.Algorithm}, "|"))
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				assets = append(assets, a)
			}
		}
	}

	if s.certs != nil {
		items, err := s.certs.ListCertificates(ctx, tenantID, 5000)
		if err == nil {
			for _, item := range items {
				alg := normalizeAlgorithm(firstString(item["algorithm"], item["signature_algorithm"], item["cert_class"]))
				a := discoveredAsset{
					ID:             firstString(item["id"], item["cert_id"]),
					AssetType:      "certificate",
					Name:           firstString(item["subject_cn"], item["id"]),
					Source:         "certs",
					Algorithm:      alg,
					Classification: classifyAlgorithm(alg),
					QSL:            algorithmQSL(alg),
					Status:         strings.ToLower(firstString(item["status"])),
				}
				key := strings.ToLower(strings.Join([]string{a.Source, a.ID, a.AssetType, a.Algorithm}, "|"))
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				assets = append(assets, a)
			}
		}
	}

	sort.Slice(assets, func(i, j int) bool {
		left := assets[i].Source + "|" + assets[i].AssetType + "|" + assets[i].ID
		right := assets[j].Source + "|" + assets[j].AssetType + "|" + assets[j].ID
		return left < right
	})
	return assets, nil
}

func (s *Service) applyMigrationStep(ctx context.Context, tenantID string, step MigrationStep, actor string) error {
	if s.keycore == nil {
		return nil
	}
	if step.AssetType == "key" || step.AssetType == "kms_key" {
		reason := "pqc migration by " + defaultString(actor, "system") + ": " + step.CurrentAlg + " -> " + step.TargetAlg
		return s.keycore.RotateKey(ctx, tenantID, step.AssetID, reason)
	}
	return nil
}

func (s *Service) timelineStatusMap(readinessScore int) map[string]interface{} {
	cnsaDeadline := time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC)
	euDeadline := time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC)
	return map[string]interface{}{
		"cnsa2": map[string]interface{}{
			"deadline":       cnsaDeadline.Format("2006-01-02"),
			"status":         timelineReadinessStatus(readinessScore, cnsaDeadline, s.now()),
			"readiness":      readinessScore,
			"days_remaining": int(cnsaDeadline.Sub(s.now()).Hours() / 24),
		},
		"eu_pqc": map[string]interface{}{
			"deadline":       euDeadline.Format("2006-01-02"),
			"status":         timelineReadinessStatus(readinessScore, euDeadline, s.now()),
			"readiness":      readinessScore,
			"days_remaining": int(euDeadline.Sub(s.now()).Hours() / 24),
		},
	}
}

func (s *Service) buildTimelineMilestones(readinessScore int) []TimelineMilestone {
	now := s.now()
	milestones := []TimelineMilestone{
		{
			ID:          "cnsa2-hybrid",
			Standard:    "cnsa2",
			Title:       "Classical to hybrid transition",
			DueDate:     time.Date(2028, 12, 31, 0, 0, 0, 0, time.UTC),
			Description: "Adopt hybrid cryptography for high-value systems.",
		},
		{
			ID:          "cnsa2-pqc-default",
			Standard:    "cnsa2",
			Title:       "PQC-by-default rollout",
			DueDate:     time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC),
			Description: "Default to PQC key establishment and signatures.",
		},
		{
			ID:          "cnsa2-classical-retire",
			Standard:    "cnsa2",
			Title:       "Classical-only retirement",
			DueDate:     time.Date(2033, 12, 31, 0, 0, 0, 0, time.UTC),
			Description: "Retire classical-only cryptographic paths.",
		},
		{
			ID:          "eu-agility",
			Standard:    "eu-pqc",
			Title:       "EU crypto-agility baseline",
			DueDate:     time.Date(2029, 6, 30, 0, 0, 0, 0, time.UTC),
			Description: "Ensure crypto inventory and algorithm agility controls.",
		},
		{
			ID:          "eu-pqc-transition",
			Standard:    "eu-pqc",
			Title:       "EU PQC transition target",
			DueDate:     time.Date(2031, 12, 31, 0, 0, 0, 0, time.UTC),
			Description: "Transition trust services to hybrid/PQC-safe cryptography.",
		},
	}
	for i := range milestones {
		milestones[i].DaysLeft = int(milestones[i].DueDate.Sub(now).Hours() / 24)
		milestones[i].Status = timelineReadinessStatus(readinessScore, milestones[i].DueDate, now)
	}
	return milestones
}

func timelineReadinessStatus(readinessScore int, due time.Time, now time.Time) string {
	days := int(due.Sub(now).Hours() / 24)
	if readinessScore >= 85 {
		return "on_track"
	}
	if days < 0 {
		if readinessScore >= 70 {
			return "at_risk"
		}
		return "overdue"
	}
	if days <= 365 {
		if readinessScore >= 70 {
			return "at_risk"
		}
		return "critical"
	}
	if readinessScore >= 70 {
		return "in_progress"
	}
	return "not_started"
}

func migrationTarget(alg string, assetType string) string {
	alg = normalizeAlgorithm(alg)
	assetType = strings.ToLower(strings.TrimSpace(assetType))
	switch {
	case isPQCAlgorithm(alg):
		return alg
	case isHybridAlgorithm(alg):
		return "ML-KEM-768 + ML-DSA-65"
	case strings.Contains(assetType, "signature") || strings.Contains(alg, "RSA") || strings.Contains(alg, "ECDSA") || strings.Contains(alg, "ED25519"):
		return "ML-DSA-65-HYBRID"
	case strings.Contains(alg, "ECDH") || strings.Contains(assetType, "tls"):
		return "ML-KEM-768-HYBRID"
	case strings.Contains(alg, "AES-128"):
		return "AES-256"
	default:
		return "ML-KEM-768-HYBRID"
	}
}

func migrationPhase(current string, target string) string {
	current = normalizeAlgorithm(current)
	target = normalizeAlgorithm(target)
	switch {
	case isPQCAlgorithm(current):
		return "pqc_hardening"
	case isHybridAlgorithm(current) && isPQCAlgorithm(target):
		return "hybrid_to_pqc"
	case !isPQCAlgorithm(current) && isHybridAlgorithm(target):
		return "classical_to_hybrid"
	case !isPQCAlgorithm(current) && isPQCAlgorithm(target):
		return "classical_to_pqc"
	default:
		return "classical_to_hybrid"
	}
}

func riskPriority(alg string, classification string, qsl float64, source string) int {
	priority := 40
	classification = strings.ToLower(strings.TrimSpace(classification))
	source = strings.ToLower(strings.TrimSpace(source))
	if classification == "vulnerable" {
		priority += 25
	} else if classification == "weak" {
		priority += 12
	}
	if isDeprecatedAlgorithm(alg) {
		priority += 18
	}
	if qsl < 50 {
		priority += 20
	} else if qsl < 70 {
		priority += 10
	}
	if source == "code" {
		priority += 10
	}
	if priority > 100 {
		return 100
	}
	if priority < 1 {
		return 1
	}
	return priority
}

func riskReason(alg string, classification string, qsl float64) string {
	parts := []string{}
	if isDeprecatedAlgorithm(alg) {
		parts = append(parts, "deprecated algorithm")
	}
	if strings.TrimSpace(classification) != "" {
		parts = append(parts, "classification="+classification)
	}
	parts = append(parts, "qsl="+formatScore(qsl))
	return strings.Join(parts, ", ")
}

func estimatedRiskReduction(steps []MigrationStep) int {
	if len(steps) == 0 {
		return 0
	}
	total := 0
	for _, step := range steps {
		total += step.Priority
	}
	return clampScore(total / len(steps))
}

func defaultDeadline(standard string) time.Time {
	standard = strings.ToLower(strings.TrimSpace(standard))
	switch standard {
	case "eu", "eu-pqc", "eidas":
		return time.Date(2031, 12, 31, 0, 0, 0, 0, time.UTC)
	default:
		return time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC)
	}
}

func formatScore(v float64) string {
	return strings.TrimRight(strings.TrimRight(strconv.FormatFloat(round2(v), 'f', 2, 64), "0"), ".")
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func defaultFloat(v float64, fallback float64) float64 {
	if v == 0 {
		return fallback
	}
	return v
}

func errorsIsNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errNotFound) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "pqc",
		"action":    subject,
		"timestamp": s.now().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}
