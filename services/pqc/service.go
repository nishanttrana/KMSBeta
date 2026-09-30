package main

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"vecta-kms/pkg/cryptocatalog"
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

		if a := cryptocatalog.Assess(alg); a.Ready {
			continue // neither weak nor quantum-vulnerable: nothing to migrate
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
	timelineStatus := s.timelineStatusMap(ctx, tenantID)
	scan := ReadinessScan{
		ID:               newID("scan"),
		TenantID:         tenantID,
		Status:           "completed",
		TotalAssets:      total,
		PQCReadyAssets:   pqcReady,
		HybridAssets:     hybrid,
		ClassicalAssets:  classical,
		AverageQSL:       round2(avgQSL),
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
		"scan_id":          out.ID,
		"total_assets":     out.TotalAssets,
		"pqc_ready_assets": out.PQCReadyAssets,
		"hybrid_assets":    out.HybridAssets,
		"classical_assets": out.ClassicalAssets,
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

func (s *Service) GetInventory(ctx context.Context, tenantID string) (PQCInventory, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return PQCInventory{}, newServiceError(400, "bad_request", "tenant_id is required")
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

	keyBreakdown, classicalUsage := buildKeyInventory(keys)
	certBreakdown, classicalCerts, nonMigratedCerts := buildCertificateInventory(certs)
	classicalUsage = append(classicalUsage, classicalCerts...)
	sortClassicalUsage(classicalUsage)
	sortCertificatePQCItems(nonMigratedCerts)

	inventory := PQCInventory{
		TenantID:                tenantID,
		GeneratedAt:             s.now(),
		Keys:                    keyBreakdown,
		Certificates:            certBreakdown,
		Interfaces:              interfacesUnavailable,
		Listeners:               []ListenerPQCItem{},
		ClassicalUsage:          classicalUsage,
		NonMigratedCertificates: nonMigratedCerts,
		Recommendations:         buildPQCRecommendations(classicalUsage, nonMigratedCerts),
	}
	if s.certs != nil {
		if measured, err := s.certs.EdgeMeasurement(ctx, tenantID); err == nil {
			inventory.Interfaces = interfacesNotMeasured
			for _, m := range measured {
				inventory.Listeners = append(inventory.Listeners, classifyListener(m))
				inventory.Interfaces = interfacesMeasured
			}
		}
	}
	_ = s.publishAudit(ctx, "audit.pqc.inventory_viewed", tenantID, map[string]interface{}{
		"interfaces":              inventory.Interfaces,
		"listener_count":          len(inventory.Listeners),
		"key_count":               keyBreakdown.Total,
		"certificate_count":       certBreakdown.Total,
		"classical_usage_count":   len(inventory.ClassicalUsage),
		"non_migrated_cert_count": len(inventory.NonMigratedCertificates),
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
	timeline := s.buildTimelineMilestones(ctx, tenantID)
	topRisks := readiness.RiskItems
	if len(topRisks) > 8 {
		topRisks = topRisks[:8]
	}
	report := PQCMigrationReport{
		TenantID:        tenantID,
		GeneratedAt:     s.now(),
		Inventory:       inventory,
		LatestReadiness: readiness,
		Timeline:        timeline,
		TopRisks:        topRisks,
		NextActions:     inventory.Recommendations,
	}
	_ = s.publishAudit(ctx, "audit.pqc.migration_report_viewed", tenantID, map[string]interface{}{
		"top_risk_count": len(report.TopRisks),
		"timeline_count": len(report.Timeline),
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
	// The customer decides when to migrate: the deadline is theirs, and a
	// plan without one has none.
	timelineStandard := defaultString(req.TimelineStandard, "customer")
	deadline := parseTimeString(req.Deadline)
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
			"scan_id":               readiness.ID,
			"total_steps":           len(steps),
			"classical_to_hybrid":   phaseCount["classical_to_hybrid"],
			"hybrid_to_pqc":         phaseCount["hybrid_to_pqc"],
			"classical_to_pqc":      phaseCount["classical_to_pqc"],
			"pqc_hardening":         phaseCount["pqc_hardening"],
			"classical_replacement": phaseCount["classical_replacement"],
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
	manual := 0
	done := map[string]bool{"completed": true, "rotated": true, "algorithm_changed": true, "successor_created": true}
	for i := range plan.Steps {
		step := &plan.Steps[i]
		if step.Metadata == nil {
			step.Metadata = map[string]interface{}{}
		}
		if !req.DryRun && done[step.Status] {
			skipped++
			continue
		}
		if req.DryRun {
			// A dry run changes nothing and says so; it is not a migration.
			step.Metadata["dry_run_would"] = map[bool]string{true: "change key in keycore", false: "require a manual change"}[isKeyAsset(step.AssetType)]
			continue
		}
		outcome, newKeyID, err := s.applyMigrationStep(ctx, tenantID, *step, actor)
		if errors.Is(err, errManualStep) {
			manual++
			step.Status = "manual_required"
			step.Metadata["reason"] = "the KMS cannot change a " + step.AssetType + "; change it at its source"
			if isKeyAsset(step.AssetType) {
				step.Metadata["reason"] = "no migration target: " + step.CurrentAlg + " does not name a parameter set"
			}
			continue
		}
		if err != nil {
			failed++
			step.Status = "failed"
			step.Metadata["error"] = err.Error()
			_ = s.publishAudit(ctx, "audit.pqc.migration_failed", tenantID, map[string]interface{}{
				"plan_id":   planID,
				"step_id":   step.ID,
				"asset_id":  step.AssetID,
				"algorithm": step.CurrentAlg,
				"result":    "failure",
				"reason":    err.Error(),
			})
			continue
		}
		migrated++
		step.Status = outcome
		step.ExecutedAt = s.now()
		step.ExecutedBy = actor
		ev := map[string]interface{}{
			"plan_id":  planID,
			"step_id":  step.ID,
			"asset_id": step.AssetID,
			"from":     step.CurrentAlg,
			"to":       step.TargetAlg,
			"outcome":  outcome,
			"actor":    actor,
		}
		if newKeyID != "" {
			step.Metadata["successor_key_id"] = newKeyID
			ev["successor_key_id"] = newKeyID
		}
		_ = s.publishAudit(ctx, "audit.pqc.migration_step_executed", tenantID, ev)
	}

	switch {
	case req.DryRun:
		plan.Status = "planned"
	case failed > 0:
		plan.Status = "failed"
	case manual > 0:
		plan.Status = "manual_steps_remaining"
	default:
		plan.Status = "completed"
		plan.ExecutedAt = s.now()
	}
	plan.Summary["manual_steps"] = manual
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
		"manual_steps":   manual,
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
			"manual_steps":   manual,
			"plan_status":    plan.Status,
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
	// Rollback deactivates the successor keys this plan created and rotates
	// changed keys back to their old algorithm. A same-algorithm rotation
	// cannot be undone and is reported as such, never marked rolled back.
	rolled, irreversible, rollbackFailed := 0, 0, 0
	for i := range plan.Steps {
		step := &plan.Steps[i]
		switch step.Status {
		case "successor_created":
			id := firstString(step.Metadata["successor_key_id"])
			if s.keycore == nil || id == "" {
				rollbackFailed++
				continue
			}
			if err := s.keycore.DeactivateKey(ctx, tenantID, id, "pqc migration rollback by "+defaultString(actor, "system")); err != nil {
				rollbackFailed++
				step.Metadata["rollback_error"] = err.Error()
				continue
			}
			step.Status = "rolled_back"
			step.RolledBackAt = s.now()
			step.RolledBackBy = defaultString(actor, "system")
			rolled++
		case "algorithm_changed":
			// Rotate back: the key returns to its old algorithm under the
			// same ID; data protected meanwhile stays decryptable by version.
			if s.keycore == nil {
				rollbackFailed++
				continue
			}
			if err := s.keycore.RotateKey(ctx, tenantID, step.AssetID, "pqc migration rollback by "+defaultString(actor, "system"), step.CurrentAlg); err != nil {
				rollbackFailed++
				step.Metadata["rollback_error"] = err.Error()
				continue
			}
			step.Status = "rolled_back"
			step.RolledBackAt = s.now()
			step.RolledBackBy = defaultString(actor, "system")
			rolled++
		case "rotated", "completed":
			irreversible++
			step.Metadata["rollback"] = "not reversible: the key was rotated"
		}
	}
	plan.Status = "rolled_back"
	if rollbackFailed > 0 || irreversible > 0 {
		plan.Status = "partially_rolled_back"
	}
	plan.Summary["irreversible_steps"] = irreversible
	plan.Summary["rollback_failed_steps"] = rollbackFailed
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
	milestones := s.buildTimelineMilestones(ctx, tenantID)
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

func buildKeyInventory(items []map[string]interface{}) (InventoryBreakdown, []ClassicalUsageItem) {
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
		if mode == "classical" && isClassicalAsymmetricAlgorithm(alg) {
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

func buildCertificateInventory(items []map[string]interface{}) (InventoryBreakdown, []ClassicalUsageItem, []CertificatePQCItem) {
	breakdown := InventoryBreakdown{Algorithms: map[string]int{}}
	classicalUsage := make([]ClassicalUsageItem, 0)
	nonMigrated := make([]CertificatePQCItem, 0)
	for _, item := range items {
		alg := normalizeAlgorithm(firstString(item["algorithm"], item["signature_algorithm"], item["cert_class"]))
		mode := certificateInventoryMode(item)
		breakdown.Total++
		incrementInventoryMode(&breakdown, mode)
		breakdown.Algorithms[alg]++
		if mode == "classical" && isClassicalAsymmetricAlgorithm(alg) {
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
	// A key's mode is its algorithm; a label never makes a key hybrid.
	if isPQCAlgorithm(alg) {
		return "pqc_only"
	}
	return "classical"
}

func certificateInventoryMode(item map[string]interface{}) string {
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
	return "classical"
}

// buildPQCRecommendations names only what the inventory found.
func buildPQCRecommendations(classicalUsage []ClassicalUsageItem, nonMigratedCerts []CertificatePQCItem) []string {
	out := make([]string, 0, 2)
	if len(classicalUsage) > 0 {
		out = append(out, "Rotate RSA/ECC-only keys and certificates to hybrid or PQC-native algorithms, starting with the highest-QSL-risk assets.")
	}
	if len(nonMigratedCerts) > 0 {
		out = append(out, "Issue hybrid or PQC-class certificates for externally exposed interfaces before moving them to PQC-only.")
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

var errManualStep = errors.New("manual step")

// applyMigrationStep performs a key step in keycore and returns what it did:
// "rotated" (target is the current algorithm), "algorithm_changed" (same key
// ID, new algorithm) or "successor_created" (a new
// key of the target algorithm, id returned). Non-key assets return
// errManualStep: nothing is changed and the step is never marked completed.
// Before 1.26.0-beta every step was marked completed after a same-algorithm
// rotate, or after nothing at all.
func (s *Service) applyMigrationStep(ctx context.Context, tenantID string, step MigrationStep, actor string) (string, string, error) {
	if _, ok := cryptocatalog.Lookup(step.TargetAlg); !isKeyAsset(step.AssetType) || !ok {
		return "", "", errManualStep
	}
	if s.keycore == nil {
		return "", "", errKeycoreNotConfigured
	}
	reason := "pqc migration by " + defaultString(actor, "system") + ": " + step.CurrentAlg + " -> " + step.TargetAlg
	if normalizeAlgorithm(step.TargetAlg) == normalizeAlgorithm(step.CurrentAlg) {
		return "rotated", "", s.keycore.RotateKey(ctx, tenantID, step.AssetID, reason, "")
	}
	// Preferred: the key moves to the target under the same key ID, so its
	// callers change nothing. Keycore refuses when the target can't serve
	// what the key does (e.g. an RSA encryption key to ML-KEM); only then is
	// a successor key created, which callers must adopt.
	// A discovered key (cloud KMS, …) isn't keycore's to rotate.
	if firstString(step.Metadata["source"]) == "keycore" {
		err := s.keycore.RotateKey(ctx, tenantID, step.AssetID, reason, step.TargetAlg)
		if err == nil {
			return "algorithm_changed", "", nil
		}
		if !strings.HasPrefix(err.Error(), "algorithm change refused") {
			return "", "", err
		}
	}
	keyType, purpose := "symmetric", "encrypt-decrypt"
	switch target := normalizeAlgorithm(step.TargetAlg); {
	case strings.Contains(target, "ML-DSA"), strings.Contains(target, "SLH-DSA"):
		keyType, purpose = "asymmetric-private", "sign-verify"
	case strings.Contains(target, "ML-KEM"):
		keyType, purpose = "asymmetric-private", "key-encapsulation"
	}
	id, err := s.keycore.CreateKey(ctx, tenantID, map[string]interface{}{
		"name":       defaultString(step.Name, step.AssetID) + "-" + strings.ToLower(step.TargetAlg),
		"algorithm":  step.TargetAlg,
		"key_type":   keyType,
		"purpose":    purpose,
		"owner":      defaultString(actor, "system"),
		"created_by": defaultString(actor, "system"),
		"labels":     map[string]string{"pqc_successor_of": step.AssetID},
	})
	return "successor_created", id, err
}

// buildTimelineMilestones lists the customer's migration plans that have a
// deadline, soonest first, with how many of each plan's steps are still
// open. The product sets no deadlines of its own.
func (s *Service) buildTimelineMilestones(ctx context.Context, tenantID string) []TimelineMilestone {
	out := []TimelineMilestone{}
	plans, err := s.store.ListMigrationPlans(ctx, tenantID, 500, 0)
	if err != nil {
		return out
	}
	now := s.now()
	done := map[string]bool{"completed": true, "rotated": true, "algorithm_changed": true, "successor_created": true}
	for _, p := range plans {
		if p.Deadline.IsZero() || p.Status == "rolled_back" {
			continue
		}
		open, algs := 0, map[string]bool{}
		for _, st := range p.Steps {
			if !done[st.Status] {
				open++
				algs[st.CurrentAlg] = true
			}
		}
		names := make([]string, 0, len(algs))
		for a := range algs {
			names = append(names, a)
		}
		sort.Strings(names)
		days := int(p.Deadline.Sub(now).Hours() / 24)
		status := "upcoming"
		switch {
		case open == 0:
			status = "met"
		case days < 0:
			status = "overdue"
		case days <= 365:
			status = "due_within_year"
		}
		out = append(out, TimelineMilestone{
			ID: p.ID, Standard: p.TimelineStandard, Title: p.Name, DueDate: p.Deadline,
			Status: status, DaysLeft: days, AffectedAssets: open, Description: strings.Join(names, ", "),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DueDate.Before(out[j].DueDate) })
	return out
}

// timelineStatusMap is the scan's summary of those milestones, keyed by plan.
func (s *Service) timelineStatusMap(ctx context.Context, tenantID string) map[string]interface{} {
	out := map[string]interface{}{}
	for _, m := range s.buildTimelineMilestones(ctx, tenantID) {
		out[m.ID] = map[string]interface{}{
			"plan":            m.Title,
			"deadline":        m.DueDate.Format("2006-01-02"),
			"status":          m.Status,
			"days_remaining":  m.DaysLeft,
			"affected_assets": m.AffectedAssets,
		}
	}
	return out
}

// migrationTarget is the algorithm an asset should move to. A key asset's
// target is one keycore can generate; other assets (TLS endpoints,
// certificates, code) get the algorithm to adopt, and their steps are manual
// since the KMS cannot change them. An algorithm the catalogue cannot assess
// gets no target.
func migrationTarget(alg string, assetType string) string {
	e, ok := cryptocatalog.Lookup(alg)
	switch {
	case ok && e.PostQuantum:
		return e.Algorithm
	case strings.Contains(strings.ToLower(assetType), "tls"):
		return "X25519MLKEM768"
	case !ok:
		return ""
	case e.Function == "key_establishment":
		return "ML-KEM-768"
	case e.QuantumVulnerable:
		// Signatures, and RSA or EC keys whose use the asset doesn't record.
		return "ML-DSA-65"
	case e.Weak:
		return "AES-256" // weak symmetric (3DES, DES, AES-ECB)
	}
	return e.Algorithm
}

func isKeyAsset(assetType string) bool {
	switch strings.ToLower(strings.TrimSpace(assetType)) {
	case "key", "kms_key":
		return true
	}
	return false
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
		return "classical_replacement"
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

func formatScore(v float64) string {
	return strings.TrimRight(strings.TrimRight(strconv.FormatFloat(round2(v), 'f', 2, 64), "0"), ".")
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

// classifyListener states what a measured listener's groups are, from
// pkg/cryptocatalog.
func classifyListener(m ListenerMeasurement) ListenerPQCItem {
	item := ListenerPQCItem{ListenerMeasurement: m, Classification: "hybrid", QuantumVulnerableGroups: []string{}}
	if len(m.AcceptedGroups) == 0 {
		item.Classification = "not_assessed"
	}
	for _, g := range m.AcceptedGroups {
		e, ok := cryptocatalog.Lookup(g)
		switch {
		case !ok:
			item.Classification = "not_assessed"
		case e.QuantumVulnerable:
			item.QuantumVulnerableGroups = append(item.QuantumVulnerableGroups, g)
		case !e.Hybrid && !e.PostQuantum:
			item.Classification = "not_assessed"
		}
	}
	if len(item.QuantumVulnerableGroups) > 0 && item.Classification != "not_assessed" {
		item.Classification = "classical"
	}
	return item
}
