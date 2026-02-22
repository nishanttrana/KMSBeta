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
	discovery DiscoveryClient
	events    EventPublisher
	now       func() time.Time
}

func NewService(store Store, keycore KeyCoreClient, discovery DiscoveryClient, events EventPublisher) *Service {
	return &Service{
		store:     store,
		keycore:   keycore,
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
