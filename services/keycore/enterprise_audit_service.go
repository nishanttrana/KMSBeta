package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

func (s *Service) CalculateKeyHealth(ctx context.Context, tenantID, keyID string) (KeyHealthScore, error) {
	key, err := s.GetKey(ctx, tenantID, keyID)
	if err != nil {
		return KeyHealthScore{}, err
	}
	now := time.Now().UTC()
	entropyScore := entropyScoreForAlgorithm(key.Algorithm)
	ageScore := ageScoreForKey(key.CreatedAt, 365)
	usageScore := usageScoreForKey(key.OpsTotal, key.CreatedAt)
	algorithmScore := algorithmHealthScore(key.Algorithm)

	backupStatus := "missing"
	if inv, err := s.store.GetInventoryItem(ctx, tenantID, keyID); err == nil {
		backupStatus = backupStatusForVerification(inv.BackupVerifiedAt, 30)
	}
	rotationOverdue := now.Sub(key.UpdatedAt.UTC()) > 90*24*time.Hour
	expiryImminent := false
	if key.ExpiryDate != nil {
		expiryImminent = key.ExpiryDate.UTC().Before(now.AddDate(0, 0, 90))
	}

	backupScore := map[string]int{"verified": 100, "stale": 60, "missing": 20, "unknown": 50}[backupStatus]
	if backupScore == 0 {
		backupScore = 50
	}
	rotationScore := 100
	if rotationOverdue {
		rotationScore = 20
	}

	overall := int(float64(entropyScore)*0.15 +
		float64(ageScore)*0.15 +
		float64(usageScore)*0.15 +
		float64(algorithmScore)*0.25 +
		float64(backupScore)*0.15 +
		float64(rotationScore)*0.15)

	status := normalizeLifecycleStatus(key.Status)
	if status == StateSuspended && overall > 65 {
		overall = 65
	}
	if status == StateCompromised && overall > 25 {
		overall = 25
	}
	if isDeletedLike(status) {
		overall = 0
	}

	score := KeyHealthScore{
		KeyID:              keyID,
		TenantID:           tenantID,
		HealthScore:        clampScore(overall),
		EntropyScore:       entropyScore,
		AgeScore:           ageScore,
		UsageScore:         usageScore,
		AlgorithmScore:     algorithmScore,
		BackupStatus:       backupStatus,
		RotationOverdue:    rotationOverdue,
		ExpiryImminent:     expiryImminent,
		ComplianceWarnings: healthWarnings(key, algorithmScore, backupStatus, rotationOverdue, expiryImminent),
		UpdatedAt:          now,
	}
	score.RecommendedActions = healthRecommendations(score, key)
	if err := s.store.UpsertKeyHealthScore(ctx, score); err != nil {
		return KeyHealthScore{}, err
	}
	_ = s.publishAudit(ctx, "audit.key.health_scored", tenantID, map[string]any{
		"key_id":       keyID,
		"health_score": score.HealthScore,
	})
	return score, nil
}

func (s *Service) SyncKeyInventory(ctx context.Context, tenantID string) (KeyInventorySummary, error) {
	keys, err := s.store.ListKeys(ctx, tenantID, 10000, 0)
	if err != nil {
		return KeyInventorySummary{}, err
	}
	now := time.Now().UTC()
	for _, key := range keys {
		if normalizeLifecycleStatus(key.Status) == "deleted" {
			continue
		}
		var existing KeyInventoryItem
		if inv, err := s.store.GetInventoryItem(ctx, tenantID, key.ID); err == nil {
			existing = inv
		}
		item := KeyInventoryItem{
			KeyID:              key.ID,
			TenantID:           tenantID,
			KeyName:            key.Name,
			KeyType:            key.KeyType,
			Algorithm:          key.Algorithm,
			Owner:              key.Owner,
			Status:             normalizeLifecycleStatus(key.Status),
			CreatedDate:        key.CreatedAt,
			CloudProvider:      key.Cloud,
			Region:             key.Region,
			ComplianceTags:     key.Compliance,
			ExpiryDate:         key.ExpiryDate,
			BackupVerifiedAt:   existing.BackupVerifiedAt,
			HSMStored:          existing.HSMStored,
			RotationFrequency:  existing.RotationFrequency,
			NextRotation:       existing.NextRotation,
			Metadata:           map[string]any{"tags": key.Tags, "labels": key.Labels, "current_version": key.CurrentVersion},
			DiscoveredVia:      "keycore_sync",
			DiscoveryTimestamp: &now,
		}
		if key.OpsTotal > 0 {
			t := key.UpdatedAt.UTC()
			item.LastUsed = &t
		}
		if key.CurrentVersion > 1 {
			t := key.UpdatedAt.UTC()
			item.LastRotated = &t
		}
		if item.RotationFrequency == "" {
			item.RotationFrequency = "quarterly"
		}
		if item.NextRotation == nil {
			t := key.UpdatedAt.UTC().AddDate(0, 0, 90)
			item.NextRotation = &t
		}
		if err := s.store.UpsertInventoryItem(ctx, item); err != nil {
			return KeyInventorySummary{}, err
		}
		_, _ = s.CalculateKeyHealth(ctx, tenantID, key.ID)
	}
	duplicates, err := s.DetectDuplicateKeys(ctx, tenantID)
	if err != nil {
		return KeyInventorySummary{}, err
	}
	summary, err := s.store.GetInventorySummary(ctx, tenantID, len(duplicates))
	if err != nil {
		return KeyInventorySummary{}, err
	}
	_ = s.publishAudit(ctx, "audit.key.inventory_synced", tenantID, map[string]any{
		"total_keys":     summary.TotalKeys,
		"orphaned_keys":  summary.OrphanedKeys,
		"duplicate_sets": summary.DuplicateSets,
	})
	return summary, nil
}

func (s *Service) DetectDuplicateKeys(ctx context.Context, tenantID string) ([]DuplicateKeyGroup, error) {
	keys, err := s.store.ListKeys(ctx, tenantID, 10000, 0)
	if err != nil {
		return nil, err
	}
	groups := map[string][]string{}
	algorithms := map[string]string{}
	for _, key := range keys {
		if len(key.KCV) == 0 || isDeletedLike(key.Status) {
			continue
		}
		fingerprint := strings.ToUpper(hex.EncodeToString(key.KCV))
		groupKey := strings.ToUpper(strings.TrimSpace(key.Algorithm)) + "|" + fingerprint
		groups[groupKey] = append(groups[groupKey], key.ID)
		algorithms[groupKey] = key.Algorithm
	}
	out := make([]DuplicateKeyGroup, 0)
	for groupKey, ids := range groups {
		if len(ids) < 2 {
			continue
		}
		sort.Strings(ids)
		parts := strings.SplitN(groupKey, "|", 2)
		out = append(out, DuplicateKeyGroup{
			Fingerprint: parts[1],
			Algorithm:   algorithms[groupKey],
			KeyIDs:      ids,
			Count:       len(ids),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Fingerprint < out[j].Fingerprint
		}
		return out[i].Count > out[j].Count
	})
	return out, nil
}

func (s *Service) ReportCompromiseEvent(ctx context.Context, event CompromiseEvent, autoSuspend bool) (CompromiseEvent, error) {
	key, err := s.GetKey(ctx, event.TenantID, event.KeyID)
	if err != nil {
		return CompromiseEvent{}, err
	}
	now := time.Now().UTC()
	if strings.TrimSpace(event.EventID) == "" {
		event.EventID = newID("cmp")
	}
	event.ThreatType = normalizeThreatType(event.ThreatType)
	event.Severity = normalizeSeverity(event.Severity)
	if strings.TrimSpace(event.Status) == "" {
		event.Status = "pending"
	}
	if event.DetectionDate.IsZero() {
		event.DetectionDate = now
	}
	if strings.TrimSpace(event.RemediationStatus) == "" {
		event.RemediationStatus = "not_started"
	}
	if strings.TrimSpace(event.RemediationPlan) == "" {
		event.RemediationPlan = "Suspend or isolate impacted key, rotate dependent data keys, verify downstream services, and close with evidence."
	}
	if event.Metadata == nil {
		event.Metadata = map[string]any{}
	}

	shouldSuspend := autoSuspend || event.Severity == "critical" || event.Severity == "high"
	autoSuspended := false
	targetStatus := StateSuspended
	currentStatus := normalizeLifecycleStatus(key.Status)
	if currentStatus == StateDeactivated {
		targetStatus = StateCompromised
	}
	if shouldSuspend && currentStatus != targetStatus && !isDeletedLike(currentStatus) {
		if err := CanTransition(currentStatus, targetStatus, true); err == nil {
			if err := s.store.SetKeyStatus(ctx, event.TenantID, event.KeyID, targetStatus); err == nil {
				autoSuspended = true
				_ = s.cache.Delete(ctx, event.TenantID, event.KeyID)
				_ = s.publishAudit(ctx, "audit.key.compromise_auto_suspended", event.TenantID, map[string]any{
					"key_id":        event.KeyID,
					"event_id":      event.EventID,
					"from":          currentStatus,
					"to":            targetStatus,
					"severity":      event.Severity,
					"detection_src": event.DetectionSource,
				})
			}
		}
	}
	event.Metadata["auto_suspend_evaluated"] = shouldSuspend
	event.Metadata["auto_suspended"] = autoSuspended
	event.Metadata["key_status_before_response"] = currentStatus
	event.UpdatedAt = now
	event.CreatedAt = now
	if err := s.store.RecordCompromiseEvent(ctx, event); err != nil {
		return CompromiseEvent{}, err
	}
	_ = s.publishAudit(ctx, "audit.key.compromise_detected", event.TenantID, map[string]any{
		"key_id":         event.KeyID,
		"event_id":       event.EventID,
		"severity":       event.Severity,
		"threat_type":    event.ThreatType,
		"auto_suspended": autoSuspended,
	})
	return event, nil
}

func (s *Service) IngestCompromiseAdvisories(ctx context.Context, tenantID string, advisories []CompromiseAdvisory, autoSuspend bool) (CompromiseIngestResult, error) {
	if len(advisories) > 200 {
		return CompromiseIngestResult{}, fmt.Errorf("advisory ingest limited to 200 items")
	}
	keys, err := s.store.ListKeys(ctx, tenantID, 10000, 0)
	if err != nil {
		return CompromiseIngestResult{}, err
	}
	keysByID := map[string]Key{}
	keysByAlgorithm := map[string][]Key{}
	for _, key := range keys {
		if isDeletedLike(key.Status) {
			continue
		}
		keysByID[key.ID] = key
		keysByAlgorithm[strings.ToUpper(strings.TrimSpace(key.Algorithm))] = append(keysByAlgorithm[strings.ToUpper(strings.TrimSpace(key.Algorithm))], key)
	}

	result := CompromiseIngestResult{AdvisoriesProcessed: len(advisories)}
	for _, advisory := range advisories {
		targets := map[string]Key{}
		for _, keyID := range advisory.AffectedKeyIDs {
			if key, ok := keysByID[strings.TrimSpace(keyID)]; ok {
				targets[key.ID] = key
			}
		}
		for _, alg := range advisory.AffectedAlgorithms {
			for _, key := range keysByAlgorithm[strings.ToUpper(strings.TrimSpace(alg))] {
				targets[key.ID] = key
			}
		}
		for _, key := range targets {
			metadata := map[string]any{
				"advisory_summary":    advisory.Summary,
				"affected_algorithms": advisory.AffectedAlgorithms,
			}
			if advisory.Metadata != nil {
				metadata["feed_metadata"] = advisory.Metadata
			}
			if advisory.PublishedAt != nil {
				metadata["published_at"] = advisory.PublishedAt.UTC().Format(time.RFC3339)
			}
			event, err := s.ReportCompromiseEvent(ctx, CompromiseEvent{
				TenantID:        tenantID,
				KeyID:           key.ID,
				CVEID:           advisory.CVEID,
				ThreatType:      advisory.ThreatType,
				Severity:        advisory.Severity,
				DetectionSource: firstNonEmpty(advisory.DetectionSource, "feed_ingest"),
				Metadata:        metadata,
			}, autoSuspend)
			if err != nil {
				return result, err
			}
			result.EventsCreated++
			if suspended, _ := event.Metadata["auto_suspended"].(bool); suspended {
				result.AutoSuspendedKeys++
			}
			result.Events = append(result.Events, event)
		}
	}
	return result, nil
}

func (s *Service) GetEnterpriseAuditSummary(ctx context.Context, tenantID string, days int) (EnterpriseAuditSummary, error) {
	if days <= 0 {
		days = 30
	}
	since := time.Now().UTC().AddDate(0, 0, -days)
	duplicates, err := s.DetectDuplicateKeys(ctx, tenantID)
	if err != nil {
		return EnterpriseAuditSummary{}, err
	}
	rotation, err := s.store.GetRotationAnalyticsSummary(ctx, tenantID, days)
	if err != nil {
		return EnterpriseAuditSummary{}, err
	}
	health, err := s.store.GetKeyHealthSummary(ctx, tenantID)
	if err != nil {
		return EnterpriseAuditSummary{}, err
	}
	inventory, err := s.store.GetInventorySummary(ctx, tenantID, len(duplicates))
	if err != nil {
		return EnterpriseAuditSummary{}, err
	}
	compromise, err := s.store.GetCompromiseSummary(ctx, tenantID)
	if err != nil {
		return EnterpriseAuditSummary{}, err
	}
	hotspots, err := s.store.ListKeyHotspots(ctx, tenantID, since, 10)
	if err != nil {
		return EnterpriseAuditSummary{}, err
	}
	benchmarks, err := s.store.GetAlgorithmBenchmarks(ctx, tenantID, since)
	if err != nil {
		return EnterpriseAuditSummary{}, err
	}
	return EnterpriseAuditSummary{
		TenantID:    tenantID,
		GeneratedAt: time.Now().UTC(),
		Rotation:    rotation,
		Health:      health,
		Inventory:   inventory,
		Compromise:  compromise,
		Hotspots:    hotspots,
		Algorithms:  benchmarks,
		Roadmap:     enterpriseAuditRoadmap(),
	}, nil
}

func entropyScoreForAlgorithm(algorithm string) int {
	bits := algorithmSecurityBits(algorithm)
	switch {
	case bits >= 256:
		return 100
	case bits >= 192:
		return 90
	case bits >= 128:
		return 80
	case bits >= 112:
		return 65
	default:
		return 40
	}
}

func algorithmSecurityBits(algorithm string) int {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "AES-256", "HMAC-SHA512", "ML-KEM-1024", "ML-DSA-87", "SLH-DSA-SHA2-256S", "SLH-DSA-SHAKE-256S":
		return 256
	case "AES-192", "HMAC-SHA384", "EC-P384", "ECDSA-P384", "ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-192S", "SLH-DSA-SHAKE-192S":
		return 192
	case "AES-128", "HMAC-SHA256", "RSA-3072", "RSA-4096", "EC-P256", "ECDSA-P256", "ED25519", "ML-KEM-512", "ML-DSA-44", "SLH-DSA-SHA2-128S", "SLH-DSA-SHAKE-128S":
		return 128
	case "RSA-2048":
		return 112
	default:
		return 96
	}
}

func algorithmHealthScore(algorithm string) int {
	switch strings.ToUpper(strings.TrimSpace(algorithm)) {
	case "MD5", "SHA-1", "DES", "3DES", "RSA-1024", "EC-P192", "ECDSA-P192":
		return 20
	case "RSA-2048":
		return 75
	default:
		if algorithmSecurityBits(algorithm) >= 128 {
			return 100
		}
		return 60
	}
}

func ageScoreForKey(createdAt time.Time, maxAgeDays int) int {
	if createdAt.IsZero() {
		return 60
	}
	if maxAgeDays <= 0 {
		maxAgeDays = 365
	}
	ageDays := time.Since(createdAt.UTC()).Hours() / 24
	if ageDays <= 0 {
		return 100
	}
	score := int((1 - ageDays/float64(maxAgeDays)) * 100)
	if score < 40 {
		return 40
	}
	return clampScore(score)
}

func usageScoreForKey(totalOps int64, createdAt time.Time) int {
	if totalOps == 0 {
		return 60
	}
	days := time.Since(createdAt.UTC()).Hours() / 24
	if days <= 0 {
		return 90
	}
	opsPerDay := float64(totalOps) / days
	switch {
	case opsPerDay > 1000:
		return 100
	case opsPerDay > 100:
		return 90
	case opsPerDay > 10:
		return 80
	default:
		return 70
	}
}

func backupStatusForVerification(lastVerified *time.Time, maxAgeDays int) string {
	if lastVerified == nil {
		return "missing"
	}
	if maxAgeDays <= 0 {
		maxAgeDays = 30
	}
	ageDays := time.Since(lastVerified.UTC()).Hours() / 24
	switch {
	case ageDays <= float64(maxAgeDays):
		return "verified"
	case ageDays <= float64(maxAgeDays*2):
		return "stale"
	default:
		return "missing"
	}
}

func healthWarnings(key Key, algorithmScore int, backupStatus string, rotationOverdue, expiryImminent bool) []string {
	var warnings []string
	if algorithmScore < 80 {
		warnings = append(warnings, "algorithm requires modernization")
	}
	if backupStatus != "verified" {
		warnings = append(warnings, "backup verification is not current")
	}
	if rotationOverdue {
		warnings = append(warnings, "rotation is overdue")
	}
	if expiryImminent {
		warnings = append(warnings, "expiry is within the warning window")
	}
	if normalizeLifecycleStatus(key.Status) == StateSuspended {
		warnings = append(warnings, "key is suspended")
	}
	if normalizeLifecycleStatus(key.Status) == StateCompromised {
		warnings = append(warnings, "key is marked compromised")
	}
	return warnings
}

func healthRecommendations(score KeyHealthScore, key Key) []string {
	var actions []string
	if score.HealthScore < 60 {
		actions = append(actions, "open an immediate key review")
	}
	if score.RotationOverdue {
		actions = append(actions, "rotate the key and validate dependent services")
	}
	if score.BackupStatus == "missing" {
		actions = append(actions, "verify backup coverage or escrow policy")
	}
	if score.BackupStatus == "stale" {
		actions = append(actions, "refresh backup verification")
	}
	if score.AlgorithmScore < 80 {
		actions = append(actions, "migrate to a stronger or post-quantum-ready algorithm")
	}
	if score.ExpiryImminent {
		actions = append(actions, "schedule replacement before expiry")
	}
	if normalizeLifecycleStatus(key.Status) == StateSuspended {
		actions = append(actions, "complete incident triage before reactivation")
	}
	if len(actions) == 0 {
		actions = append(actions, "continue scheduled monitoring")
	}
	return actions
}

func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func normalizeThreatType(threatType string) string {
	switch strings.ToLower(strings.TrimSpace(threatType)) {
	case "cve", "breach", "suspicious_activity", "key_exposure", "algorithm_weakness", "canary_trip":
		return strings.ToLower(strings.TrimSpace(threatType))
	case "":
		return "suspicious_activity"
	default:
		return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(threatType), " ", "_"))
	}
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(severity))
	case "":
		return "high"
	default:
		return "medium"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func enterpriseAuditRoadmap() []AuditRoadmapItem {
	return []AuditRoadmapItem{
		{ID: 1, Tier: 1, Name: "Key Rotation Analytics Dashboard", Status: "implemented", Impact: "5/5", Effort: "2-3 weeks", Capabilities: []string{"rotation schedules", "success rates", "overdue detection", "batch visibility"}},
		{ID: 2, Tier: 1, Name: "Key Compromise Detection & Response", Status: "implemented", Impact: "5/5", Effort: "2-3 weeks", Capabilities: []string{"advisory ingestion", "automated suspension", "incident workflow state", "remediation evidence"}},
		{ID: 3, Tier: 1, Name: "Advanced Key Analytics & Reporting", Status: "implemented", Impact: "5/5", Effort: "3 weeks", Capabilities: []string{"real-time usage metrics", "hotspot detection", "trend data", "algorithm benchmarking"}},
		{ID: 4, Tier: 1, Name: "Key Health Scoring & Monitoring", Status: "implemented", Impact: "4/5", Effort: "2-3 weeks", Capabilities: []string{"health scoring", "backup verification status", "rotation and expiry warnings", "modernization recommendations"}},
		{ID: 5, Tier: 1, Name: "Key Inventory & Dependency Mapping", Status: "implemented", Impact: "4/5", Effort: "2-3 weeks", Capabilities: []string{"inventory sync", "dependency graph records", "orphaned key detection", "duplicate KCV detection"}},
		{ID: 6, Tier: 2, Name: "Machine Learning & Anomaly Detection", Status: "roadmap", Impact: "5/5", Effort: "3-4 weeks", Capabilities: []string{"behavioral baselines", "predictive failure", "insider-threat scoring"}},
		{ID: 7, Tier: 2, Name: "Advanced Key Scheduling & Orchestration", Status: "foundation", Impact: "4/5", Effort: "3 weeks", Capabilities: []string{"cron expressions", "rotation policy API", "batch run records"}},
		{ID: 8, Tier: 2, Name: "Key Federation & Multi-KMS Orchestration", Status: "roadmap", Impact: "4/5", Effort: "3-4 weeks", Capabilities: []string{"cross-KMS lookup", "distributed sync", "cross-region failover"}},
		{ID: 9, Tier: 2, Name: "Enhanced Key Recovery & Escrow", Status: "foundation", Impact: "4/5", Effort: "3 weeks", Capabilities: []string{"guardians", "recovery requests", "quorum workflows"}},
		{ID: 10, Tier: 2, Name: "Blockchain-Backed Audit Chain", Status: "foundation", Impact: "3/5", Effort: "4+ weeks", Capabilities: []string{"Merkle audit chain", "external anchoring adapters"}},
		{ID: 11, Tier: 3, Name: "Key Derivation Functions", Status: "foundation", Impact: "4/5", Effort: "2-3 weeks", Capabilities: []string{"HKDF endpoint", "derivation metering"}},
		{ID: 12, Tier: 3, Name: "Key Material Verification", Status: "foundation", Impact: "4/5", Effort: "2 weeks", Capabilities: []string{"KCV verification", "fingerprint tracking"}},
		{ID: 13, Tier: 3, Name: "Regulatory Compliance Dashboard", Status: "foundation", Impact: "4/5", Effort: "2-3 weeks", Capabilities: []string{"framework scoring", "evidence generation"}},
		{ID: 14, Tier: 3, Name: "Cost & Optimization Dashboard", Status: "roadmap", Impact: "3/5", Effort: "2-3 weeks", Capabilities: []string{"tenant usage cost", "efficiency scoring"}},
		{ID: 15, Tier: 4, Name: "Advanced Encryption Modes", Status: "research", Impact: "3/5", Effort: "4+ weeks", Capabilities: []string{"homomorphic", "searchable", "functional encryption"}},
		{ID: 16, Tier: 4, Name: "Enhanced Key Binding", Status: "foundation", Impact: "3/5", Effort: "3 weeks", Capabilities: []string{"hardware attestation", "geofence controls"}},
		{ID: 17, Tier: 4, Name: "Edge & IoT Key Management", Status: "foundation", Impact: "3/5", Effort: "3-4 weeks", Capabilities: []string{"EKM agents", "offline operations"}},
		{ID: 18, Tier: 3, Name: "Fine-Grained Key Sharing", Status: "foundation", Impact: "3/5", Effort: "2-3 weeks", Capabilities: []string{"temporary grants", "justifications", "delegation policy"}},
		{ID: 19, Tier: 3, Name: "Key Metadata Management", Status: "foundation", Impact: "3/5", Effort: "2 weeks", Capabilities: []string{"tags", "labels", "inventory metadata"}},
		{ID: 20, Tier: 4, Name: "Advanced Threat Protection", Status: "foundation", Impact: "4/5", Effort: "4+ weeks", Capabilities: []string{"side-channel test suite", "canary keys", "compromise workflows"}},
	}
}
