package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"
)

func (s *SQLStore) RecordRotationMetric(ctx context.Context, metric RotationMetric) error {
	now := time.Now().UTC()
	if strings.TrimSpace(metric.RotationID) == "" {
		metric.RotationID = newID("rotm")
	}
	if metric.ScheduledDate.IsZero() {
		metric.ScheduledDate = now
	}
	if strings.TrimSpace(metric.Status) == "" {
		metric.Status = "scheduled"
	}
	if strings.TrimSpace(metric.InitiatedBy) == "" {
		metric.InitiatedBy = "system"
	}
	if metric.CreatedAt.IsZero() {
		metric.CreatedAt = now
	}
	if metric.UpdatedAt.IsZero() {
		metric.UpdatedAt = now
	}
	metadata, _ := json.Marshal(nonNilMap(metric.Metadata))
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_rotation_metrics (
    rotation_id, tenant_id, key_id, scheduled_date, actual_date, status, duration_ms,
    reason, initiated_by, completed_by, error_details, old_version, new_version,
    rollback_attempted, metadata_json, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
ON CONFLICT (tenant_id, rotation_id) DO UPDATE SET
    key_id = EXCLUDED.key_id,
    scheduled_date = EXCLUDED.scheduled_date,
    actual_date = EXCLUDED.actual_date,
    status = EXCLUDED.status,
    duration_ms = EXCLUDED.duration_ms,
    reason = EXCLUDED.reason,
    initiated_by = EXCLUDED.initiated_by,
    completed_by = EXCLUDED.completed_by,
    error_details = EXCLUDED.error_details,
    old_version = EXCLUDED.old_version,
    new_version = EXCLUDED.new_version,
    rollback_attempted = EXCLUDED.rollback_attempted,
    metadata_json = EXCLUDED.metadata_json,
    updated_at = CURRENT_TIMESTAMP
`, metric.RotationID, metric.TenantID, metric.KeyID, metric.ScheduledDate, nullableTime(metric.ActualDate),
		metric.Status, metric.DurationMs, nullable(metric.Reason), nullable(metric.InitiatedBy),
		nullable(metric.CompletedBy), nullable(metric.ErrorDetails), metric.OldVersion, metric.NewVersion,
		metric.RollbackAttempt, metadata, metric.CreatedAt, metric.UpdatedAt)
	return err
}

func (s *SQLStore) ListRotationMetrics(ctx context.Context, tenantID, keyID, status string, limit int) ([]RotationMetric, error) {
	limit = clampAuditLimit(limit, 200)
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT rotation_id, tenant_id, key_id, scheduled_date, actual_date, status, COALESCE(duration_ms,0),
       COALESCE(reason,''), COALESCE(initiated_by,''), COALESCE(completed_by,''), COALESCE(error_details,''),
       COALESCE(old_version,0), COALESCE(new_version,0), COALESCE(rollback_attempted,FALSE),
       COALESCE(metadata_json,'{}'), created_at, updated_at
FROM key_rotation_metrics
WHERE tenant_id=$1
  AND ($2='' OR key_id=$2)
  AND ($3='' OR status=$3)
ORDER BY created_at DESC
LIMIT $4
`, tenantID, strings.TrimSpace(keyID), strings.TrimSpace(status), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []RotationMetric
	for rows.Next() {
		item, err := scanRotationMetric(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListOverdueRotationMetrics(ctx context.Context, tenantID string, limit int) ([]RotationMetric, error) {
	limit = clampAuditLimit(limit, 200)
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT rotation_id, tenant_id, key_id, scheduled_date, actual_date, status, COALESCE(duration_ms,0),
       COALESCE(reason,''), COALESCE(initiated_by,''), COALESCE(completed_by,''), COALESCE(error_details,''),
       COALESCE(old_version,0), COALESCE(new_version,0), COALESCE(rollback_attempted,FALSE),
       COALESCE(metadata_json,'{}'), created_at, updated_at
FROM key_rotation_metrics
WHERE tenant_id=$1
  AND status IN ('scheduled','in_progress')
  AND scheduled_date < CURRENT_TIMESTAMP
ORDER BY scheduled_date ASC
LIMIT $2
`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []RotationMetric
	for rows.Next() {
		item, err := scanRotationMetric(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetRotationAnalyticsSummary(ctx context.Context, tenantID string, days int) (RotationAnalyticsSummary, error) {
	if days <= 0 {
		days = 30
	}
	since := time.Now().UTC().AddDate(0, 0, -days)
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT
    COUNT(*),
    COUNT(CASE WHEN status='scheduled' THEN 1 END),
    COUNT(CASE WHEN status='in_progress' THEN 1 END),
    COUNT(CASE WHEN status='completed' THEN 1 END),
    COUNT(CASE WHEN status='failed' THEN 1 END),
    COUNT(CASE WHEN status='cancelled' THEN 1 END),
    COALESCE(AVG(CASE WHEN status='completed' THEN duration_ms END),0),
    MIN(CASE WHEN status='scheduled' THEN scheduled_date END),
    MAX(CASE WHEN status='completed' THEN actual_date END),
    COUNT(CASE WHEN LOWER(COALESCE(reason,'')) LIKE '%bulk%' OR LOWER(COALESCE(initiated_by,'')) LIKE '%batch%' THEN 1 END)
FROM key_rotation_metrics
WHERE tenant_id=$1 AND created_at >= $2
`, tenantID, since)
	var (
		summary       RotationAnalyticsSummary
		avgDuration   float64
		nextScheduled sql.NullTime
		lastCompleted sql.NullTime
		batchOps      int
		completed     int
		failed        int
	)
	if err := row.Scan(&summary.Total, &summary.Scheduled, &summary.InProgress, &completed, &failed,
		&summary.Cancelled, &avgDuration, &nextScheduled, &lastCompleted, &batchOps); err != nil {
		return RotationAnalyticsSummary{}, err
	}
	overdue, err := s.countOverdueRotations(ctx, tenantID)
	if err != nil {
		return RotationAnalyticsSummary{}, err
	}
	summary.TenantID = tenantID
	summary.WindowDays = days
	summary.Completed = completed
	summary.Failed = failed
	summary.Overdue = overdue
	summary.AverageDurationMs = int64(avgDuration)
	summary.BatchOperations = batchOps
	if nextScheduled.Valid {
		t := nextScheduled.Time.UTC()
		summary.NextScheduledAt = &t
	}
	if lastCompleted.Valid {
		t := lastCompleted.Time.UTC()
		summary.LastCompletedAt = &t
	}
	if completed+failed > 0 {
		summary.SuccessRate = float64(completed) / float64(completed+failed) * 100
	}
	summary.GeneratedAt = time.Now().UTC()
	return summary, nil
}

func (s *SQLStore) RecordKeyAnalyticsMetric(ctx context.Context, metric KeyAnalyticsMetric) error {
	if strings.TrimSpace(metric.MetricID) == "" {
		metric.MetricID = newID("met")
	}
	if strings.TrimSpace(metric.AggregationPeriod) == "" {
		metric.AggregationPeriod = "realtime"
	}
	if metric.Timestamp.IsZero() {
		metric.Timestamp = time.Now().UTC()
	}
	metadata, _ := json.Marshal(nonNilMap(metric.Metadata))
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_analytics_metrics
    (metric_id, tenant_id, key_id, metric_type, value, aggregation_period, timestamp, metadata_json)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (tenant_id, metric_id) DO UPDATE SET
    key_id=EXCLUDED.key_id,
    metric_type=EXCLUDED.metric_type,
    value=EXCLUDED.value,
    aggregation_period=EXCLUDED.aggregation_period,
    timestamp=EXCLUDED.timestamp,
    metadata_json=EXCLUDED.metadata_json
`, metric.MetricID, metric.TenantID, metric.KeyID, metric.MetricType, metric.Value,
		metric.AggregationPeriod, metric.Timestamp, metadata)
	return err
}

func (s *SQLStore) GetKeyUsageMetricSummary(ctx context.Context, tenantID, keyID string, since time.Time) (KeyUsageMetricSummary, error) {
	if since.IsZero() {
		since = time.Now().UTC().AddDate(0, 0, -1)
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT metric_type, COUNT(*), COALESCE(AVG(value),0), COALESCE(MAX(value),0), COALESCE(MIN(value),0)
FROM key_analytics_metrics
WHERE tenant_id=$1
  AND ($2='' OR key_id=$2)
  AND timestamp >= $3
GROUP BY metric_type
ORDER BY metric_type ASC
`, tenantID, strings.TrimSpace(keyID), since)
	if err != nil {
		return KeyUsageMetricSummary{}, err
	}
	defer rows.Close() //nolint:errcheck

	out := KeyUsageMetricSummary{TenantID: tenantID, KeyID: keyID, Since: since, GeneratedAt: time.Now().UTC()}
	for rows.Next() {
		var agg MetricAggregate
		if err := rows.Scan(&agg.Type, &agg.Count, &agg.Average, &agg.Maximum, &agg.Minimum); err != nil {
			return KeyUsageMetricSummary{}, err
		}
		out.Metrics = append(out.Metrics, agg)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListKeyHotspots(ctx context.Context, tenantID string, since time.Time, limit int) ([]KeyHotspot, error) {
	if since.IsZero() {
		since = time.Now().UTC().AddDate(0, 0, -7)
	}
	limit = clampAuditLimit(limit, 20)
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT key_id, COUNT(*) AS access_count, MAX(timestamp) AS last_access
FROM key_analytics_metrics
WHERE tenant_id=$1
  AND timestamp >= $2
  AND (metric_type LIKE 'usage_%' OR metric_type LIKE 'access_%')
GROUP BY key_id
ORDER BY access_count DESC
LIMIT $3
`, tenantID, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []KeyHotspot
	var maxCount int64
	for rows.Next() {
		var h KeyHotspot
		var last sql.NullTime
		if err := rows.Scan(&h.KeyID, &h.AccessCount, &last); err != nil {
			return nil, err
		}
		if last.Valid {
			t := last.Time.UTC()
			h.LastAccess = &t
		}
		if h.AccessCount > maxCount {
			maxCount = h.AccessCount
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if maxCount > 0 {
			out[i].Percentile = float64(out[i].AccessCount) / float64(maxCount) * 100
		}
	}
	return out, nil
}

func (s *SQLStore) GetKeyTrend(ctx context.Context, tenantID, metricType string, since time.Time) ([]TrendPoint, error) {
	if since.IsZero() {
		since = time.Now().UTC().AddDate(0, 0, -30)
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT timestamp, value
FROM key_analytics_metrics
WHERE tenant_id=$1
  AND metric_type=$2
  AND timestamp >= $3
ORDER BY timestamp ASC
`, tenantID, metricType, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	type bucket struct {
		sum   float64
		count int
	}
	buckets := map[string]bucket{}
	for rows.Next() {
		var ts time.Time
		var value float64
		if err := rows.Scan(&ts, &value); err != nil {
			return nil, err
		}
		key := ts.UTC().Format("2006-01-02")
		b := buckets[key]
		b.sum += value
		b.count++
		buckets[key] = b
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	points := make([]TrendPoint, 0, len(keys))
	var previous float64
	for _, key := range keys {
		day, _ := time.Parse("2006-01-02", key)
		avg := buckets[key].sum / float64(buckets[key].count)
		points = append(points, TrendPoint{Timestamp: day.UTC(), Value: avg, Change: avg - previous})
		previous = avg
	}
	return points, nil
}

func (s *SQLStore) GetAlgorithmBenchmarks(ctx context.Context, tenantID string, since time.Time) ([]AlgorithmBenchmark, error) {
	if since.IsZero() {
		since = time.Now().UTC().AddDate(0, 0, -7)
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT k.algorithm, m.metric_type, COUNT(*), COALESCE(AVG(m.value),0)
FROM key_analytics_metrics m
JOIN keys k ON k.tenant_id=m.tenant_id AND k.id=m.key_id
WHERE m.tenant_id=$1
  AND m.timestamp >= $2
  AND m.metric_type LIKE 'latency_%'
GROUP BY k.algorithm, m.metric_type
ORDER BY k.algorithm ASC, m.metric_type ASC
`, tenantID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []AlgorithmBenchmark
	for rows.Next() {
		var b AlgorithmBenchmark
		var metricType string
		if err := rows.Scan(&b.Algorithm, &metricType, &b.Count, &b.AverageLatency); err != nil {
			return nil, err
		}
		b.Operation = strings.TrimPrefix(metricType, "latency_")
		b.SuccessRate = 100
		b.FailureRate = 0
		b.PerformanceBand = latencyBand(b.AverageLatency)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertKeyHealthScore(ctx context.Context, score KeyHealthScore) error {
	if score.UpdatedAt.IsZero() {
		score.UpdatedAt = time.Now().UTC()
	}
	warnings, _ := json.Marshal(nonNilStrings(score.ComplianceWarnings))
	recommendations, _ := json.Marshal(nonNilStrings(score.RecommendedActions))
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_health_scores (
    key_id, tenant_id, health_score, entropy_score, age_score, usage_score,
    algorithm_score, backup_status, rotation_overdue, expiry_imminent,
    compliance_warnings, recommended_actions, last_audit_date, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
ON CONFLICT (tenant_id, key_id) DO UPDATE SET
    health_score=EXCLUDED.health_score,
    entropy_score=EXCLUDED.entropy_score,
    age_score=EXCLUDED.age_score,
    usage_score=EXCLUDED.usage_score,
    algorithm_score=EXCLUDED.algorithm_score,
    backup_status=EXCLUDED.backup_status,
    rotation_overdue=EXCLUDED.rotation_overdue,
    expiry_imminent=EXCLUDED.expiry_imminent,
    compliance_warnings=EXCLUDED.compliance_warnings,
    recommended_actions=EXCLUDED.recommended_actions,
    last_audit_date=EXCLUDED.last_audit_date,
    updated_at=EXCLUDED.updated_at
`, score.KeyID, score.TenantID, score.HealthScore, score.EntropyScore, score.AgeScore,
		score.UsageScore, score.AlgorithmScore, score.BackupStatus, score.RotationOverdue,
		score.ExpiryImminent, warnings, recommendations, nullableTime(score.LastAuditDate), score.UpdatedAt)
	return err
}

func (s *SQLStore) GetKeyHealthScore(ctx context.Context, tenantID, keyID string) (KeyHealthScore, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT key_id, tenant_id, health_score, entropy_score, age_score, usage_score,
       algorithm_score, backup_status, rotation_overdue, expiry_imminent,
       COALESCE(compliance_warnings,'[]'), COALESCE(recommended_actions,'[]'),
       last_audit_date, updated_at
FROM key_health_scores
WHERE tenant_id=$1 AND key_id=$2
`, tenantID, keyID)
	score, err := scanKeyHealthScore(row)
	if errors.Is(err, sql.ErrNoRows) {
		return KeyHealthScore{}, errStoreNotFound
	}
	return score, err
}

func (s *SQLStore) ListKeyHealthScores(ctx context.Context, tenantID string, limit int) ([]KeyHealthScore, error) {
	limit = clampAuditLimit(limit, 200)
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT key_id, tenant_id, health_score, entropy_score, age_score, usage_score,
       algorithm_score, backup_status, rotation_overdue, expiry_imminent,
       COALESCE(compliance_warnings,'[]'), COALESCE(recommended_actions,'[]'),
       last_audit_date, updated_at
FROM key_health_scores
WHERE tenant_id=$1
ORDER BY health_score ASC, updated_at DESC
LIMIT $2
`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []KeyHealthScore
	for rows.Next() {
		score, err := scanKeyHealthScore(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, score)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetKeyHealthSummary(ctx context.Context, tenantID string) (KeyHealthSummary, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*),
       COALESCE(AVG(health_score),0),
       COUNT(CASE WHEN health_score >= 80 THEN 1 END),
       COUNT(CASE WHEN health_score < 60 THEN 1 END),
       COUNT(CASE WHEN health_score < 40 THEN 1 END),
       COUNT(CASE WHEN rotation_overdue THEN 1 END),
       COUNT(CASE WHEN expiry_imminent THEN 1 END)
FROM key_health_scores
WHERE tenant_id=$1
`, tenantID)
	var summary KeyHealthSummary
	if err := row.Scan(&summary.TotalKeys, &summary.AverageHealth, &summary.HealthyKeys,
		&summary.AtRiskKeys, &summary.CriticalKeys, &summary.OverdueRotations, &summary.ExpiringSoon); err != nil {
		return KeyHealthSummary{}, err
	}
	summary.TenantID = tenantID
	if summary.TotalKeys > 0 {
		summary.HealthPercentage = float64(summary.HealthyKeys) / float64(summary.TotalKeys) * 100
	}
	summary.GeneratedAt = time.Now().UTC()
	return summary, nil
}

func (s *SQLStore) GetInventoryItem(ctx context.Context, tenantID, keyID string) (KeyInventoryItem, error) {
	row := s.db.SQL().QueryRowContext(ctx, inventorySelectSQL()+` WHERE tenant_id=$1 AND key_id=$2`, tenantID, keyID)
	item, err := scanInventoryItem(row)
	if errors.Is(err, sql.ErrNoRows) {
		return KeyInventoryItem{}, errStoreNotFound
	}
	return item, err
}

func (s *SQLStore) UpsertInventoryItem(ctx context.Context, item KeyInventoryItem) error {
	if item.CreatedDate.IsZero() {
		item.CreatedDate = time.Now().UTC()
	}
	if item.DiscoveryTimestamp == nil {
		t := time.Now().UTC()
		item.DiscoveryTimestamp = &t
	}
	tags, _ := json.Marshal(nonNilStrings(item.ComplianceTags))
	metadata, _ := json.Marshal(nonNilMap(item.Metadata))
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_inventory (
    key_id, tenant_id, key_name, key_type, algorithm, owner, status, created_date,
    last_used, last_rotated, rotation_frequency, next_rotation, expiry_date,
    backup_verified_at, hsm_stored, cloud_provider, region, compliance_tags,
    metadata_json, discovered_via, discovery_timestamp
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
ON CONFLICT (tenant_id, key_id) DO UPDATE SET
    key_name=EXCLUDED.key_name,
    key_type=EXCLUDED.key_type,
    algorithm=EXCLUDED.algorithm,
    owner=EXCLUDED.owner,
    status=EXCLUDED.status,
    created_date=EXCLUDED.created_date,
    last_used=EXCLUDED.last_used,
    last_rotated=EXCLUDED.last_rotated,
    rotation_frequency=EXCLUDED.rotation_frequency,
    next_rotation=EXCLUDED.next_rotation,
    expiry_date=EXCLUDED.expiry_date,
    hsm_stored=EXCLUDED.hsm_stored,
    cloud_provider=EXCLUDED.cloud_provider,
    region=EXCLUDED.region,
    compliance_tags=EXCLUDED.compliance_tags,
    metadata_json=EXCLUDED.metadata_json,
    discovered_via=EXCLUDED.discovered_via,
    discovery_timestamp=EXCLUDED.discovery_timestamp
`, item.KeyID, item.TenantID, item.KeyName, item.KeyType, item.Algorithm, item.Owner, item.Status,
		item.CreatedDate, nullableTime(item.LastUsed), nullableTime(item.LastRotated), nullable(item.RotationFrequency),
		nullableTime(item.NextRotation), nullableTime(item.ExpiryDate), nullableTime(item.BackupVerifiedAt),
		item.HSMStored, nullable(item.CloudProvider), nullable(item.Region), tags, metadata,
		nullable(item.DiscoveredVia), nullableTime(item.DiscoveryTimestamp))
	return err
}

func (s *SQLStore) ListInventoryItems(ctx context.Context, tenantID, status, owner string, limit, offset int) ([]KeyInventoryItem, error) {
	limit = clampAuditLimit(limit, 200)
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.SQL().QueryContext(ctx, inventorySelectSQL()+`
WHERE tenant_id=$1
  AND ($2='' OR status=$2)
  AND ($3='' OR owner=$3)
ORDER BY created_date DESC, key_id ASC
LIMIT $4 OFFSET $5
`, tenantID, strings.TrimSpace(status), strings.TrimSpace(owner), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	return scanInventoryRows(rows)
}

func (s *SQLStore) ListOrphanedInventoryItems(ctx context.Context, tenantID string, limit int) ([]KeyInventoryItem, error) {
	limit = clampAuditLimit(limit, 200)
	rows, err := s.db.SQL().QueryContext(ctx, inventorySelectSQL()+`
WHERE i.tenant_id=$1
  AND i.status IN ('active','pre-active','suspended')
  AND NOT EXISTS (
      SELECT 1 FROM key_dependencies d WHERE d.tenant_id=i.tenant_id AND d.key_id=i.key_id
  )
ORDER BY i.created_date DESC
LIMIT $2
`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	return scanInventoryRows(rows)
}

func (s *SQLStore) GetInventorySummary(ctx context.Context, tenantID string, duplicateSets int) (KeyInventorySummary, error) {
	expiringSoonCutoff := time.Now().UTC().AddDate(0, 0, 90)
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*),
       COUNT(CASE WHEN status='active' THEN 1 END),
       COUNT(CASE WHEN expiry_date IS NOT NULL AND expiry_date < CURRENT_TIMESTAMP THEN 1 END),
       COUNT(CASE WHEN expiry_date IS NOT NULL AND expiry_date BETWEEN CURRENT_TIMESTAMP AND $2 THEN 1 END),
       COUNT(CASE WHEN hsm_stored THEN 1 END),
       COUNT(CASE WHEN COALESCE(cloud_provider,'') <> '' THEN 1 END)
FROM key_inventory
WHERE tenant_id=$1
`, tenantID, expiringSoonCutoff)
	var summary KeyInventorySummary
	if err := row.Scan(&summary.TotalKeys, &summary.ActiveKeys, &summary.ExpiredKeys,
		&summary.ExpiringSoon, &summary.HSMStoredKeys, &summary.CloudKeys); err != nil {
		return KeyInventorySummary{}, err
	}
	var orphaned int
	if err := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*)
FROM key_inventory i
WHERE i.tenant_id=$1
  AND i.status IN ('active','pre-active','suspended')
  AND NOT EXISTS (
      SELECT 1 FROM key_dependencies d WHERE d.tenant_id=i.tenant_id AND d.key_id=i.key_id
  )
`, tenantID).Scan(&orphaned); err != nil {
		return KeyInventorySummary{}, err
	}
	summary.TenantID = tenantID
	summary.OrphanedKeys = orphaned
	summary.DuplicateSets = duplicateSets
	summary.GeneratedAt = time.Now().UTC()
	return summary, nil
}

func (s *SQLStore) UpsertKeyDependencyRecord(ctx context.Context, dep KeyDependencyRecord) error {
	if strings.TrimSpace(dep.DependencyID) == "" {
		dep.DependencyID = newID("dep")
	}
	if strings.TrimSpace(dep.Criticality) == "" {
		dep.Criticality = "medium"
	}
	if strings.TrimSpace(dep.VerificationStatus) == "" {
		dep.VerificationStatus = "unknown"
	}
	if strings.TrimSpace(dep.UsageFrequency) == "" {
		dep.UsageFrequency = "unknown"
	}
	if dep.DiscoveredAt.IsZero() {
		dep.DiscoveredAt = time.Now().UTC()
	}
	metadata, _ := json.Marshal(nonNilMap(dep.Metadata))
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO key_dependencies (
    dependency_id, tenant_id, key_id, service_id, app_id, dependency_type,
    criticality, last_verified, verification_status, usage_frequency,
    last_access_log_id, metadata_json, discovered_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT (tenant_id, dependency_id) DO UPDATE SET
    key_id=EXCLUDED.key_id,
    service_id=EXCLUDED.service_id,
    app_id=EXCLUDED.app_id,
    dependency_type=EXCLUDED.dependency_type,
    criticality=EXCLUDED.criticality,
    last_verified=EXCLUDED.last_verified,
    verification_status=EXCLUDED.verification_status,
    usage_frequency=EXCLUDED.usage_frequency,
    last_access_log_id=EXCLUDED.last_access_log_id,
    metadata_json=EXCLUDED.metadata_json
`, dep.DependencyID, dep.TenantID, dep.KeyID, dep.ServiceID, nullable(dep.AppID), dep.DependencyType,
		dep.Criticality, nullableTime(dep.LastVerified), dep.VerificationStatus, dep.UsageFrequency,
		nullable(dep.LastAccessLogID), metadata, dep.DiscoveredAt)
	return err
}

func (s *SQLStore) ListKeyDependencies(ctx context.Context, tenantID, keyID string, limit int) ([]KeyDependencyRecord, error) {
	limit = clampAuditLimit(limit, 200)
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT dependency_id, tenant_id, key_id, service_id, COALESCE(app_id,''), dependency_type,
       criticality, last_verified, COALESCE(verification_status,''), COALESCE(usage_frequency,''),
       COALESCE(last_access_log_id,''), COALESCE(metadata_json,'{}'), discovered_at
FROM key_dependencies
WHERE tenant_id=$1
  AND ($2='' OR key_id=$2)
ORDER BY
  CASE criticality WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
  discovered_at DESC
LIMIT $3
`, tenantID, strings.TrimSpace(keyID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	var out []KeyDependencyRecord
	for rows.Next() {
		dep, err := scanKeyDependencyRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, dep)
	}
	return out, rows.Err()
}

func (s *SQLStore) RecordCompromiseEvent(ctx context.Context, event CompromiseEvent) error {
	now := time.Now().UTC()
	if strings.TrimSpace(event.EventID) == "" {
		event.EventID = newID("cmp")
	}
	if strings.TrimSpace(event.ThreatType) == "" {
		event.ThreatType = "suspicious_activity"
	}
	if strings.TrimSpace(event.Severity) == "" {
		event.Severity = "high"
	}
	if event.DetectionDate.IsZero() {
		event.DetectionDate = now
	}
	if strings.TrimSpace(event.Status) == "" {
		event.Status = "pending"
	}
	if strings.TrimSpace(event.RemediationStatus) == "" {
		event.RemediationStatus = "not_started"
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = now
	}
	if event.UpdatedAt.IsZero() {
		event.UpdatedAt = now
	}
	affected, _ := json.Marshal(nonNilStrings(event.AffectedSystems))
	notifications, _ := json.Marshal(nonNilStrings(event.NotificationsSent))
	metadata, _ := json.Marshal(nonNilMap(event.Metadata))
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO compromise_events (
    event_id, tenant_id, key_id, cve_id, threat_type, severity, detection_date,
    confirmed_date, status, remediation_plan, remediation_status, remediation_date,
    affected_systems, notifications_sent, root_cause, detection_source,
    metadata_json, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
ON CONFLICT (tenant_id, event_id) DO UPDATE SET
    key_id=EXCLUDED.key_id,
    cve_id=EXCLUDED.cve_id,
    threat_type=EXCLUDED.threat_type,
    severity=EXCLUDED.severity,
    confirmed_date=EXCLUDED.confirmed_date,
    status=EXCLUDED.status,
    remediation_plan=EXCLUDED.remediation_plan,
    remediation_status=EXCLUDED.remediation_status,
    remediation_date=EXCLUDED.remediation_date,
    affected_systems=EXCLUDED.affected_systems,
    notifications_sent=EXCLUDED.notifications_sent,
    root_cause=EXCLUDED.root_cause,
    detection_source=EXCLUDED.detection_source,
    metadata_json=EXCLUDED.metadata_json,
    updated_at=EXCLUDED.updated_at
`, event.EventID, event.TenantID, event.KeyID, nullable(event.CVEID), event.ThreatType, event.Severity,
		event.DetectionDate, nullableTime(event.ConfirmedDate), event.Status, nullable(event.RemediationPlan),
		event.RemediationStatus, nullableTime(event.RemediationDate), affected, notifications,
		nullable(event.RootCause), nullable(event.DetectionSource), metadata, event.CreatedAt, event.UpdatedAt)
	return err
}

func (s *SQLStore) ListCompromiseEvents(ctx context.Context, tenantID, status, severity string, limit int) ([]CompromiseEvent, error) {
	limit = clampAuditLimit(limit, 200)
	rows, err := s.db.SQL().QueryContext(ctx, compromiseSelectSQL()+`
WHERE tenant_id=$1
  AND ($2='' OR status=$2)
  AND ($3='' OR severity=$3)
ORDER BY created_at DESC
LIMIT $4
`, tenantID, strings.TrimSpace(status), strings.TrimSpace(severity), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	return scanCompromiseRows(rows)
}

func (s *SQLStore) UpdateCompromiseEventStatus(ctx context.Context, tenantID, eventID, status, remediationStatus, rootCause string, notifications []string) (CompromiseEvent, error) {
	if strings.TrimSpace(status) == "" {
		return CompromiseEvent{}, errors.New("status is required")
	}
	notificationJSON, _ := json.Marshal(nonNilStrings(notifications))
	row := s.db.SQL().QueryRowContext(ctx, `
UPDATE compromise_events
SET status=$1,
    remediation_status=COALESCE(NULLIF($2,''), remediation_status),
    root_cause=COALESCE(NULLIF($3,''), root_cause),
    notifications_sent=CASE WHEN $4 IS NULL THEN notifications_sent ELSE $4 END,
    confirmed_date=CASE WHEN $1='confirmed' AND confirmed_date IS NULL THEN CURRENT_TIMESTAMP ELSE confirmed_date END,
    remediation_date=CASE WHEN $1 IN ('resolved','false_positive') OR $2='completed' THEN CURRENT_TIMESTAMP ELSE remediation_date END,
    updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$5 AND event_id=$6
RETURNING event_id, tenant_id, key_id, COALESCE(cve_id,''), threat_type, severity,
          detection_date, confirmed_date, status, COALESCE(remediation_plan,''),
          COALESCE(remediation_status,''), remediation_date,
          COALESCE(affected_systems,'[]'), COALESCE(notifications_sent,'[]'),
          COALESCE(root_cause,''), COALESCE(detection_source,''), COALESCE(metadata_json,'{}'),
          created_at, updated_at
`, status, remediationStatus, rootCause, nullableBytesForJSON(notificationJSON, len(notifications) == 0), tenantID, eventID)
	event, err := scanCompromiseEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CompromiseEvent{}, errStoreNotFound
	}
	return event, err
}

func (s *SQLStore) GetCompromiseSummary(ctx context.Context, tenantID string) (CompromiseSummary, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(CASE WHEN status NOT IN ('resolved','false_positive') THEN 1 END),
       COUNT(CASE WHEN severity='critical' THEN 1 END),
       COUNT(CASE WHEN severity='high' THEN 1 END),
       COUNT(CASE WHEN status='confirmed' THEN 1 END),
       COUNT(CASE WHEN status='pending' THEN 1 END),
       COUNT(CASE WHEN remediation_status='completed' OR status='resolved' THEN 1 END),
       COUNT(DISTINCT CASE WHEN CAST(COALESCE(metadata_json,'{}') AS TEXT) LIKE '%auto_suspended%true%' THEN key_id END)
FROM compromise_events
WHERE tenant_id=$1
`, tenantID)
	var summary CompromiseSummary
	if err := row.Scan(&summary.OpenEvents, &summary.CriticalEvents, &summary.HighEvents,
		&summary.ConfirmedEvents, &summary.PendingEvents, &summary.RemediatedEvents,
		&summary.AutoSuspendedKeys); err != nil {
		return CompromiseSummary{}, err
	}
	summary.TenantID = tenantID
	summary.GeneratedAt = time.Now().UTC()
	return summary, nil
}

func (s *SQLStore) countOverdueRotations(ctx context.Context, tenantID string) (int, error) {
	var count int
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*)
FROM key_rotation_metrics
WHERE tenant_id=$1
  AND status IN ('scheduled','in_progress')
  AND scheduled_date < CURRENT_TIMESTAMP
`, tenantID).Scan(&count)
	return count, err
}

func (s *SQLStore) recordCryptoOperationMetric(ctx context.Context, tenantID, keyID, op string, duration time.Duration) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(keyID) == "" || strings.TrimSpace(op) == "" {
		return
	}
	now := time.Now().UTC()
	usage := KeyAnalyticsMetric{
		MetricID:          newID("met"),
		TenantID:          tenantID,
		KeyID:             keyID,
		MetricType:        "usage_" + op,
		Value:             1,
		AggregationPeriod: "realtime",
		Timestamp:         now,
	}
	latency := KeyAnalyticsMetric{
		MetricID:          newID("met"),
		TenantID:          tenantID,
		KeyID:             keyID,
		MetricType:        "latency_" + op,
		Value:             float64(duration.Milliseconds()),
		AggregationPeriod: "realtime",
		Timestamp:         now,
	}
	_ = s.RecordKeyAnalyticsMetric(ctx, usage)
	_ = s.RecordKeyAnalyticsMetric(ctx, latency)
}

func scanRotationMetric(scanner interface {
	Scan(dest ...interface{}) error
}) (RotationMetric, error) {
	var (
		item      RotationMetric
		actual    sql.NullTime
		metadata  string
		createdAt time.Time
		updatedAt time.Time
	)
	if err := scanner.Scan(&item.RotationID, &item.TenantID, &item.KeyID, &item.ScheduledDate, &actual,
		&item.Status, &item.DurationMs, &item.Reason, &item.InitiatedBy, &item.CompletedBy,
		&item.ErrorDetails, &item.OldVersion, &item.NewVersion, &item.RollbackAttempt,
		&metadata, &createdAt, &updatedAt); err != nil {
		return RotationMetric{}, err
	}
	if actual.Valid {
		t := actual.Time.UTC()
		item.ActualDate = &t
	}
	item.CreatedAt = createdAt.UTC()
	item.UpdatedAt = updatedAt.UTC()
	item.Metadata = parseMap(metadata)
	return item, nil
}

func scanKeyHealthScore(scanner interface {
	Scan(dest ...interface{}) error
}) (KeyHealthScore, error) {
	var (
		score           KeyHealthScore
		warnings        string
		recommendations string
		lastAudit       sql.NullTime
	)
	if err := scanner.Scan(&score.KeyID, &score.TenantID, &score.HealthScore, &score.EntropyScore,
		&score.AgeScore, &score.UsageScore, &score.AlgorithmScore, &score.BackupStatus,
		&score.RotationOverdue, &score.ExpiryImminent, &warnings, &recommendations,
		&lastAudit, &score.UpdatedAt); err != nil {
		return KeyHealthScore{}, err
	}
	if lastAudit.Valid {
		t := lastAudit.Time.UTC()
		score.LastAuditDate = &t
	}
	score.ComplianceWarnings = parseStrings(warnings)
	score.RecommendedActions = parseStrings(recommendations)
	score.UpdatedAt = score.UpdatedAt.UTC()
	return score, nil
}

func inventorySelectSQL() string {
	return `
SELECT key_id, tenant_id, key_name, key_type, algorithm, owner, status, created_date,
       last_used, last_rotated, COALESCE(rotation_frequency,''), next_rotation, expiry_date,
       backup_verified_at, hsm_stored, COALESCE(cloud_provider,''), COALESCE(region,''),
       COALESCE(compliance_tags,'[]'), COALESCE(metadata_json,'{}'),
       COALESCE(discovered_via,''), discovery_timestamp
FROM key_inventory i`
}

func scanInventoryRows(rows *sql.Rows) ([]KeyInventoryItem, error) {
	var out []KeyInventoryItem
	for rows.Next() {
		item, err := scanInventoryItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func scanInventoryItem(scanner interface {
	Scan(dest ...interface{}) error
}) (KeyInventoryItem, error) {
	var (
		item               KeyInventoryItem
		lastUsed           sql.NullTime
		lastRotated        sql.NullTime
		nextRotation       sql.NullTime
		expiryDate         sql.NullTime
		backupVerified     sql.NullTime
		discoveryTimestamp sql.NullTime
		complianceTags     string
		metadata           string
	)
	if err := scanner.Scan(&item.KeyID, &item.TenantID, &item.KeyName, &item.KeyType, &item.Algorithm,
		&item.Owner, &item.Status, &item.CreatedDate, &lastUsed, &lastRotated, &item.RotationFrequency,
		&nextRotation, &expiryDate, &backupVerified, &item.HSMStored, &item.CloudProvider, &item.Region,
		&complianceTags, &metadata, &item.DiscoveredVia, &discoveryTimestamp); err != nil {
		return KeyInventoryItem{}, err
	}
	item.CreatedDate = item.CreatedDate.UTC()
	item.LastUsed = nullTimePtr(lastUsed)
	item.LastRotated = nullTimePtr(lastRotated)
	item.NextRotation = nullTimePtr(nextRotation)
	item.ExpiryDate = nullTimePtr(expiryDate)
	item.BackupVerifiedAt = nullTimePtr(backupVerified)
	item.DiscoveryTimestamp = nullTimePtr(discoveryTimestamp)
	item.ComplianceTags = parseStrings(complianceTags)
	item.Metadata = parseMap(metadata)
	return item, nil
}

func scanKeyDependencyRecord(scanner interface {
	Scan(dest ...interface{}) error
}) (KeyDependencyRecord, error) {
	var (
		dep          KeyDependencyRecord
		lastVerified sql.NullTime
		metadata     string
	)
	if err := scanner.Scan(&dep.DependencyID, &dep.TenantID, &dep.KeyID, &dep.ServiceID, &dep.AppID,
		&dep.DependencyType, &dep.Criticality, &lastVerified, &dep.VerificationStatus,
		&dep.UsageFrequency, &dep.LastAccessLogID, &metadata, &dep.DiscoveredAt); err != nil {
		return KeyDependencyRecord{}, err
	}
	dep.LastVerified = nullTimePtr(lastVerified)
	dep.Metadata = parseMap(metadata)
	dep.DiscoveredAt = dep.DiscoveredAt.UTC()
	return dep, nil
}

func compromiseSelectSQL() string {
	return `
SELECT event_id, tenant_id, key_id, COALESCE(cve_id,''), threat_type, severity,
       detection_date, confirmed_date, status, COALESCE(remediation_plan,''),
       COALESCE(remediation_status,''), remediation_date,
       COALESCE(affected_systems,'[]'), COALESCE(notifications_sent,'[]'),
       COALESCE(root_cause,''), COALESCE(detection_source,''), COALESCE(metadata_json,'{}'),
       created_at, updated_at
FROM compromise_events`
}

func scanCompromiseRows(rows *sql.Rows) ([]CompromiseEvent, error) {
	var out []CompromiseEvent
	for rows.Next() {
		event, err := scanCompromiseEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

func scanCompromiseEvent(scanner interface {
	Scan(dest ...interface{}) error
}) (CompromiseEvent, error) {
	var (
		event         CompromiseEvent
		confirmed     sql.NullTime
		remediated    sql.NullTime
		affected      string
		notifications string
		metadata      string
	)
	if err := scanner.Scan(&event.EventID, &event.TenantID, &event.KeyID, &event.CVEID,
		&event.ThreatType, &event.Severity, &event.DetectionDate, &confirmed, &event.Status,
		&event.RemediationPlan, &event.RemediationStatus, &remediated, &affected, &notifications,
		&event.RootCause, &event.DetectionSource, &metadata, &event.CreatedAt, &event.UpdatedAt); err != nil {
		return CompromiseEvent{}, err
	}
	event.ConfirmedDate = nullTimePtr(confirmed)
	event.RemediationDate = nullTimePtr(remediated)
	event.AffectedSystems = parseStrings(affected)
	event.NotificationsSent = parseStrings(notifications)
	event.Metadata = parseMap(metadata)
	event.DetectionDate = event.DetectionDate.UTC()
	event.CreatedAt = event.CreatedAt.UTC()
	event.UpdatedAt = event.UpdatedAt.UTC()
	return event, nil
}

func clampAuditLimit(limit, defaultLimit int) int {
	if defaultLimit <= 0 {
		defaultLimit = 100
	}
	if limit <= 0 {
		return defaultLimit
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func latencyBand(avgMs float64) string {
	switch {
	case avgMs <= 25:
		return "excellent"
	case avgMs <= 100:
		return "good"
	case avgMs <= 250:
		return "fair"
	default:
		return "poor"
	}
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func nonNilMap(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	return in
}

func nullableBytesForJSON(in []byte, empty bool) any {
	if empty {
		return nil
	}
	return in
}

func nullTimePtr(in sql.NullTime) *time.Time {
	if !in.Valid {
		return nil
	}
	t := in.Time.UTC()
	return &t
}

func parseStrings(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err == nil {
		return out
	}
	return nil
}

func parseMap(raw string) map[string]any {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err == nil && out != nil {
		return out
	}
	return map[string]any{"raw": raw}
}
