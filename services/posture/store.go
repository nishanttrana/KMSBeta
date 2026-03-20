package main

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

type Store interface {
	IngestEvents(ctx context.Context, events []NormalizedEvent) (int, error)
	ListTenants(ctx context.Context) ([]string, error)
	GetSignalSummary(ctx context.Context, tenantID string, from time.Time, to time.Time) (SignalSummary, error)

	UpsertFindingByFingerprint(ctx context.Context, tenantID string, candidate FindingCandidate, detectedAt time.Time) (Finding, error)
	ListFindings(ctx context.Context, tenantID string, q FindingQuery) ([]Finding, error)
	UpdateFindingStatus(ctx context.Context, tenantID string, id string, status string) error
	ListOverdueFindings(ctx context.Context, tenantID string, now time.Time, limit int) ([]Finding, error)
	ListOpenFindings(ctx context.Context, tenantID string, limit int) ([]Finding, error)
	GetFindingByFingerprint(ctx context.Context, tenantID string, fp string) (Finding, error)

	CreateActionIfAbsent(ctx context.Context, tenantID string, findingID string, candidate ActionCandidate) (RemediationAction, error)
	ListActions(ctx context.Context, tenantID string, q ActionQuery) ([]RemediationAction, error)
	UpdateActionExecution(ctx context.Context, tenantID string, id string, status string, executedBy string, resultMessage string, approvalRequestID string) error
	GetAction(ctx context.Context, tenantID string, id string) (RemediationAction, error)

	CreateRiskSnapshot(ctx context.Context, snap RiskSnapshot) error
	GetLatestRiskSnapshot(ctx context.Context, tenantID string) (RiskSnapshot, error)
	ListRiskSnapshots(ctx context.Context, tenantID string, q RiskQuery) ([]RiskSnapshot, error)

	PurgeHotEventsBefore(ctx context.Context, before time.Time, limit int) (int64, error)
	UpdateEngineState(ctx context.Context, tenantID string, lastAuditSyncAt time.Time, lastAuditEventTS time.Time, lastRunAt time.Time) error
	GetEngineState(ctx context.Context, tenantID string) (time.Time, time.Time, time.Time, error)
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) IngestEvents(ctx context.Context, events []NormalizedEvent) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	inserted := 0
	for _, item := range events {
		if strings.TrimSpace(item.TenantID) == "" || strings.TrimSpace(item.Service) == "" || strings.TrimSpace(item.Action) == "" {
			continue
		}
		if strings.TrimSpace(item.ID) == "" {
			item.ID = newID("pev")
		}
		if item.Timestamp.IsZero() {
			item.Timestamp = nowUTC()
		}
		if item.CreatedAt.IsZero() {
			item.CreatedAt = nowUTC()
		}
		item.Result = strings.ToLower(defaultString(item.Result, "success"))
		item.Severity = normalizeSeverity(firstNonEmpty(item.Severity, statusToSeverity(item.Result)))
		if item.Details == nil {
			item.Details = map[string]interface{}{}
		}
		query := `
INSERT INTO posture_events_hot (
	tenant_id, id, event_ts, service, action, result, severity, actor, ip, request_id, resource_id,
	error_code, latency_ms, node_id, details_json, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
) ON CONFLICT (tenant_id, id) DO NOTHING`
		res, err := tx.ExecContext(ctx, query,
			item.TenantID, item.ID, item.Timestamp, item.Service, item.Action, item.Result, item.Severity, item.Actor, item.IP, item.RequestID, item.ResourceID,
			item.ErrorCode, item.LatencyMS, item.NodeID, mustJSON(item.Details, "{}"), item.CreatedAt,
		)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			inserted++
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO posture_events_history (
	tenant_id, id, event_ts, service, action, result, severity, actor, ip, request_id, resource_id,
	error_code, latency_ms, node_id, details_json, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16
) ON CONFLICT (tenant_id, id) DO NOTHING`,
			item.TenantID, item.ID, item.Timestamp, item.Service, item.Action, item.Result, item.Severity, item.Actor, item.IP, item.RequestID, item.ResourceID,
			item.ErrorCode, item.LatencyMS, item.NodeID, mustJSON(item.Details, "{}"), item.CreatedAt,
		)
		if err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return inserted, nil
}

func (s *SQLStore) ListTenants(ctx context.Context) ([]string, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id FROM (
	SELECT DISTINCT tenant_id FROM posture_events_history
	UNION
	SELECT DISTINCT tenant_id FROM posture_findings
	UNION
	SELECT DISTINCT tenant_id FROM posture_actions
) t
ORDER BY tenant_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck

	out := make([]string, 0)
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			return nil, err
		}
		if strings.TrimSpace(tenantID) == "" {
			continue
		}
		out = append(out, tenantID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return []string{"root"}, nil
	}
	return out, nil
}

func (s *SQLStore) GetSignalSummary(ctx context.Context, tenantID string, from time.Time, to time.Time) (SignalSummary, error) {
	if strings.TrimSpace(tenantID) == "" {
		return SignalSummary{}, newServiceError(400, "tenant_required", "tenant_id is required")
	}
	if from.IsZero() {
		from = nowUTC().Add(-24 * time.Hour)
	}
	if to.IsZero() {
		to = nowUTC()
	}
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT
	COUNT(*) AS total_events,
	COALESCE(SUM(CASE
		WHEN (service = 'auth' AND result IN ('failure','failed','denied','error'))
		  OR action LIKE 'auth.login_failed%'
		THEN 1 ELSE 0 END), 0) AS failed_auth_count,
	COALESCE(SUM(CASE
		WHEN (action LIKE '%unwrap%' OR action LIKE '%decrypt%')
		 AND result IN ('failure','failed','denied','error')
		THEN 1 ELSE 0 END), 0) AS failed_crypto_count,
	COALESCE(SUM(CASE
		WHEN action LIKE 'policy.%deny%' OR result = 'denied'
		THEN 1 ELSE 0 END), 0) AS policy_deny_count,
	COALESCE(SUM(CASE
		WHEN action LIKE 'key.delete%' OR action LIKE 'key.destroy%'
		THEN 1 ELSE 0 END), 0) AS key_delete_count,
	COALESCE(SUM(CASE
		WHEN action LIKE 'cert.delete%' OR action LIKE 'cert.destroy%'
		THEN 1 ELSE 0 END), 0) AS cert_delete_count,
	COALESCE(SUM(CASE
		WHEN action LIKE 'governance.quorum_bypass%' OR action LIKE 'governance.vote.denied%'
		THEN 1 ELSE 0 END), 0) AS quorum_bypass_count,
	COALESCE(SUM(CASE
		WHEN action LIKE '%tenant_mismatch%' OR error_code = 'tenant_mismatch'
		THEN 1 ELSE 0 END), 0) AS tenant_mismatch_count,
	COALESCE(SUM(CASE
		WHEN action LIKE 'cluster.drift%' OR error_code = 'cluster_state_drift'
		THEN 1 ELSE 0 END), 0) AS cluster_drift_count,
	COALESCE(SUM(CASE
		WHEN service IN ('cloud','hyok','ekm','kmip')
		 AND action LIKE '%auth%'
		 AND result IN ('failure','failed','denied','error')
		THEN 1 ELSE 0 END), 0) AS connector_auth_flaps,
	COALESCE(SUM(CASE
		WHEN action LIKE 'cluster.replication_retry%' OR action LIKE 'cluster.sync.retry%'
		THEN 1 ELSE 0 END), 0) AS replication_retry,
	COALESCE(SUM(CASE
		WHEN action LIKE 'cert.expiry%' OR action LIKE 'key.expiry%' OR action LIKE '%expiry_warning%'
		THEN 1 ELSE 0 END), 0) AS expiry_backlog_count,
	COALESCE(SUM(CASE
		WHEN action LIKE 'audit.cert.renewal_window_missed%' OR action LIKE 'cert.renewal_window_missed%'
		THEN 1 ELSE 0 END), 0) AS cert_renewal_missed_count,
	COALESCE(SUM(CASE
		WHEN action LIKE 'audit.cert.emergency_rotation_started%' OR action LIKE 'cert.emergency_rotation_started%'
		THEN 1 ELSE 0 END), 0) AS cert_emergency_rotations,
	COALESCE(SUM(CASE
		WHEN action LIKE 'audit.cert.mass_renewal_risk_detected%' OR action LIKE 'cert.mass_renewal_risk_detected%'
		THEN 1 ELSE 0 END), 0) AS cert_mass_renewal_risks,
	COALESCE(SUM(CASE
		WHEN action LIKE 'fips.non_approved%' OR error_code = 'fips_non_approved_algorithm'
		THEN 1 ELSE 0 END), 0) AS non_approved_algo_count,
	COALESCE(AVG(CASE
		WHEN service = 'hsm' OR action LIKE 'hsm.%'
		THEN latency_ms
		ELSE NULL END), 0) AS hsm_latency_avg_ms,
	COALESCE(AVG(CASE
		WHEN service = 'cluster-manager' OR action LIKE 'cluster.%'
		THEN latency_ms
		ELSE NULL END), 0) AS cluster_lag_avg_ms,
	COALESCE(SUM(CASE
		WHEN service IN ('cloud', 'byok', 'kms-cloud')
		  OR action LIKE 'audit.cloud.%'
		  OR action LIKE 'cloud.%'
		  OR action LIKE 'byok.%'
		THEN 1 ELSE 0 END), 0) AS byok_events,
	COALESCE(SUM(CASE
		WHEN (
			service IN ('cloud', 'byok', 'kms-cloud')
			OR action LIKE 'audit.cloud.%'
			OR action LIKE 'cloud.%'
			OR action LIKE 'byok.%'
		)
		AND (
			result IN ('failure','failed','denied','error')
			OR action LIKE '%sync_failed%'
			OR action LIKE '%auth_failed%'
			OR action LIKE '%connector_failed%'
			OR action LIKE '%request_denied%'
		)
		THEN 1 ELSE 0 END), 0) AS byok_failures,
	COALESCE(AVG(CASE
		WHEN service IN ('cloud', 'byok', 'kms-cloud')
		  OR action LIKE 'audit.cloud.%'
		  OR action LIKE 'cloud.%'
		  OR action LIKE 'byok.%'
		THEN latency_ms
		ELSE NULL END), 0) AS byok_latency_avg_ms,
	COALESCE(SUM(CASE
		WHEN service IN ('hyok', 'kms-hyok-proxy')
		  OR action LIKE 'audit.hyok.%'
		  OR action LIKE 'hyok.%'
		THEN 1 ELSE 0 END), 0) AS hyok_events,
	COALESCE(SUM(CASE
		WHEN (
			service IN ('hyok', 'kms-hyok-proxy')
			OR action LIKE 'audit.hyok.%'
			OR action LIKE 'hyok.%'
		)
		AND (
			result IN ('failure','failed','denied','error')
			OR action LIKE '%request_denied%'
			OR action LIKE '%failed%'
		)
		THEN 1 ELSE 0 END), 0) AS hyok_failures,
	COALESCE(AVG(CASE
		WHEN service IN ('hyok', 'kms-hyok-proxy')
		  OR action LIKE 'audit.hyok.%'
		  OR action LIKE 'hyok.%'
		THEN latency_ms
		ELSE NULL END), 0) AS hyok_latency_avg_ms,
	COALESCE(SUM(CASE
		WHEN service IN ('ekm', 'kms-ekm')
		  OR action LIKE 'audit.ekm.%'
		  OR action LIKE 'ekm.%'
		THEN 1 ELSE 0 END), 0) AS ekm_events,
	COALESCE(SUM(CASE
		WHEN (
			service IN ('ekm', 'kms-ekm')
			OR action LIKE 'audit.ekm.%'
			OR action LIKE 'ekm.%'
		)
		AND (
			result IN ('failure','failed','denied','error')
			OR action LIKE '%agent_disconnected%'
			OR action LIKE '%_failed%'
		)
		THEN 1 ELSE 0 END), 0) AS ekm_failures,
	COALESCE(AVG(CASE
		WHEN service IN ('ekm', 'kms-ekm')
		  OR action LIKE 'audit.ekm.%'
		  OR action LIKE 'ekm.%'
		THEN latency_ms
		ELSE NULL END), 0) AS ekm_latency_avg_ms,
	COALESCE(SUM(CASE
		WHEN service IN ('kmip', 'kms-kmip')
		  OR action LIKE 'audit.kmip.%'
		  OR action LIKE 'kmip.%'
		THEN 1 ELSE 0 END), 0) AS kmip_events,
	COALESCE(SUM(CASE
		WHEN (
			service IN ('kmip', 'kms-kmip')
			OR action LIKE 'audit.kmip.%'
			OR action LIKE 'kmip.%'
		)
		AND (
			result IN ('failure','failed','denied','error')
			OR action LIKE '%interop_validation_failed%'
			OR action LIKE '%request_denied%'
			OR action LIKE '%_failed%'
		)
		THEN 1 ELSE 0 END), 0) AS kmip_failures,
	COALESCE(SUM(CASE
		WHEN action LIKE '%interop_validation_failed%' OR error_code = 'kmip_interop_failed'
		THEN 1 ELSE 0 END), 0) AS kmip_interop_failures,
	COALESCE(AVG(CASE
		WHEN service IN ('kmip', 'kms-kmip')
		  OR action LIKE 'audit.kmip.%'
		  OR action LIKE 'kmip.%'
		THEN latency_ms
		ELSE NULL END), 0) AS kmip_latency_avg_ms,
	COALESCE(SUM(CASE
		WHEN action LIKE 'audit.ekm.bitlocker_%'
		  OR action LIKE 'ekm.bitlocker_%'
		  OR action LIKE '%bitlocker_%'
		THEN 1 ELSE 0 END), 0) AS bitlocker_events,
	COALESCE(SUM(CASE
		WHEN (
			action LIKE 'audit.ekm.bitlocker_%'
			OR action LIKE 'ekm.bitlocker_%'
			OR action LIKE '%bitlocker_%'
		)
		AND (
			result IN ('failure','failed','denied','error')
			OR action LIKE '%_disconnected%'
			OR action LIKE '%_failed%'
		)
		THEN 1 ELSE 0 END), 0) AS bitlocker_failures,
	COALESCE(AVG(CASE
		WHEN action LIKE 'audit.ekm.bitlocker_%'
		  OR action LIKE 'ekm.bitlocker_%'
		  OR action LIKE '%bitlocker_%'
		THEN latency_ms
		ELSE NULL END), 0) AS bitlocker_latency_avg_ms,
	COALESCE(SUM(CASE
		WHEN service IN ('dataprotect', 'sdk', 'wrapper')
		  OR action LIKE 'audit.dataprotect.field_encryption.%'
		  OR action LIKE 'audit.dataprotect.field_protection.%'
		  OR action LIKE 'audit.dataprotect.%sdk%'
		  OR action LIKE 'audit.dataprotect.%wrapper%'
		THEN 1 ELSE 0 END), 0) AS sdk_events,
	COALESCE(SUM(CASE
		WHEN (
			service IN ('dataprotect', 'sdk', 'wrapper')
			OR action LIKE 'audit.dataprotect.field_encryption.%'
			OR action LIKE 'audit.dataprotect.field_protection.%'
			OR action LIKE 'audit.dataprotect.%sdk%'
			OR action LIKE 'audit.dataprotect.%wrapper%'
		)
		AND (
			result IN ('failure','failed','denied','error')
			OR action LIKE '%receipt_missing_detected%'
			OR action LIKE '%lease_revoked%'
			OR action LIKE '%request_denied%'
			OR action LIKE '%_failed%'
		)
		THEN 1 ELSE 0 END), 0) AS sdk_failures,
	COALESCE(SUM(CASE
		WHEN action LIKE '%receipt_missing_detected%'
		THEN 1 ELSE 0 END), 0) AS sdk_receipt_missing,
	COALESCE(AVG(CASE
		WHEN service IN ('dataprotect', 'sdk', 'wrapper')
		  OR action LIKE 'audit.dataprotect.field_encryption.%'
		  OR action LIKE 'audit.dataprotect.field_protection.%'
		  OR action LIKE 'audit.dataprotect.%sdk%'
		  OR action LIKE 'audit.dataprotect.%wrapper%'
		THEN latency_ms
		ELSE NULL END), 0) AS sdk_latency_avg_ms
FROM posture_events_history
WHERE tenant_id = $1
  AND event_ts >= $2
  AND event_ts <= $3
`, tenantID, from.UTC(), to.UTC())

	out := SignalSummary{}
	err := row.Scan(
		&out.TotalEvents,
		&out.FailedAuthCount,
		&out.FailedCryptoCount,
		&out.PolicyDenyCount,
		&out.KeyDeleteCount,
		&out.CertDeleteCount,
		&out.QuorumBypassCount,
		&out.TenantMismatchCount,
		&out.ClusterDriftCount,
		&out.ConnectorAuthFlaps,
		&out.ReplicationRetry,
		&out.ExpiryBacklogCount,
		&out.CertRenewalMissedCount,
		&out.CertEmergencyRotations,
		&out.CertMassRenewalRisks,
		&out.NonApprovedAlgoCount,
		&out.HSMLatencyAvgMS,
		&out.ClusterLagAvgMS,
		&out.BYOKEvents,
		&out.BYOKFailures,
		&out.BYOKLatencyAvgMS,
		&out.HYOKEvents,
		&out.HYOKFailures,
		&out.HYOKLatencyAvgMS,
		&out.EKMEvents,
		&out.EKMFailures,
		&out.EKMLatencyAvgMS,
		&out.KMIPEvents,
		&out.KMIPFailures,
		&out.KMIPInteropFailures,
		&out.KMIPLatencyAvgMS,
		&out.BitLockerEvents,
		&out.BitLockerFailures,
		&out.BitLockerLatencyAvgMS,
		&out.SDKEvents,
		&out.SDKFailures,
		&out.SDKReceiptMissing,
		&out.SDKLatencyAvgMS,
	)
	return out, err
}

func (s *SQLStore) UpsertFindingByFingerprint(ctx context.Context, tenantID string, candidate FindingCandidate, detectedAt time.Time) (Finding, error) {
	if strings.TrimSpace(tenantID) == "" {
		return Finding{}, newServiceError(400, "tenant_required", "tenant_id is required")
	}
	if strings.TrimSpace(candidate.Fingerprint) == "" {
		return Finding{}, newServiceError(400, "fingerprint_required", "finding fingerprint is required")
	}
	existing, err := s.GetFindingByFingerprint(ctx, tenantID, candidate.Fingerprint)
	if err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, errNotFound) {
		return Finding{}, err
	}
	sev := normalizeSeverity(candidate.Severity)
	risk := clampRisk(candidate.RiskScore)
	slaDue := slaForSeverity(sev, detectedAt)
	if detectedAt.IsZero() {
		detectedAt = nowUTC()
	}
	if existing.ID != "" {
		nextStatus := existing.Status
		reopenCount := existing.ReopenCount
		if strings.EqualFold(existing.Status, "resolved") {
			nextStatus = "reopened"
			reopenCount++
		}
		_, err := s.db.SQL().ExecContext(ctx, `
UPDATE posture_findings
SET engine = $1,
	finding_type = $2,
	title = $3,
	description = $4,
	severity = $5,
	risk_score = $6,
	recommended_action = $7,
	auto_action_allowed = $8,
	status = $9,
	evidence_json = $10,
	updated_at = CURRENT_TIMESTAMP,
	sla_due_at = $11,
	reopen_count = $12
WHERE tenant_id = $13 AND id = $14
`, candidate.Engine, candidate.FindingType, candidate.Title, candidate.Description, sev, risk, candidate.RecommendedAction, candidate.AutoActionAllowed, nextStatus, mustJSON(candidate.Evidence, "{}"), nullableTime(slaDue), reopenCount, tenantID, existing.ID)
		if err != nil {
			return Finding{}, err
		}
		return s.getFindingByID(ctx, tenantID, existing.ID)
	}

	id := newID("finding")
	_, err = s.db.SQL().ExecContext(ctx, `
INSERT INTO posture_findings (
	tenant_id, id, engine, finding_type, title, description, severity, risk_score,
	recommended_action, auto_action_allowed, status, fingerprint, evidence_json, detected_at, updated_at, sla_due_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'open',$11,$12,$13,$13,$14
)
`, tenantID, id, candidate.Engine, candidate.FindingType, candidate.Title, candidate.Description, sev, risk, candidate.RecommendedAction, candidate.AutoActionAllowed, candidate.Fingerprint, mustJSON(candidate.Evidence, "{}"), detectedAt.UTC(), nullableTime(slaDue))
	if err != nil {
		return Finding{}, err
	}
	return s.getFindingByID(ctx, tenantID, id)
}

func (s *SQLStore) GetFindingByFingerprint(ctx context.Context, tenantID string, fp string) (Finding, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, engine, finding_type, title, description, severity, risk_score, recommended_action,
	   auto_action_allowed, status, fingerprint, evidence_json, detected_at, updated_at, resolved_at, sla_due_at, reopen_count
FROM posture_findings
WHERE tenant_id = $1 AND fingerprint = $2
`, tenantID, fp)
	item, err := scanFinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Finding{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) getFindingByID(ctx context.Context, tenantID string, id string) (Finding, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, engine, finding_type, title, description, severity, risk_score, recommended_action,
	   auto_action_allowed, status, fingerprint, evidence_json, detected_at, updated_at, resolved_at, sla_due_at, reopen_count
FROM posture_findings
WHERE tenant_id = $1 AND id = $2
`, tenantID, id)
	item, err := scanFinding(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Finding{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListFindings(ctx context.Context, tenantID string, q FindingQuery) ([]Finding, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	sev := ""
	if strings.TrimSpace(q.Severity) != "" {
		sev = normalizeSeverity(q.Severity)
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, engine, finding_type, title, description, severity, risk_score, recommended_action,
	   auto_action_allowed, status, fingerprint, evidence_json, detected_at, updated_at, resolved_at, sla_due_at, reopen_count
FROM posture_findings
WHERE tenant_id = $1
  AND ($2 = '' OR engine = $2)
  AND ($3 = '' OR status = $3)
  AND ($4 = '' OR severity = $4)
  AND ($5 = '' OR finding_type = $5)
  AND detected_at >= COALESCE($6, detected_at)
  AND detected_at <= COALESCE($7, detected_at)
ORDER BY detected_at DESC
LIMIT $8 OFFSET $9
`, tenantID, strings.TrimSpace(q.Engine), strings.TrimSpace(q.Status), sev, strings.TrimSpace(q.FindingType), nullableTime(q.From), nullableTime(q.To), q.Limit, max(0, q.Offset))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]Finding, 0)
	for rows.Next() {
		item, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateFindingStatus(ctx context.Context, tenantID string, id string, status string) error {
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		return newServiceError(400, "status_required", "status is required")
	}
	switch status {
	case "open", "acknowledged", "resolved", "suppressed", "reopened":
	default:
		return newServiceError(400, "bad_status", "unsupported finding status")
	}
	var resolvedAt interface{}
	if status == "resolved" {
		resolvedAt = nowUTC()
	}
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE posture_findings
SET status = $1,
	updated_at = CURRENT_TIMESTAMP,
	resolved_at = COALESCE($2, resolved_at)
WHERE tenant_id = $3 AND id = $4
`, status, resolvedAt, tenantID, id)
	return err
}

func (s *SQLStore) ListOverdueFindings(ctx context.Context, tenantID string, now time.Time, limit int) ([]Finding, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, engine, finding_type, title, description, severity, risk_score, recommended_action,
	   auto_action_allowed, status, fingerprint, evidence_json, detected_at, updated_at, resolved_at, sla_due_at, reopen_count
FROM posture_findings
WHERE tenant_id = $1
  AND status IN ('open', 'acknowledged', 'reopened')
  AND sla_due_at IS NOT NULL
  AND sla_due_at < $2
ORDER BY sla_due_at ASC
LIMIT $3
`, tenantID, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]Finding, 0)
	for rows.Next() {
		item, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListOpenFindings(ctx context.Context, tenantID string, limit int) ([]Finding, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, engine, finding_type, title, description, severity, risk_score, recommended_action,
	   auto_action_allowed, status, fingerprint, evidence_json, detected_at, updated_at, resolved_at, sla_due_at, reopen_count
FROM posture_findings
WHERE tenant_id = $1
  AND status IN ('open','reopened','acknowledged')
ORDER BY risk_score DESC, detected_at DESC
LIMIT $2
`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]Finding, 0)
	for rows.Next() {
		item, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateActionIfAbsent(ctx context.Context, tenantID string, findingID string, candidate ActionCandidate) (RemediationAction, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, finding_id, action_type, recommended_action, safety_gate, approval_required, approval_request_id,
	   status, executed_by, executed_at, evidence_json, result_message, created_at, updated_at
FROM posture_actions
WHERE tenant_id = $1
  AND finding_id = $2
  AND action_type = $3
  AND status IN ('suggested','pending_approval','approved','executing')
ORDER BY created_at DESC
LIMIT 1
`, tenantID, findingID, candidate.ActionType)
	existing, err := scanAction(row)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return RemediationAction{}, err
	}
	id := newID("action")
	_, err = s.db.SQL().ExecContext(ctx, `
INSERT INTO posture_actions (
	tenant_id, id, finding_id, action_type, recommended_action, safety_gate, approval_required, status, evidence_json
) VALUES ($1,$2,$3,$4,$5,$6,$7,'suggested',$8)
`, tenantID, id, findingID, candidate.ActionType, candidate.RecommendedAction, defaultString(candidate.SafetyGate, "manual"), candidate.ApprovalRequired, mustJSON(candidate.Evidence, "{}"))
	if err != nil {
		return RemediationAction{}, err
	}
	return s.GetAction(ctx, tenantID, id)
}

func (s *SQLStore) ListActions(ctx context.Context, tenantID string, q ActionQuery) ([]RemediationAction, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, finding_id, action_type, recommended_action, safety_gate, approval_required, approval_request_id,
	   status, executed_by, executed_at, evidence_json, result_message, created_at, updated_at
FROM posture_actions
WHERE tenant_id = $1
  AND ($2 = '' OR status = $2)
  AND ($3 = '' OR action_type = $3)
ORDER BY created_at DESC
LIMIT $4 OFFSET $5
`, tenantID, strings.TrimSpace(q.Status), strings.TrimSpace(q.ActionType), q.Limit, max(0, q.Offset))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]RemediationAction, 0)
	for rows.Next() {
		item, err := scanAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateActionExecution(ctx context.Context, tenantID string, id string, status string, executedBy string, resultMessage string, approvalRequestID string) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE posture_actions
SET status = $1,
	executed_by = $2,
	executed_at = CASE WHEN $1 IN ('executed','failed') THEN CURRENT_TIMESTAMP ELSE executed_at END,
	approval_request_id = CASE WHEN $3 <> '' THEN $3 ELSE approval_request_id END,
	result_message = $4,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $5 AND id = $6
`, status, executedBy, approvalRequestID, resultMessage, tenantID, id)
	return err
}

func (s *SQLStore) GetAction(ctx context.Context, tenantID string, id string) (RemediationAction, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, finding_id, action_type, recommended_action, safety_gate, approval_required, approval_request_id,
	   status, executed_by, executed_at, evidence_json, result_message, created_at, updated_at
FROM posture_actions
WHERE tenant_id = $1 AND id = $2
`, tenantID, id)
	item, err := scanAction(row)
	if errors.Is(err, sql.ErrNoRows) {
		return RemediationAction{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) CreateRiskSnapshot(ctx context.Context, snap RiskSnapshot) error {
	if strings.TrimSpace(snap.ID) == "" {
		snap.ID = newID("risk")
	}
	if snap.CapturedAt.IsZero() {
		snap.CapturedAt = nowUTC()
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO posture_risk_snapshots (
	tenant_id, id, risk_24h, risk_7d, predictive_score, preventive_score, corrective_score, top_signals_json, captured_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
`, snap.TenantID, snap.ID, clampRisk(snap.Risk24h), clampRisk(snap.Risk7d), clampRisk(snap.PredictiveScore), clampRisk(snap.PreventiveScore), clampRisk(snap.CorrectiveScore), mustJSON(snap.TopSignals, "{}"), snap.CapturedAt.UTC())
	return err
}

func (s *SQLStore) GetLatestRiskSnapshot(ctx context.Context, tenantID string) (RiskSnapshot, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, risk_24h, risk_7d, predictive_score, preventive_score, corrective_score, top_signals_json, captured_at
FROM posture_risk_snapshots
WHERE tenant_id = $1
ORDER BY captured_at DESC
LIMIT 1
`, tenantID)
	item, err := scanRiskSnapshot(row)
	if errors.Is(err, sql.ErrNoRows) {
		return RiskSnapshot{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListRiskSnapshots(ctx context.Context, tenantID string, q RiskQuery) ([]RiskSnapshot, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, risk_24h, risk_7d, predictive_score, preventive_score, corrective_score, top_signals_json, captured_at
FROM posture_risk_snapshots
WHERE tenant_id = $1
ORDER BY captured_at DESC
LIMIT $2 OFFSET $3
`, tenantID, q.Limit, max(0, q.Offset))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]RiskSnapshot, 0)
	for rows.Next() {
		item, err := scanRiskSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) PurgeHotEventsBefore(ctx context.Context, before time.Time, limit int) (int64, error) {
	if limit <= 0 || limit > 100000 {
		limit = 10000
	}
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM posture_events_hot
WHERE id IN (
	SELECT id
	FROM posture_events_hot
	WHERE event_ts < $1
	LIMIT $2
)
`, before.UTC(), limit)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (s *SQLStore) UpdateEngineState(ctx context.Context, tenantID string, lastAuditSyncAt time.Time, lastAuditEventTS time.Time, lastRunAt time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO posture_engine_state (tenant_id, last_audit_sync_at, last_audit_event_ts, last_run_at)
VALUES ($1,$2,$3,$4)
ON CONFLICT (tenant_id) DO UPDATE
SET last_audit_sync_at = COALESCE(EXCLUDED.last_audit_sync_at, posture_engine_state.last_audit_sync_at),
	last_audit_event_ts = COALESCE(EXCLUDED.last_audit_event_ts, posture_engine_state.last_audit_event_ts),
	last_run_at = COALESCE(EXCLUDED.last_run_at, posture_engine_state.last_run_at)
`, tenantID, nullableTime(lastAuditSyncAt), nullableTime(lastAuditEventTS), nullableTime(lastRunAt))
	return err
}

func (s *SQLStore) GetEngineState(ctx context.Context, tenantID string) (time.Time, time.Time, time.Time, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT last_audit_sync_at, last_audit_event_ts, last_run_at
FROM posture_engine_state
WHERE tenant_id = $1
`, tenantID)
	var lastAuditSync sql.NullTime
	var lastAuditEvent sql.NullTime
	var lastRun sql.NullTime
	if err := row.Scan(&lastAuditSync, &lastAuditEvent, &lastRun); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, time.Time{}, time.Time{}, nil
		}
		return time.Time{}, time.Time{}, time.Time{}, err
	}
	return toTime(lastAuditSync), toTime(lastAuditEvent), toTime(lastRun), nil
}

type scanner interface {
	Scan(dest ...interface{}) error
}

var errNotFound = errors.New("not found")

func scanFinding(row scanner) (Finding, error) {
	var out Finding
	var evidenceRaw string
	var resolvedAt sql.NullTime
	var slaDueAt sql.NullTime
	err := row.Scan(
		&out.TenantID,
		&out.ID,
		&out.Engine,
		&out.FindingType,
		&out.Title,
		&out.Description,
		&out.Severity,
		&out.RiskScore,
		&out.RecommendedAction,
		&out.AutoActionAllowed,
		&out.Status,
		&out.Fingerprint,
		&evidenceRaw,
		&out.DetectedAt,
		&out.UpdatedAt,
		&resolvedAt,
		&slaDueAt,
		&out.ReopenCount,
	)
	if err != nil {
		return Finding{}, err
	}
	out.Evidence = parseJSONMap(evidenceRaw)
	out.ResolvedAt = toTime(resolvedAt)
	out.SLADueAt = toTime(slaDueAt)
	return out, nil
}

func scanAction(row scanner) (RemediationAction, error) {
	var out RemediationAction
	var evidenceRaw string
	var executedAt sql.NullTime
	err := row.Scan(
		&out.TenantID,
		&out.ID,
		&out.FindingID,
		&out.ActionType,
		&out.RecommendedAction,
		&out.SafetyGate,
		&out.ApprovalRequired,
		&out.ApprovalRequestID,
		&out.Status,
		&out.ExecutedBy,
		&executedAt,
		&evidenceRaw,
		&out.ResultMessage,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
	if err != nil {
		return RemediationAction{}, err
	}
	out.ExecutedAt = toTime(executedAt)
	out.Evidence = parseJSONMap(evidenceRaw)
	return out, nil
}

func scanRiskSnapshot(row scanner) (RiskSnapshot, error) {
	var out RiskSnapshot
	var signalsRaw string
	err := row.Scan(
		&out.TenantID,
		&out.ID,
		&out.Risk24h,
		&out.Risk7d,
		&out.PredictiveScore,
		&out.PreventiveScore,
		&out.CorrectiveScore,
		&signalsRaw,
		&out.CapturedAt,
	)
	if err != nil {
		return RiskSnapshot{}, err
	}
	out.TopSignals = parseJSONMap(signalsRaw)
	return out, nil
}

func nullableTime(v time.Time) interface{} {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
}

func toTime(v sql.NullTime) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return v.Time.UTC()
}
