package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)


var errNotFound = errors.New("not found")

type Store interface {
	PersistEventAndAlert(ctx context.Context, event AuditEvent, alert Alert, dedupWindowSec int, escalationThreshold int, escalationWindow time.Duration) (AuditEvent, Alert, error)
	QueryEvents(ctx context.Context, tenantID string, q EventQuery) ([]AuditEvent, error)
	GetEvent(ctx context.Context, tenantID string, id string) (AuditEvent, error)
	VerifyChain(ctx context.Context, tenantID string) (bool, []map[string]interface{}, error)

	QueryAlerts(ctx context.Context, tenantID string, q AlertQuery) ([]Alert, error)
	GetAlert(ctx context.Context, tenantID string, id string) (Alert, error)
	UpdateAlertStatus(ctx context.Context, tenantID string, id string, action string, actor string, note string, suppressUntil *time.Time) error
	AlertStats(ctx context.Context, tenantID string) (AlertStats, error)

	CreateRule(ctx context.Context, tenantID string, rule AlertRule) error
	ListRules(ctx context.Context, tenantID string) ([]AlertRule, error)
	UpdateRule(ctx context.Context, tenantID string, rule AlertRule) error
	DeleteRule(ctx context.Context, tenantID string, id string) error

	CountDistinctIPsForTarget(ctx context.Context, tenantID string, targetID string, since time.Time) (int, error)

	// Merkle tree operations
	BuildMerkleEpoch(ctx context.Context, tenantID string, maxLeaves int) (*MerkleEpochResult, error)
	ListMerkleEpochs(ctx context.Context, tenantID string, limit int) ([]MerkleEpoch, error)
	GetMerkleEpoch(ctx context.Context, tenantID string, epochID string) (MerkleEpoch, error)
	GetEventMerkleProof(ctx context.Context, tenantID string, eventID string) (*MerkleProofResponse, error)
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

type EventQuery struct {
	Action        string
	ActorID       string
	Result        string
	TargetID      string
	SessionID     string
	CorrelationID string
	RiskMin       int
	From          time.Time
	To            time.Time
	Limit         int
	Offset        int
}

type AlertQuery struct {
	Severity string
	Category string
	Status   string
	From     time.Time
	To       time.Time
	Limit    int
	Offset   int
}

func (s *SQLStore) PersistEventAndAlert(ctx context.Context, event AuditEvent, alert Alert, dedupWindowSec int, escalationThreshold int, escalationWindow time.Duration) (AuditEvent, Alert, error) {
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return AuditEvent{}, Alert{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	tenantID := event.TenantID
	previousHash := "GENESIS"
	sequence := int64(1)

	var prevSeq int64
	var prevHash string
	err = tx.QueryRowContext(ctx, `
SELECT sequence, chain_hash FROM audit_events
WHERE tenant_id=$1 ORDER BY sequence DESC LIMIT 1
`, tenantID).Scan(&prevSeq, &prevHash)
	if err == nil {
		sequence = prevSeq + 1
		previousHash = prevHash
	} else if !errors.Is(err, sql.ErrNoRows) {
		return AuditEvent{}, Alert{}, err
	}
	if event.ID == "" {
		event.ID = newID("evt")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.ActorType == "" {
		event.ActorType = "system"
	}
	if event.Result == "" {
		event.Result = "success"
	}
	event.Sequence = sequence
	event.PreviousHash = previousHash
	event.ChainHash = chainHash(previousHash, eventHashInput(event))

	tags, _ := json.Marshal(event.Tags)
	details, _ := json.Marshal(event.Details)
	_, err = tx.ExecContext(ctx, `
INSERT INTO audit_events (
    id, tenant_id, sequence, chain_hash, previous_hash, timestamp, service, action, actor_id, actor_type,
    target_type, target_id, method, endpoint, source_ip, user_agent, request_hash, correlation_id, parent_event_id,
    session_id, result, status_code, error_message, duration_ms, fips_compliant, approval_id, risk_score, tags, node_id, details, created_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,CURRENT_TIMESTAMP
)
`, event.ID, event.TenantID, event.Sequence, event.ChainHash, event.PreviousHash, event.Timestamp, event.Service, event.Action, event.ActorID, event.ActorType,
		event.TargetType, event.TargetID, event.Method, event.Endpoint, nullable(event.SourceIP), nullable(event.UserAgent), nullable(event.RequestHash),
		nullable(event.CorrelationID), nullable(event.ParentEventID), nullable(event.SessionID), event.Result, event.StatusCode, nullable(event.ErrorMessage),
		event.DurationMS, event.FIPSCompliant, nullable(event.ApprovalID), event.RiskScore, tags, nullable(event.NodeID), details,
	)
	if err != nil {
		return AuditEvent{}, Alert{}, err
	}

	if alert.ID == "" {
		alert.ID = newID("alr")
	}
	alert.TenantID = tenantID
	alert.AuditEventID = event.ID
	if alert.Status == "" {
		alert.Status = "open"
	}
	if alert.DedupKey == "" {
		alert.DedupKey = dedupKey(event, dedupWindowSec)
	}
	if alert.DispatchStatus == nil {
		alert.DispatchStatus = map[string]interface{}{}
	}
	if alert.OccurrenceCount == 0 {
		alert.OccurrenceCount = 1
	}
	dispatchJSON, _ := json.Marshal(alert.DispatchStatus)
	channelsJSON, _ := json.Marshal(alert.DispatchedChannels)

	var existingID string
	var existingCount int
	var existingSeverity string
	err = tx.QueryRowContext(ctx, `
SELECT id, occurrence_count, severity
FROM alerts
WHERE tenant_id=$1 AND dedup_key=$2 AND created_at >= $3
ORDER BY created_at DESC LIMIT 1
`, tenantID, alert.DedupKey, time.Now().UTC().Add(-time.Duration(dedupWindowSec)*time.Second)).Scan(&existingID, &existingCount, &existingSeverity)
	if err == nil {
		alert.ID = existingID
		alert.OccurrenceCount = existingCount + 1
		if existingSeverity != "" {
			alert.Severity = existingSeverity
		}
		_, err = tx.ExecContext(ctx, `
UPDATE alerts SET occurrence_count=$1, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$2 AND id=$3
`, alert.OccurrenceCount, tenantID, existingID)
		if err != nil {
			return AuditEvent{}, Alert{}, err
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		_, err = tx.ExecContext(ctx, `
INSERT INTO alerts (
    id, tenant_id, audit_event_id, severity, category, title, description, source_service, actor_id, target_id, risk_score,
    status, dispatched_channels, dispatch_status, dedup_key, occurrence_count, escalated_from, escalated_at, created_at, updated_at
) VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
`, alert.ID, alert.TenantID, alert.AuditEventID, alert.Severity, alert.Category, alert.Title, nullable(alert.Description),
			alert.SourceService, nullable(alert.ActorID), nullable(alert.TargetID), alert.RiskScore, alert.Status, channelsJSON, dispatchJSON, alert.DedupKey,
			alert.OccurrenceCount, nullable(alert.EscalatedFrom), nullableTime(alert.EscalatedAt))
		if err != nil {
			return AuditEvent{}, Alert{}, err
		}
	} else {
		return AuditEvent{}, Alert{}, err
	}

	if strings.EqualFold(alert.Severity, "HIGH") && escalationThreshold > 0 {
		shouldEscalate := alert.OccurrenceCount >= escalationThreshold
		if !shouldEscalate {
			var recentHigh int
			err = tx.QueryRowContext(ctx, `
SELECT COUNT(1) FROM alerts
WHERE tenant_id=$1 AND severity='HIGH' AND created_at >= $2
`, tenantID, time.Now().UTC().Add(-escalationWindow)).Scan(&recentHigh)
			if err != nil {
				return AuditEvent{}, Alert{}, err
			}
			shouldEscalate = recentHigh >= escalationThreshold
		}
		if shouldEscalate {
			alert.EscalatedFrom = "HIGH"
			alert.Severity = "CRITICAL"
			alert.EscalatedAt = time.Now().UTC()
			_, err = tx.ExecContext(ctx, `
UPDATE alerts
SET severity='CRITICAL', escalated_from='HIGH', escalated_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$1 AND id=$2
`, tenantID, alert.ID)
			if err != nil {
				return AuditEvent{}, Alert{}, err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return AuditEvent{}, Alert{}, err
	}
	return event, alert, nil
}

func (s *SQLStore) QueryEvents(ctx context.Context, tenantID string, q EventQuery) ([]AuditEvent, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, sequence, chain_hash, previous_hash, timestamp, service, action, actor_id, actor_type,
       COALESCE(target_type,''), COALESCE(target_id,''), COALESCE(method,''), COALESCE(endpoint,''), COALESCE(CAST(source_ip AS TEXT),''), COALESCE(user_agent,''),
       COALESCE(request_hash,''), COALESCE(correlation_id,''), COALESCE(parent_event_id,''), COALESCE(session_id,''),
       result, COALESCE(status_code,0), COALESCE(error_message,''), COALESCE(duration_ms,0), COALESCE(fips_compliant,false), COALESCE(approval_id,''),
       COALESCE(risk_score,0), COALESCE(tags,'[]'), COALESCE(node_id,''), COALESCE(details,'{}'), created_at
FROM audit_events
WHERE tenant_id=$1
  AND ($2='' OR action=$2)
  AND ($3='' OR actor_id=$3)
  AND ($4='' OR result=$4)
  AND ($5='' OR target_id=$5)
  AND ($6='' OR session_id=$6)
  AND ($7='' OR correlation_id=$7)
  AND ($8=0 OR risk_score >= $8)
  AND timestamp >= COALESCE($9, timestamp)
  AND timestamp <= COALESCE($10, timestamp)
ORDER BY timestamp DESC
LIMIT $11 OFFSET $12
`, tenantID, q.Action, q.ActorID, q.Result, q.TargetID, q.SessionID, q.CorrelationID, q.RiskMin, nullableTime(q.From), nullableTime(q.To), q.Limit, q.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []AuditEvent
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetEvent(ctx context.Context, tenantID string, id string) (AuditEvent, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, sequence, chain_hash, previous_hash, timestamp, service, action, actor_id, actor_type,
       COALESCE(target_type,''), COALESCE(target_id,''), COALESCE(method,''), COALESCE(endpoint,''), COALESCE(CAST(source_ip AS TEXT),''), COALESCE(user_agent,''),
       COALESCE(request_hash,''), COALESCE(correlation_id,''), COALESCE(parent_event_id,''), COALESCE(session_id,''),
       result, COALESCE(status_code,0), COALESCE(error_message,''), COALESCE(duration_ms,0), COALESCE(fips_compliant,false), COALESCE(approval_id,''),
       COALESCE(risk_score,0), COALESCE(tags,'[]'), COALESCE(node_id,''), COALESCE(details,'{}'), created_at
FROM audit_events WHERE tenant_id=$1 AND id=$2
`, tenantID, id)
	ev, err := scanEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return AuditEvent{}, errNotFound
	}
	return ev, err
}

func (s *SQLStore) VerifyChain(ctx context.Context, tenantID string) (bool, []map[string]interface{}, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, sequence, previous_hash, chain_hash, timestamp, service, action, actor_id, actor_type,
       COALESCE(target_type,''), COALESCE(target_id,''), COALESCE(method,''), COALESCE(endpoint,''), COALESCE(CAST(source_ip AS TEXT),''), COALESCE(user_agent,''),
       COALESCE(request_hash,''), COALESCE(correlation_id,''), COALESCE(parent_event_id,''), COALESCE(session_id,''),
       result, COALESCE(status_code,0), COALESCE(error_message,''), COALESCE(duration_ms,0), COALESCE(fips_compliant,false), COALESCE(approval_id,''),
       COALESCE(risk_score,0), tags, COALESCE(node_id,''), details
FROM audit_events
WHERE tenant_id=$1
ORDER BY sequence ASC
`, tenantID)
	if err != nil {
		return false, nil, err
	}
	defer rows.Close() //nolint:errcheck

	prevHash := "GENESIS"
	var breaks []map[string]interface{}
	for rows.Next() {
		var (
			ev                       AuditEvent
			timestampRaw             interface{}
			tagsRaw, detailsRaw      []byte
			targetType, targetID     string
			method, endpoint         string
			sourceIP, userAgent      string
			requestHash, corrID      string
			parentID, sessionID      string
			errorMessage, approvalID string
			nodeID                   string
		)
		if err := rows.Scan(&ev.ID, &ev.Sequence, &ev.PreviousHash, &ev.ChainHash, &timestampRaw, &ev.Service, &ev.Action, &ev.ActorID, &ev.ActorType,
			&targetType, &targetID, &method, &endpoint, &sourceIP, &userAgent, &requestHash, &corrID, &parentID, &sessionID,
			&ev.Result, &ev.StatusCode, &errorMessage, &ev.DurationMS, &ev.FIPSCompliant, &approvalID, &ev.RiskScore, &tagsRaw, &nodeID, &detailsRaw); err != nil {
			return false, nil, err
		}
		ev.TenantID = tenantID
		ev.TargetType = targetType
		ev.TargetID = targetID
		ev.Method = method
		ev.Endpoint = endpoint
		ev.SourceIP = sourceIP
		ev.UserAgent = userAgent
		ev.RequestHash = requestHash
		ev.CorrelationID = corrID
		ev.ParentEventID = parentID
		ev.SessionID = sessionID
		ev.ErrorMessage = errorMessage
		ev.ApprovalID = approvalID
		ev.NodeID = nodeID
		ev.Timestamp = parseTimeValue(timestampRaw)
		_ = json.Unmarshal(tagsRaw, &ev.Tags)
		_ = json.Unmarshal(detailsRaw, &ev.Details)

		if ev.PreviousHash != prevHash {
			breaks = append(breaks, map[string]interface{}{"sequence": ev.Sequence, "event_id": ev.ID, "reason": "previous_hash_mismatch"})
		}
		expected := chainHash(prevHash, eventHashInput(ev))
		if ev.ChainHash != expected {
			breaks = append(breaks, map[string]interface{}{"sequence": ev.Sequence, "event_id": ev.ID, "reason": "chain_hash_mismatch"})
		}
		prevHash = ev.ChainHash
	}
	return len(breaks) == 0, breaks, rows.Err()
}

func (s *SQLStore) QueryAlerts(ctx context.Context, tenantID string, q AlertQuery) ([]Alert, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 200
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, audit_event_id, severity, category, title, COALESCE(description,''), source_service,
       COALESCE(actor_id,''), COALESCE(target_id,''), COALESCE(risk_score,0), status, COALESCE(acknowledged_by,''),
       acknowledged_at, COALESCE(resolved_by,''), resolved_at,
       COALESCE(resolution_note,''), COALESCE(dispatched_channels,'[]'), COALESCE(dispatch_status,'{}'), COALESCE(dedup_key,''),
       COALESCE(occurrence_count,1), COALESCE(escalated_from,''), escalated_at, created_at, updated_at
FROM alerts
WHERE tenant_id=$1
  AND ($2='' OR severity=$2)
  AND ($3='' OR category=$3)
  AND ($4='' OR status=$4)
  AND created_at >= COALESCE($5, created_at)
  AND created_at <= COALESCE($6, created_at)
ORDER BY created_at DESC
LIMIT $7 OFFSET $8
`, tenantID, q.Severity, q.Category, q.Status, nullableTime(q.From), nullableTime(q.To), q.Limit, q.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []Alert
	for rows.Next() {
		al, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, al)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetAlert(ctx context.Context, tenantID string, id string) (Alert, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, audit_event_id, severity, category, title, COALESCE(description,''), source_service,
       COALESCE(actor_id,''), COALESCE(target_id,''), COALESCE(risk_score,0), status, COALESCE(acknowledged_by,''),
       acknowledged_at, COALESCE(resolved_by,''), resolved_at,
       COALESCE(resolution_note,''), COALESCE(dispatched_channels,'[]'), COALESCE(dispatch_status,'{}'), COALESCE(dedup_key,''),
       COALESCE(occurrence_count,1), COALESCE(escalated_from,''), escalated_at, created_at, updated_at
FROM alerts WHERE tenant_id=$1 AND id=$2
`, tenantID, id)
	al, err := scanAlert(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Alert{}, errNotFound
	}
	return al, err
}

func (s *SQLStore) UpdateAlertStatus(ctx context.Context, tenantID string, id string, action string, actor string, note string, suppressUntil *time.Time) error {
	switch strings.ToLower(action) {
	case "acknowledge":
		_, err := s.db.SQL().ExecContext(ctx, `
UPDATE alerts SET status='acknowledged', acknowledged_by=$1, acknowledged_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$2 AND id=$3
`, actor, tenantID, id)
		return err
	case "resolve":
		_, err := s.db.SQL().ExecContext(ctx, `
UPDATE alerts SET status='resolved', resolved_by=$1, resolved_at=CURRENT_TIMESTAMP, resolution_note=$2, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$3 AND id=$4
`, actor, note, tenantID, id)
		return err
	case "suppress":
		noteText := note
		if suppressUntil != nil {
			noteText = noteText + " suppress_until=" + suppressUntil.UTC().Format(time.RFC3339)
		}
		_, err := s.db.SQL().ExecContext(ctx, `
UPDATE alerts SET status='suppressed', resolution_note=$1, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$2 AND id=$3
`, noteText, tenantID, id)
		return err
	default:
		return fmt.Errorf("unsupported alert action %s", action)
	}
}

func (s *SQLStore) AlertStats(ctx context.Context, tenantID string) (AlertStats, error) {
	stats := AlertStats{
		OpenBySeverity: map[string]int{},
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT severity, COUNT(1)
FROM alerts
WHERE tenant_id=$1 AND status='open'
GROUP BY severity
`, tenantID)
	if err != nil {
		return stats, err
	}
	for rows.Next() {
		var sev string
		var cnt int
		if err := rows.Scan(&sev, &cnt); err != nil {
			rows.Close() //nolint:errcheck
			return stats, err
		}
		stats.OpenBySeverity[sev] = cnt
		stats.TotalOpen += cnt
	}
	rows.Close() //nolint:errcheck
	_ = s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(1) FROM alerts WHERE tenant_id=$1 AND status='acknowledged'`, tenantID).Scan(&stats.TotalAck)
	_ = s.db.SQL().QueryRowContext(ctx, `SELECT COUNT(1) FROM alerts WHERE tenant_id=$1 AND status='resolved'`, tenantID).Scan(&stats.TotalResolved)
	return stats, nil
}

func (s *SQLStore) CreateRule(ctx context.Context, tenantID string, rule AlertRule) error {
	if rule.ID == "" {
		rule.ID = newID("rule")
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO alert_rules (id, tenant_id, name, condition_expr, severity, title, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
`, rule.ID, tenantID, rule.Name, rule.Condition, rule.Severity, rule.Title)
	return err
}

func (s *SQLStore) ListRules(ctx context.Context, tenantID string) ([]AlertRule, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, name, condition_expr, severity, title
FROM alert_rules
WHERE tenant_id=$1 OR tenant_id='*'
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	var out []AlertRule
	for rows.Next() {
		var r AlertRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Condition, &r.Severity, &r.Title); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateRule(ctx context.Context, tenantID string, rule AlertRule) error {
	res, err := s.db.SQL().ExecContext(ctx, `
UPDATE alert_rules
SET name=$1, condition_expr=$2, severity=$3, title=$4, updated_at=CURRENT_TIMESTAMP
WHERE tenant_id=$5 AND id=$6
`, rule.Name, rule.Condition, rule.Severity, rule.Title, tenantID, rule.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) DeleteRule(ctx context.Context, tenantID string, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `DELETE FROM alert_rules WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CountDistinctIPsForTarget(ctx context.Context, tenantID string, targetID string, since time.Time) (int, error) {
	if targetID == "" {
		return 0, nil
	}
	var n int
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(DISTINCT source_ip)
FROM audit_events
WHERE tenant_id=$1 AND target_id=$2 AND timestamp >= $3
`, tenantID, targetID, since).Scan(&n)
	return n, err
}

func scanEvent(scanner interface {
	Scan(dest ...interface{}) error
}) (AuditEvent, error) {
	var ev AuditEvent
	var tagsRaw []byte
	var detailsRaw []byte
	var timestampRaw interface{}
	var createdRaw interface{}
	err := scanner.Scan(
		&ev.ID, &ev.TenantID, &ev.Sequence, &ev.ChainHash, &ev.PreviousHash, &timestampRaw, &ev.Service, &ev.Action,
		&ev.ActorID, &ev.ActorType, &ev.TargetType, &ev.TargetID, &ev.Method, &ev.Endpoint, &ev.SourceIP, &ev.UserAgent,
		&ev.RequestHash, &ev.CorrelationID, &ev.ParentEventID, &ev.SessionID, &ev.Result, &ev.StatusCode, &ev.ErrorMessage,
		&ev.DurationMS, &ev.FIPSCompliant, &ev.ApprovalID, &ev.RiskScore, &tagsRaw, &ev.NodeID, &detailsRaw, &createdRaw,
	)
	if err != nil {
		return AuditEvent{}, err
	}
	ev.Timestamp = parseTimeValue(timestampRaw)
	ev.CreatedAt = parseTimeValue(createdRaw)
	_ = json.Unmarshal(tagsRaw, &ev.Tags)
	_ = json.Unmarshal(detailsRaw, &ev.Details)
	if ev.Details == nil {
		ev.Details = map[string]interface{}{}
	}
	return ev, nil
}

func scanAlert(scanner interface {
	Scan(dest ...interface{}) error
}) (Alert, error) {
	var al Alert
	var channelsRaw []byte
	var dispatchRaw []byte
	var acknowledgedRaw interface{}
	var resolvedRaw interface{}
	var escalatedRaw interface{}
	var createdRaw interface{}
	var updatedRaw interface{}
	err := scanner.Scan(
		&al.ID, &al.TenantID, &al.AuditEventID, &al.Severity, &al.Category, &al.Title, &al.Description, &al.SourceService,
		&al.ActorID, &al.TargetID, &al.RiskScore, &al.Status, &al.AcknowledgedBy, &acknowledgedRaw, &al.ResolvedBy,
		&resolvedRaw, &al.ResolutionNote, &channelsRaw, &dispatchRaw, &al.DedupKey, &al.OccurrenceCount, &al.EscalatedFrom,
		&escalatedRaw, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return Alert{}, err
	}
	al.AcknowledgedAt = parseTimeValue(acknowledgedRaw)
	al.ResolvedAt = parseTimeValue(resolvedRaw)
	al.EscalatedAt = parseTimeValue(escalatedRaw)
	al.CreatedAt = parseTimeValue(createdRaw)
	al.UpdatedAt = parseTimeValue(updatedRaw)
	_ = json.Unmarshal(channelsRaw, &al.DispatchedChannels)
	_ = json.Unmarshal(dispatchRaw, &al.DispatchStatus)
	if al.DispatchStatus == nil {
		al.DispatchStatus = map[string]interface{}{}
	}
	return al, nil
}

func nullable(v string) interface{} {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func nullableTime(t time.Time) interface{} {
	if t.IsZero() {
		return nil
	}
	return t
}

func parseTimeValue(v interface{}) time.Time {
	switch x := v.(type) {
	case nil:
		return time.Time{}
	case time.Time:
		return x
	case *time.Time:
		if x == nil {
			return time.Time{}
		}
		return *x
	case []byte:
		return parseTimeString(string(x))
	case string:
		return parseTimeString(x)
	default:
		return time.Time{}
	}
}

// ── Merkle Tree Store Methods ─────────────────────────────────

func (s *SQLStore) BuildMerkleEpoch(ctx context.Context, tenantID string, maxLeaves int) (*MerkleEpochResult, error) {
	if maxLeaves <= 0 {
		maxLeaves = 1000
	}

	// Find the last epoch's seq_to for this tenant
	var lastSeqTo int64
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT COALESCE(MAX(seq_to), 0) FROM audit_merkle_epochs WHERE tenant_id=$1
`, tenantID).Scan(&lastSeqTo)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	// Fetch next batch of events after the last epoch
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, sequence, chain_hash FROM audit_events
WHERE tenant_id=$1 AND sequence > $2
ORDER BY sequence ASC
LIMIT $3
`, tenantID, lastSeqTo, maxLeaves)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type leaf struct {
		eventID   string
		sequence  int64
		chainHash string
	}
	var leaves []leaf
	for rows.Next() {
		var l leaf
		if err := rows.Scan(&l.eventID, &l.sequence, &l.chainHash); err != nil {
			return nil, err
		}
		leaves = append(leaves, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(leaves) == 0 {
		return nil, nil // nothing to build
	}

	// Build Merkle tree from chain_hash values
	hashes := make([]string, len(leaves))
	for i, l := range leaves {
		hashes[i] = l.chainHash
	}
	tree := BuildMerkleTree(hashes)
	root := tree.Root()

	// Get next epoch number
	var epochNum int
	err = s.db.SQL().QueryRowContext(ctx, `
SELECT COALESCE(MAX(epoch_number), 0) + 1 FROM audit_merkle_epochs WHERE tenant_id=$1
`, tenantID).Scan(&epochNum)
	if err != nil {
		return nil, err
	}

	epochID := newID("mke")
	seqFrom := leaves[0].sequence
	seqTo := leaves[len(leaves)-1].sequence

	// Insert epoch + leaves in a transaction
	tx, err := s.db.SQL().BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
INSERT INTO audit_merkle_epochs (id, tenant_id, epoch_number, seq_from, seq_to, leaf_count, tree_root, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
`, epochID, tenantID, epochNum, seqFrom, seqTo, len(leaves), root)
	if err != nil {
		return nil, err
	}

	for i, l := range leaves {
		_, err = tx.ExecContext(ctx, `
INSERT INTO audit_merkle_leaves (epoch_id, tenant_id, leaf_index, event_id, sequence, leaf_hash)
VALUES ($1, $2, $3, $4, $5, $6)
`, epochID, tenantID, i, l.eventID, l.sequence, hashes[i])
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	epoch := MerkleEpoch{
		ID:          epochID,
		TenantID:    tenantID,
		EpochNumber: epochNum,
		SeqFrom:     seqFrom,
		SeqTo:       seqTo,
		LeafCount:   len(leaves),
		TreeRoot:    root,
	}
	return &MerkleEpochResult{Epoch: epoch, Leaves: len(leaves)}, nil
}

func (s *SQLStore) ListMerkleEpochs(ctx context.Context, tenantID string, limit int) ([]MerkleEpoch, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT id, tenant_id, epoch_number, seq_from, seq_to, leaf_count, tree_root, created_at
FROM audit_merkle_epochs
WHERE tenant_id=$1
ORDER BY epoch_number DESC
LIMIT $2
`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MerkleEpoch
	for rows.Next() {
		var e MerkleEpoch
		var createdRaw interface{}
		if err := rows.Scan(&e.ID, &e.TenantID, &e.EpochNumber, &e.SeqFrom, &e.SeqTo, &e.LeafCount, &e.TreeRoot, &createdRaw); err != nil {
			return nil, err
		}
		e.CreatedAt = parseTimeValue(createdRaw)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *SQLStore) GetMerkleEpoch(ctx context.Context, tenantID string, epochID string) (MerkleEpoch, error) {
	var e MerkleEpoch
	var createdRaw interface{}
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT id, tenant_id, epoch_number, seq_from, seq_to, leaf_count, tree_root, created_at
FROM audit_merkle_epochs
WHERE tenant_id=$1 AND id=$2
`, tenantID, epochID).Scan(&e.ID, &e.TenantID, &e.EpochNumber, &e.SeqFrom, &e.SeqTo, &e.LeafCount, &e.TreeRoot, &createdRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return MerkleEpoch{}, errNotFound
	}
	if err != nil {
		return MerkleEpoch{}, err
	}
	e.CreatedAt = parseTimeValue(createdRaw)
	return e, nil
}

func (s *SQLStore) GetEventMerkleProof(ctx context.Context, tenantID string, eventID string) (*MerkleProofResponse, error) {
	// Find which epoch contains this event
	var leaf MerkleLeaf
	err := s.db.SQL().QueryRowContext(ctx, `
SELECT epoch_id, tenant_id, leaf_index, event_id, sequence, leaf_hash
FROM audit_merkle_leaves
WHERE tenant_id=$1 AND event_id=$2
`, tenantID, eventID).Scan(&leaf.EpochID, &leaf.TenantID, &leaf.LeafIndex, &leaf.EventID, &leaf.Sequence, &leaf.LeafHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}

	// Fetch all leaves for this epoch to rebuild the tree
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT leaf_hash FROM audit_merkle_leaves
WHERE tenant_id=$1 AND epoch_id=$2
ORDER BY leaf_index ASC
`, tenantID, leaf.EpochID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		hashes = append(hashes, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Rebuild tree and generate proof
	tree := BuildMerkleTree(hashes)
	proof, ok := GenerateProof(tree, leaf.LeafIndex)
	if !ok {
		return nil, fmt.Errorf("failed to generate proof for leaf %d", leaf.LeafIndex)
	}

	return &MerkleProofResponse{
		EventID:   leaf.EventID,
		Sequence:  leaf.Sequence,
		EpochID:   leaf.EpochID,
		LeafHash:  leaf.LeafHash,
		LeafIndex: leaf.LeafIndex,
		Siblings:  proof.Siblings,
		Root:      proof.Root,
	}, nil
}

func parseTimeString(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999 -0700 MST",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05.999999999-07:00",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02T15:04:05",
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, v); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}
