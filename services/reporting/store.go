package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	pkgdb "vecta-kms/pkg/db"
)

var errNotFound = errors.New("not found")

type Store interface {
	CreateAlert(ctx context.Context, item Alert) error
	UpdateAlertDedup(ctx context.Context, tenantID string, id string, addCount int, channels []string, channelStatus map[string]string) error
	GetAlert(ctx context.Context, tenantID string, id string) (Alert, error)
	GetAlertByAuditEventID(ctx context.Context, tenantID string, auditEventID string) (Alert, error)
	FindRecentDedupAlert(ctx context.Context, tenantID string, action string, targetID string, window time.Duration) (Alert, error)
	ListAlerts(ctx context.Context, tenantID string, q AlertQuery) ([]Alert, error)
	UpdateAlertStatus(ctx context.Context, tenantID string, id string, status string, actor string, note string) error
	EscalateAlert(ctx context.Context, tenantID string, id string, severity string) error
	BulkUpdateAlertStatus(ctx context.Context, tenantID string, ids []string, q AlertQuery, status string, actor string, note string) (int, error)
	CountUnreadBySeverity(ctx context.Context, tenantID string) (map[string]int, error)
	CountRecentAlerts(ctx context.Context, tenantID string, actionPattern string, sourceIP string, actorID string, window time.Duration) (int, error)

	CreateIncident(ctx context.Context, item Incident) error
	UpdateIncidentCounts(ctx context.Context, tenantID string, id string, severity string, latestAt time.Time, inc int) error
	GetIncident(ctx context.Context, tenantID string, id string) (Incident, error)
	ListIncidents(ctx context.Context, tenantID string, limit int, offset int) ([]Incident, error)
	UpdateIncidentStatus(ctx context.Context, tenantID string, id string, status string, notes string) error
	AssignIncident(ctx context.Context, tenantID string, id string, assignedTo string) error

	CreateRule(ctx context.Context, item AlertRule) error
	UpdateRule(ctx context.Context, item AlertRule) error
	DeleteRule(ctx context.Context, tenantID string, id string) error
	ListRules(ctx context.Context, tenantID string) ([]AlertRule, error)

	UpsertSeverityOverride(ctx context.Context, item SeverityOverride) error
	ListSeverityOverrides(ctx context.Context, tenantID string) ([]SeverityOverride, error)

	UpsertChannel(ctx context.Context, item NotificationChannel) error
	ListChannels(ctx context.Context, tenantID string) ([]NotificationChannel, error)

	CreateReportJob(ctx context.Context, item ReportJob) error
	UpdateReportJob(ctx context.Context, item ReportJob) error
	GetReportJob(ctx context.Context, tenantID string, id string) (ReportJob, error)
	ListReportJobs(ctx context.Context, tenantID string, limit int, offset int) ([]ReportJob, error)
	DeleteReportJob(ctx context.Context, tenantID string, id string) error
	CreateErrorTelemetry(ctx context.Context, item ErrorTelemetryEvent) error
	ListErrorTelemetry(ctx context.Context, tenantID string, q ErrorTelemetryQuery) ([]ErrorTelemetryEvent, error)
	PurgeErrorTelemetryBefore(ctx context.Context, before time.Time, limit int) (int64, error)

	CreateScheduledReport(ctx context.Context, item ScheduledReport) error
	ListScheduledReports(ctx context.Context, tenantID string) ([]ScheduledReport, error)
	ListDueScheduledReports(ctx context.Context, now time.Time, limit int) ([]ScheduledReport, error)
	UpdateScheduledReportRun(ctx context.Context, tenantID string, id string, lastRun time.Time, nextRun time.Time) error
}

type SQLStore struct {
	db *pkgdb.DB
}

func NewSQLStore(db *pkgdb.DB) *SQLStore {
	return &SQLStore{db: db}
}

func (s *SQLStore) CreateAlert(ctx context.Context, item Alert) error {
	if item.ChannelStatus == nil {
		item.ChannelStatus = map[string]string{}
	}
	if item.ChannelsSent == nil {
		item.ChannelsSent = []string{}
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO reporting_alerts (
	tenant_id, id, audit_event_id, audit_action, severity, category, title, description,
	service, actor_id, actor_type, target_type, target_id, source_ip, status,
	acknowledged_by, acknowledged_at, resolved_by, resolved_at, resolution_note,
	incident_id, correlation_id, rule_id, is_escalated, escalated_from, dedup_count,
	channels_sent_json, channel_status_json, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,
	$9,$10,$11,$12,$13,$14,$15,
	$16,$17,$18,$19,$20,
	$21,$22,$23,$24,$25,$26,
	$27,$28,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, item.AuditEventID, item.AuditAction, item.Severity, item.Category, item.Title, item.Description,
		item.Service, item.ActorID, item.ActorType, item.TargetType, item.TargetID, item.SourceIP, defaultString(item.Status, "new"),
		item.AcknowledgedBy, nullableTime(item.AcknowledgedAt), item.ResolvedBy, nullableTime(item.ResolvedAt), item.ResolutionNote,
		item.IncidentID, item.CorrelationID, item.RuleID, item.IsEscalated, item.EscalatedFrom, max(1, item.DedupCount),
		mustJSON(item.ChannelsSent, "[]"), mustJSON(item.ChannelStatus, "{}"))
	return err
}

func (s *SQLStore) UpdateAlertDedup(ctx context.Context, tenantID string, id string, addCount int, channels []string, channelStatus map[string]string) error {
	item, err := s.GetAlert(ctx, tenantID, id)
	if err != nil {
		return err
	}
	item.DedupCount += addCount
	item.ChannelsSent = uniqueStrings(append(item.ChannelsSent, channels...))
	if item.ChannelStatus == nil {
		item.ChannelStatus = map[string]string{}
	}
	for k, v := range channelStatus {
		item.ChannelStatus[k] = v
	}
	_, err = s.db.SQL().ExecContext(ctx, `
UPDATE reporting_alerts
SET dedup_count = $1,
	channels_sent_json = $2,
	channel_status_json = $3,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $4 AND id = $5
`, item.DedupCount, mustJSON(item.ChannelsSent, "[]"), mustJSON(item.ChannelStatus, "{}"), tenantID, id)
	return err
}

func (s *SQLStore) GetAlert(ctx context.Context, tenantID string, id string) (Alert, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, audit_event_id, audit_action, severity, category, title, description,
	   service, actor_id, actor_type, target_type, target_id, source_ip, status,
	   acknowledged_by, acknowledged_at, resolved_by, resolved_at, resolution_note,
	   incident_id, correlation_id, rule_id, is_escalated, escalated_from, dedup_count,
	   channels_sent_json, channel_status_json, created_at, updated_at
FROM reporting_alerts
WHERE tenant_id = $1 AND id = $2
`, tenantID, id)
	item, err := scanAlert(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Alert{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) GetAlertByAuditEventID(ctx context.Context, tenantID string, auditEventID string) (Alert, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, audit_event_id, audit_action, severity, category, title, description,
	   service, actor_id, actor_type, target_type, target_id, source_ip, status,
	   acknowledged_by, acknowledged_at, resolved_by, resolved_at, resolution_note,
	   incident_id, correlation_id, rule_id, is_escalated, escalated_from, dedup_count,
	   channels_sent_json, channel_status_json, created_at, updated_at
FROM reporting_alerts
WHERE tenant_id = $1 AND audit_event_id = $2
`, tenantID, auditEventID)
	item, err := scanAlert(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Alert{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) FindRecentDedupAlert(ctx context.Context, tenantID string, action string, targetID string, window time.Duration) (Alert, error) {
	if window <= 0 {
		window = time.Minute
	}
	since := time.Now().UTC().Add(-window)
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, audit_event_id, audit_action, severity, category, title, description,
	   service, actor_id, actor_type, target_type, target_id, source_ip, status,
	   acknowledged_by, acknowledged_at, resolved_by, resolved_at, resolution_note,
	   incident_id, correlation_id, rule_id, is_escalated, escalated_from, dedup_count,
	   channels_sent_json, channel_status_json, created_at, updated_at
FROM reporting_alerts
WHERE tenant_id = $1
  AND audit_action = $2
  AND COALESCE(target_id, '') = $3
  AND created_at >= $4
ORDER BY created_at DESC
LIMIT 1
`, tenantID, action, targetID, since)
	item, err := scanAlert(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Alert{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListAlerts(ctx context.Context, tenantID string, q AlertQuery) ([]Alert, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 100
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, audit_event_id, audit_action, severity, category, title, description,
	   service, actor_id, actor_type, target_type, target_id, source_ip, status,
	   acknowledged_by, acknowledged_at, resolved_by, resolved_at, resolution_note,
	   incident_id, correlation_id, rule_id, is_escalated, escalated_from, dedup_count,
	   channels_sent_json, channel_status_json, created_at, updated_at
FROM reporting_alerts
WHERE tenant_id = $1
  AND ($2 = '' OR severity = $2)
  AND ($3 = '' OR status = $3)
  AND ($4 = '' OR audit_action = $4)
  AND ($5 = '' OR target_type = $5)
  AND ($6 = '' OR target_id = $6)
  AND created_at >= COALESCE($7, created_at)
  AND created_at <= COALESCE($8, created_at)
ORDER BY created_at DESC
LIMIT $9 OFFSET $10
`, tenantID, strings.ToLower(q.Severity), strings.ToLower(q.Status), q.Action, q.TargetType, q.TargetID, nullableTime(q.From), nullableTime(q.To), q.Limit, max(0, q.Offset))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]Alert, 0)
	for rows.Next() {
		item, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateAlertStatus(ctx context.Context, tenantID string, id string, status string, actor string, note string) error {
	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case "acknowledged":
		_, err := s.db.SQL().ExecContext(ctx, `
UPDATE reporting_alerts
SET status = 'acknowledged',
	acknowledged_by = $1,
	acknowledged_at = CURRENT_TIMESTAMP,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $2 AND id = $3
`, actor, tenantID, id)
		return err
	case "resolved":
		_, err := s.db.SQL().ExecContext(ctx, `
UPDATE reporting_alerts
SET status = 'resolved',
	resolved_by = $1,
	resolved_at = CURRENT_TIMESTAMP,
	resolution_note = $2,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $3 AND id = $4
`, actor, note, tenantID, id)
		return err
	case "false_positive":
		_, err := s.db.SQL().ExecContext(ctx, `
UPDATE reporting_alerts
SET status = 'false_positive',
	resolved_by = $1,
	resolved_at = CURRENT_TIMESTAMP,
	resolution_note = $2,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $3 AND id = $4
`, actor, note, tenantID, id)
		return err
	default:
		return newServiceError(400, "bad_request", "unsupported status")
	}
}

func (s *SQLStore) EscalateAlert(ctx context.Context, tenantID string, id string, severity string) error {
	item, err := s.GetAlert(ctx, tenantID, id)
	if err != nil {
		return err
	}
	newSeverity := normalizeSeverity(severity)
	_, err = s.db.SQL().ExecContext(ctx, `
UPDATE reporting_alerts
SET severity = $1,
	is_escalated = TRUE,
	escalated_from = $2,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $3 AND id = $4
`, newSeverity, normalizeSeverity(item.Severity), tenantID, id)
	return err
}

func (s *SQLStore) BulkUpdateAlertStatus(ctx context.Context, tenantID string, ids []string, q AlertQuery, status string, actor string, note string) (int, error) {
	targetIDs := uniqueStrings(ids)
	if len(targetIDs) == 0 {
		items, err := s.ListAlerts(ctx, tenantID, q)
		if err != nil {
			return 0, err
		}
		for _, it := range items {
			targetIDs = append(targetIDs, it.ID)
		}
	}
	updated := 0
	for _, id := range targetIDs {
		if err := s.UpdateAlertStatus(ctx, tenantID, id, status, actor, note); err != nil {
			return updated, err
		}
		updated++
	}
	return updated, nil
}

func (s *SQLStore) CountUnreadBySeverity(ctx context.Context, tenantID string) (map[string]int, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT severity, COUNT(*)
FROM reporting_alerts
WHERE tenant_id = $1 AND status = 'new'
GROUP BY severity
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := map[string]int{
		severityCritical: 0,
		severityHigh:     0,
		severityWarning:  0,
		severityInfo:     0,
	}
	for rows.Next() {
		var sev string
		var c int
		if err := rows.Scan(&sev, &c); err != nil {
			return nil, err
		}
		out[normalizeSeverity(sev)] = c
	}
	return out, rows.Err()
}

func (s *SQLStore) CountRecentAlerts(ctx context.Context, tenantID string, actionPattern string, sourceIP string, actorID string, window time.Duration) (int, error) {
	if window <= 0 {
		window = 5 * time.Minute
	}
	since := time.Now().UTC().Add(-window)
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*)
FROM reporting_alerts
WHERE tenant_id = $1
  AND ($2 = '' OR audit_action LIKE $2)
  AND ($3 = '' OR source_ip = $3)
  AND ($4 = '' OR actor_id = $4)
  AND created_at >= $5
`, tenantID, actionPattern, sourceIP, actorID, since)
	var n int
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *SQLStore) CreateIncident(ctx context.Context, item Incident) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO reporting_incidents (
	tenant_id, id, title, severity, status, alert_count, first_alert_at, last_alert_at,
	assigned_to, notes, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, item.Title, item.Severity, defaultString(item.Status, "open"), max(1, item.AlertCount),
		nullableTime(item.FirstAlertAt), nullableTime(item.LastAlertAt), item.AssignedTo, item.Notes)
	return err
}

func (s *SQLStore) UpdateIncidentCounts(ctx context.Context, tenantID string, id string, severity string, latestAt time.Time, inc int) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE reporting_incidents
SET severity = CASE
	WHEN severity = 'critical' THEN 'critical'
	WHEN severity = 'high' AND $1 IN ('critical') THEN 'critical'
	WHEN severity = 'warning' AND $1 IN ('critical','high') THEN $1
	WHEN severity = 'info' AND $1 IN ('critical','high','warning') THEN $1
	ELSE severity
END,
	alert_count = alert_count + $2,
	last_alert_at = $3,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $4 AND id = $5
`, normalizeSeverity(severity), max(inc, 1), nullableTime(latestAt), tenantID, id)
	return err
}

func (s *SQLStore) GetIncident(ctx context.Context, tenantID string, id string) (Incident, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, title, severity, status, alert_count, first_alert_at, last_alert_at, assigned_to, notes, created_at, updated_at
FROM reporting_incidents
WHERE tenant_id = $1 AND id = $2
`, tenantID, id)
	item, err := scanIncident(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Incident{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListIncidents(ctx context.Context, tenantID string, limit int, offset int) ([]Incident, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, title, severity, status, alert_count, first_alert_at, last_alert_at, assigned_to, notes, created_at, updated_at
FROM reporting_incidents
WHERE tenant_id = $1
ORDER BY COALESCE(last_alert_at, created_at) DESC
LIMIT $2 OFFSET $3
`, tenantID, limit, max(0, offset))
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []Incident{}
	for rows.Next() {
		item, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateIncidentStatus(ctx context.Context, tenantID string, id string, status string, notes string) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE reporting_incidents
SET status = $1,
	notes = CASE WHEN $2 = '' THEN notes ELSE $2 END,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $3 AND id = $4
`, strings.ToLower(strings.TrimSpace(status)), notes, tenantID, id)
	return err
}

func (s *SQLStore) AssignIncident(ctx context.Context, tenantID string, id string, assignedTo string) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE reporting_incidents
SET assigned_to = $1,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $2 AND id = $3
`, assignedTo, tenantID, id)
	return err
}

func (s *SQLStore) CreateRule(ctx context.Context, item AlertRule) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO reporting_alert_rules (
	tenant_id, id, name, condition, severity, event_pattern, threshold, window_seconds, channels_json, enabled, expression, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, item.Name, item.Condition, normalizeSeverity(item.Severity), item.EventPattern, item.Threshold,
		max(item.WindowSecond, 0), mustJSON(item.Channels, "[]"), item.Enabled, item.Expression)
	return err
}

func (s *SQLStore) UpdateRule(ctx context.Context, item AlertRule) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE reporting_alert_rules
SET name = $1,
	condition = $2,
	severity = $3,
	event_pattern = $4,
	threshold = $5,
	window_seconds = $6,
	channels_json = $7,
	enabled = $8,
	expression = $9,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $10 AND id = $11
`, item.Name, item.Condition, normalizeSeverity(item.Severity), item.EventPattern, item.Threshold, max(item.WindowSecond, 0), mustJSON(item.Channels, "[]"), item.Enabled, item.Expression, item.TenantID, item.ID)
	return err
}

func (s *SQLStore) DeleteRule(ctx context.Context, tenantID string, id string) error {
	_, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM reporting_alert_rules
WHERE tenant_id = $1 AND id = $2
`, tenantID, id)
	return err
}

func (s *SQLStore) ListRules(ctx context.Context, tenantID string) ([]AlertRule, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, name, condition, severity, event_pattern, threshold, window_seconds, channels_json, enabled, expression, created_at, updated_at
FROM reporting_alert_rules
WHERE tenant_id = $1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []AlertRule{}
	for rows.Next() {
		item, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertSeverityOverride(ctx context.Context, item SeverityOverride) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO reporting_severity_overrides (
	tenant_id, audit_action, severity, updated_at
) VALUES (
	$1,$2,$3,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, audit_action) DO UPDATE SET
	severity = excluded.severity,
	updated_at = CURRENT_TIMESTAMP
`, item.TenantID, strings.ToLower(strings.TrimSpace(item.AuditAction)), normalizeSeverity(item.Severity))
	return err
}

func (s *SQLStore) ListSeverityOverrides(ctx context.Context, tenantID string) ([]SeverityOverride, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, audit_action, severity, updated_at
FROM reporting_severity_overrides
WHERE tenant_id = $1
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []SeverityOverride{}
	for rows.Next() {
		var item SeverityOverride
		var updatedRaw interface{}
		if err := rows.Scan(&item.TenantID, &item.AuditAction, &item.Severity, &updatedRaw); err != nil {
			return nil, err
		}
		item.Severity = normalizeSeverity(item.Severity)
		item.UpdatedAt = parseTimeValue(updatedRaw)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpsertChannel(ctx context.Context, item NotificationChannel) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO reporting_notification_channels (
	tenant_id, name, enabled, config_json, updated_at
) VALUES (
	$1,$2,$3,$4,CURRENT_TIMESTAMP
)
ON CONFLICT (tenant_id, name) DO UPDATE SET
	enabled = excluded.enabled,
	config_json = excluded.config_json,
	updated_at = CURRENT_TIMESTAMP
`, item.TenantID, strings.ToLower(strings.TrimSpace(item.Name)), item.Enabled, mustJSON(item.Config, "{}"))
	return err
}

func (s *SQLStore) ListChannels(ctx context.Context, tenantID string) ([]NotificationChannel, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, name, enabled, config_json, updated_at
FROM reporting_notification_channels
WHERE tenant_id = $1
ORDER BY name
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []NotificationChannel{}
	for rows.Next() {
		var item NotificationChannel
		var configJSON string
		var updatedRaw interface{}
		if err := rows.Scan(&item.TenantID, &item.Name, &item.Enabled, &configJSON, &updatedRaw); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(configJSON), &item.Config)
		if item.Config == nil {
			item.Config = map[string]interface{}{}
		}
		item.UpdatedAt = parseTimeValue(updatedRaw)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) CreateReportJob(ctx context.Context, item ReportJob) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO reporting_report_jobs (
	tenant_id, id, template_id, format, status, filters_json, result_content, result_content_type,
	requested_by, error, created_at, updated_at, completed_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,$11
)
`, item.TenantID, item.ID, item.TemplateID, item.Format, item.Status, mustJSON(item.Filters, "{}"),
		item.ResultContent, item.ResultContentType, item.RequestedBy, item.Error, nullableTime(item.CompletedAt))
	return err
}

func (s *SQLStore) UpdateReportJob(ctx context.Context, item ReportJob) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE reporting_report_jobs
SET status = $1,
	result_content = $2,
	result_content_type = $3,
	error = $4,
	updated_at = CURRENT_TIMESTAMP,
	completed_at = $5
WHERE tenant_id = $6 AND id = $7
`, item.Status, item.ResultContent, item.ResultContentType, item.Error, nullableTime(item.CompletedAt), item.TenantID, item.ID)
	return err
}

func (s *SQLStore) GetReportJob(ctx context.Context, tenantID string, id string) (ReportJob, error) {
	row := s.db.SQL().QueryRowContext(ctx, `
SELECT tenant_id, id, template_id, format, status, filters_json, result_content, result_content_type,
	   requested_by, error, created_at, updated_at, completed_at
FROM reporting_report_jobs
WHERE tenant_id = $1 AND id = $2
`, tenantID, id)
	item, err := scanReportJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ReportJob{}, errNotFound
	}
	return item, err
}

func (s *SQLStore) ListReportJobs(ctx context.Context, tenantID string, limit int, offset int) ([]ReportJob, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, template_id, format, status, filters_json, result_content, result_content_type,
	   requested_by, error, created_at, updated_at, completed_at
FROM reporting_report_jobs
WHERE tenant_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3
`, tenantID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ReportJob, 0)
	for rows.Next() {
		item, err := scanReportJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) DeleteReportJob(ctx context.Context, tenantID string, id string) error {
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM reporting_report_jobs
WHERE tenant_id = $1 AND id = $2
`, tenantID, id)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return errNotFound
	}
	return nil
}

func (s *SQLStore) CreateErrorTelemetry(ctx context.Context, item ErrorTelemetryEvent) error {
	if item.Context == nil {
		item.Context = map[string]interface{}{}
	}
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO reporting_error_telemetry (
	tenant_id, id, source, service, component, level, message, stack_trace,
	context_json, fingerprint, request_id, release_tag, build_version, created_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,COALESCE($14, CURRENT_TIMESTAMP)
)
`,
		item.TenantID,
		item.ID,
		item.Source,
		item.Service,
		item.Component,
		item.Level,
		item.Message,
		item.StackTrace,
		mustJSON(item.Context, "{}"),
		item.Fingerprint,
		item.RequestID,
		item.ReleaseTag,
		item.BuildVer,
		nullableTime(item.CreatedAt),
	)
	return err
}

func (s *SQLStore) ListErrorTelemetry(ctx context.Context, tenantID string, q ErrorTelemetryQuery) ([]ErrorTelemetryEvent, error) {
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 100
	}
	if q.Offset < 0 {
		q.Offset = 0
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, source, service, component, level, message, stack_trace,
	   context_json, fingerprint, request_id, release_tag, build_version, created_at
FROM reporting_error_telemetry
WHERE tenant_id = $1
  AND ($2 = '' OR source = $2)
  AND ($3 = '' OR service = $3)
  AND ($4 = '' OR component = $4)
  AND ($5 = '' OR level = $5)
  AND ($6 = '' OR fingerprint = $6)
  AND ($7 = '' OR request_id = $7)
  AND created_at >= COALESCE($8, created_at)
  AND created_at <= COALESCE($9, created_at)
ORDER BY created_at DESC
LIMIT $10 OFFSET $11
`,
		tenantID,
		strings.ToLower(strings.TrimSpace(q.Source)),
		strings.ToLower(strings.TrimSpace(q.Service)),
		strings.ToLower(strings.TrimSpace(q.Component)),
		strings.ToLower(strings.TrimSpace(q.Level)),
		strings.TrimSpace(q.Fingerprint),
		strings.TrimSpace(q.RequestID),
		nullableTime(q.From),
		nullableTime(q.To),
		q.Limit,
		q.Offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := make([]ErrorTelemetryEvent, 0)
	for rows.Next() {
		item, err := scanErrorTelemetry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) PurgeErrorTelemetryBefore(ctx context.Context, before time.Time, limit int) (int64, error) {
	if before.IsZero() {
		return 0, nil
	}
	if limit <= 0 || limit > 100000 {
		limit = 10000
	}
	res, err := s.db.SQL().ExecContext(ctx, `
DELETE FROM reporting_error_telemetry
WHERE (tenant_id, id) IN (
	SELECT tenant_id, id
	FROM reporting_error_telemetry
	WHERE created_at < $1
	ORDER BY created_at ASC
	LIMIT $2
)
`, before.UTC(), limit)
	if err != nil {
		return 0, err
	}
	affected, _ := res.RowsAffected()
	return affected, nil
}

func (s *SQLStore) CreateScheduledReport(ctx context.Context, item ScheduledReport) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO reporting_scheduled_reports (
	tenant_id, id, name, template_id, format, schedule, filters_json, recipients_json, enabled,
	last_run_at, next_run_at, created_at, updated_at
) VALUES (
	$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP
)
`, item.TenantID, item.ID, item.Name, item.TemplateID, item.Format, item.Schedule, mustJSON(item.Filters, "{}"),
		mustJSON(item.Recipients, "[]"), item.Enabled, nullableTime(item.LastRunAt), nullableTime(item.NextRunAt))
	return err
}

func (s *SQLStore) ListScheduledReports(ctx context.Context, tenantID string) ([]ScheduledReport, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, name, template_id, format, schedule, filters_json, recipients_json, enabled,
	   last_run_at, next_run_at, created_at, updated_at
FROM reporting_scheduled_reports
WHERE tenant_id = $1
ORDER BY created_at DESC
`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []ScheduledReport{}
	for rows.Next() {
		item, err := scanScheduledReport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) ListDueScheduledReports(ctx context.Context, now time.Time, limit int) ([]ScheduledReport, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.SQL().QueryContext(ctx, `
SELECT tenant_id, id, name, template_id, format, schedule, filters_json, recipients_json, enabled,
	   last_run_at, next_run_at, created_at, updated_at
FROM reporting_scheduled_reports
WHERE enabled = TRUE
  AND (next_run_at IS NULL OR next_run_at <= $1)
ORDER BY next_run_at ASC
LIMIT $2
`, now.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	out := []ScheduledReport{}
	for rows.Next() {
		item, err := scanScheduledReport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SQLStore) UpdateScheduledReportRun(ctx context.Context, tenantID string, id string, lastRun time.Time, nextRun time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx, `
UPDATE reporting_scheduled_reports
SET last_run_at = $1,
	next_run_at = $2,
	updated_at = CURRENT_TIMESTAMP
WHERE tenant_id = $3 AND id = $4
`, nullableTime(lastRun), nullableTime(nextRun), tenantID, id)
	return err
}

func scanAlert(scanner interface {
	Scan(dest ...interface{}) error
}) (Alert, error) {
	var (
		item             Alert
		channelsSentJSON string
		channelStatusJS  string
		ackRaw           interface{}
		resolvedRaw      interface{}
		createdRaw       interface{}
		updatedRaw       interface{}
	)
	err := scanner.Scan(
		&item.TenantID, &item.ID, &item.AuditEventID, &item.AuditAction, &item.Severity, &item.Category, &item.Title, &item.Description,
		&item.Service, &item.ActorID, &item.ActorType, &item.TargetType, &item.TargetID, &item.SourceIP, &item.Status,
		&item.AcknowledgedBy, &ackRaw, &item.ResolvedBy, &resolvedRaw, &item.ResolutionNote,
		&item.IncidentID, &item.CorrelationID, &item.RuleID, &item.IsEscalated, &item.EscalatedFrom, &item.DedupCount,
		&channelsSentJSON, &channelStatusJS, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return Alert{}, err
	}
	_ = json.Unmarshal([]byte(channelsSentJSON), &item.ChannelsSent)
	_ = json.Unmarshal([]byte(channelStatusJS), &item.ChannelStatus)
	if item.ChannelsSent == nil {
		item.ChannelsSent = []string{}
	}
	if item.ChannelStatus == nil {
		item.ChannelStatus = map[string]string{}
	}
	item.Severity = normalizeSeverity(item.Severity)
	item.Status = strings.ToLower(defaultString(item.Status, "new"))
	item.AcknowledgedAt = parseTimeValue(ackRaw)
	item.ResolvedAt = parseTimeValue(resolvedRaw)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func scanIncident(scanner interface {
	Scan(dest ...interface{}) error
}) (Incident, error) {
	var (
		item       Incident
		firstRaw   interface{}
		lastRaw    interface{}
		createdRaw interface{}
		updatedRaw interface{}
	)
	err := scanner.Scan(&item.TenantID, &item.ID, &item.Title, &item.Severity, &item.Status, &item.AlertCount, &firstRaw, &lastRaw, &item.AssignedTo, &item.Notes, &createdRaw, &updatedRaw)
	if err != nil {
		return Incident{}, err
	}
	item.Severity = normalizeSeverity(item.Severity)
	item.FirstAlertAt = parseTimeValue(firstRaw)
	item.LastAlertAt = parseTimeValue(lastRaw)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func scanRule(scanner interface {
	Scan(dest ...interface{}) error
}) (AlertRule, error) {
	var (
		item         AlertRule
		channelsJSON string
		createdRaw   interface{}
		updatedRaw   interface{}
	)
	err := scanner.Scan(&item.TenantID, &item.ID, &item.Name, &item.Condition, &item.Severity, &item.EventPattern, &item.Threshold, &item.WindowSecond, &channelsJSON, &item.Enabled, &item.Expression, &createdRaw, &updatedRaw)
	if err != nil {
		return AlertRule{}, err
	}
	_ = json.Unmarshal([]byte(channelsJSON), &item.Channels)
	if item.Channels == nil {
		item.Channels = []string{}
	}
	item.Severity = normalizeSeverity(item.Severity)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func scanReportJob(scanner interface {
	Scan(dest ...interface{}) error
}) (ReportJob, error) {
	var (
		item         ReportJob
		filtersJSON  string
		createdRaw   interface{}
		updatedRaw   interface{}
		completedRaw interface{}
	)
	err := scanner.Scan(
		&item.TenantID, &item.ID, &item.TemplateID, &item.Format, &item.Status, &filtersJSON, &item.ResultContent, &item.ResultContentType,
		&item.RequestedBy, &item.Error, &createdRaw, &updatedRaw, &completedRaw,
	)
	if err != nil {
		return ReportJob{}, err
	}
	_ = json.Unmarshal([]byte(filtersJSON), &item.Filters)
	if item.Filters == nil {
		item.Filters = map[string]interface{}{}
	}
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	item.CompletedAt = parseTimeValue(completedRaw)
	return item, nil
}

func scanScheduledReport(scanner interface {
	Scan(dest ...interface{}) error
}) (ScheduledReport, error) {
	var (
		item         ScheduledReport
		filtersJSON  string
		recipientsJS string
		lastRunRaw   interface{}
		nextRunRaw   interface{}
		createdRaw   interface{}
		updatedRaw   interface{}
	)
	err := scanner.Scan(
		&item.TenantID, &item.ID, &item.Name, &item.TemplateID, &item.Format, &item.Schedule, &filtersJSON, &recipientsJS, &item.Enabled,
		&lastRunRaw, &nextRunRaw, &createdRaw, &updatedRaw,
	)
	if err != nil {
		return ScheduledReport{}, err
	}
	_ = json.Unmarshal([]byte(filtersJSON), &item.Filters)
	_ = json.Unmarshal([]byte(recipientsJS), &item.Recipients)
	if item.Filters == nil {
		item.Filters = map[string]interface{}{}
	}
	if item.Recipients == nil {
		item.Recipients = []string{}
	}
	item.LastRunAt = parseTimeValue(lastRunRaw)
	item.NextRunAt = parseTimeValue(nextRunRaw)
	item.CreatedAt = parseTimeValue(createdRaw)
	item.UpdatedAt = parseTimeValue(updatedRaw)
	return item, nil
}

func scanErrorTelemetry(scanner interface {
	Scan(dest ...interface{}) error
}) (ErrorTelemetryEvent, error) {
	var (
		item        ErrorTelemetryEvent
		contextJSON string
		createdRaw  interface{}
	)
	err := scanner.Scan(
		&item.TenantID,
		&item.ID,
		&item.Source,
		&item.Service,
		&item.Component,
		&item.Level,
		&item.Message,
		&item.StackTrace,
		&contextJSON,
		&item.Fingerprint,
		&item.RequestID,
		&item.ReleaseTag,
		&item.BuildVer,
		&createdRaw,
	)
	if err != nil {
		return ErrorTelemetryEvent{}, err
	}
	item.Source = strings.ToLower(strings.TrimSpace(item.Source))
	item.Service = strings.ToLower(strings.TrimSpace(item.Service))
	item.Component = strings.ToLower(strings.TrimSpace(item.Component))
	item.Level = normalizeTelemetryLevel(item.Level)
	_ = json.Unmarshal([]byte(contextJSON), &item.Context)
	if item.Context == nil {
		item.Context = map[string]interface{}{}
	}
	item.CreatedAt = parseTimeValue(createdRaw)
	return item, nil
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}
