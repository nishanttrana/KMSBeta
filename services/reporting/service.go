package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"vecta-kms/pkg/pdfutil"
)

type Service struct {
	store               Store
	audit               AuditClient
	compliance          ComplianceClient
	posture             PostureClient
	events              EventPublisher
	hub                 *feedHub
	telemetryRetention  time.Duration
	telemetryPurgeBatch int
	mu                  sync.Mutex
}

func NewService(store Store, audit AuditClient, compliance ComplianceClient, posture PostureClient, events EventPublisher) *Service {
	return &Service{
		store:               store,
		audit:               audit,
		compliance:          compliance,
		posture:             posture,
		events:              events,
		hub:                 newFeedHub(),
		telemetryRetention:  30 * 24 * time.Hour,
		telemetryPurgeBatch: 10000,
	}
}

func (s *Service) ConfigureTelemetryRetention(retention time.Duration, purgeBatch int) {
	if retention > 0 {
		s.telemetryRetention = retention
	}
	if purgeBatch > 0 {
		s.telemetryPurgeBatch = purgeBatch
	}
}

func (s *Service) StartScheduler(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		telemetryPurgeTick := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = s.RunDueSchedules(context.Background())
				telemetryPurgeTick++
				if telemetryPurgeTick >= 60 {
					telemetryPurgeTick = 0
					_ = s.PurgeErrorTelemetry(context.Background())
				}
			}
		}
	}()
}

func (s *Service) SyncAlertsFromAudit(ctx context.Context, tenantID string, limit int) error {
	if s.audit == nil {
		return nil
	}
	if limit <= 0 || limit > 2000 {
		limit = 300
	}
	events, err := s.audit.ListEvents(ctx, tenantID, limit)
	if err != nil {
		return err
	}
	sort.Slice(events, func(i, j int) bool {
		return parseTimeString(firstString(events[i]["timestamp"])).Before(parseTimeString(firstString(events[j]["timestamp"])))
	})
	for _, ev := range events {
		_, _ = s.ingestAuditEvent(ctx, tenantID, ev)
	}
	return nil
}

func (s *Service) ingestAuditEvent(ctx context.Context, tenantID string, ev map[string]interface{}) (Alert, error) {
	eventID := firstString(ev["id"], ev["event_id"])
	if eventID != "" {
		if existing, err := s.store.GetAlertByAuditEventID(ctx, tenantID, eventID); err == nil {
			return existing, nil
		}
	}
	action := strings.ToLower(firstString(ev["action"], ev["audit_action"], ev["subject"]))
	if action == "" {
		action = "unknown.action"
	}
	targetID := firstString(ev["target_id"], ev["resource_id"])

	dedup, err := s.store.FindRecentDedupAlert(ctx, tenantID, action, targetID, 60*time.Second)
	if err == nil && dedup.DedupCount < 1000 {
		_, channels, channelStatus := s.dispatchChannels(tenantID, dedup.Severity, action)
		_ = s.store.UpdateAlertDedup(ctx, tenantID, dedup.ID, 1, channels, channelStatus)
		updated, _ := s.store.GetAlert(ctx, tenantID, dedup.ID)
		s.hub.Publish(tenantID, updated)
		return updated, nil
	}

	sev := s.classifySeverity(ctx, tenantID, action, ev)
	escalateTo, incidentTitle := s.evaluateEscalationRules(ctx, tenantID, action, ev)
	if escalateTo != "" {
		sev = maxSeverity(sev, escalateTo)
	}

	// Evaluate user-defined alert rules
	ruleMatched, matchedRuleID, matchedRuleSev := s.evaluateAlertRules(ctx, tenantID, action, ev)
	if ruleMatched {
		sev = maxSeverity(sev, matchedRuleSev)
	}

	// Alert Center is reserved for actionable signals; passive info events stay in audit logs.
	if sev == severityInfo && escalateTo == "" {
		return Alert{}, nil
	}

	category := categoryForAction(action)
	title := titleForAction(action, ev)
	desc := descriptionForEvent(ev)

	alert := Alert{
		ID:            newID("alert"),
		TenantID:      tenantID,
		AuditEventID:  eventID,
		AuditAction:   action,
		Severity:      sev,
		Category:      category,
		Title:         title,
		Description:   desc,
		Service:       firstString(ev["service"]),
		ActorID:       firstString(ev["actor_id"], ev["user_id"]),
		ActorType:     firstString(ev["actor_type"], ev["role"], "user"),
		TargetType:    firstString(ev["target_type"], ev["resource_type"]),
		TargetID:      targetID,
		SourceIP:      firstString(ev["source_ip"], ev["ip"]),
		Status:        "new",
		CorrelationID: firstString(ev["correlation_id"], ev["session_id"]),
		RuleID:        matchedRuleID,
		DedupCount:    1,
	}
	if incidentTitle != "" {
		incidentID, _ := s.attachIncident(ctx, tenantID, incidentTitle, sev, parseTimeString(firstString(ev["timestamp"])))
		alert.IncidentID = incidentID
	}
	_, channels, channelStatus := s.dispatchChannels(tenantID, sev, action)
	alert.ChannelsSent = channels
	alert.ChannelStatus = channelStatus
	if err := s.store.CreateAlert(ctx, alert); err != nil {
		return Alert{}, err
	}
	alert, _ = s.store.GetAlert(ctx, tenantID, alert.ID)
	s.hub.Publish(tenantID, alert)
	_ = s.publishAudit(ctx, "audit.reporting.alert_created", tenantID, map[string]interface{}{
		"alert_id":     alert.ID,
		"audit_action": alert.AuditAction,
		"severity":     alert.Severity,
	})
	return alert, nil
}

func (s *Service) classifySeverity(ctx context.Context, tenantID string, action string, event map[string]interface{}) string {
	action = strings.ToLower(strings.TrimSpace(action))
	overrides, _ := s.store.ListSeverityOverrides(ctx, tenantID)
	for _, o := range overrides {
		if strings.EqualFold(strings.TrimSpace(o.AuditAction), action) {
			return normalizeSeverity(o.Severity)
		}
	}
	defaults := severityDefaults()
	if sev, ok := defaults[action]; ok {
		return normalizeSeverity(sev)
	}
	for pattern, sev := range defaults {
		if strings.Contains(pattern, "*") && matchPattern(action, pattern) {
			return normalizeSeverity(sev)
		}
	}
	if action == "auth.login_failed" {
		if s.shouldEscalateLoginFailed(ctx, tenantID, event) {
			return severityCritical
		}
		return severityWarning
	}
	return severityInfo
}

func (s *Service) shouldEscalateLoginFailed(ctx context.Context, tenantID string, event map[string]interface{}) bool {
	ip := firstString(event["source_ip"], event["ip"])
	if ip == "" {
		return false
	}
	count, err := s.store.CountRecentAlerts(ctx, tenantID, "auth.login_failed", ip, "", 5*time.Minute)
	if err != nil {
		return false
	}
	return count >= 3
}

func (s *Service) evaluateEscalationRules(ctx context.Context, tenantID string, action string, event map[string]interface{}) (string, string) {
	sourceIP := firstString(event["source_ip"], event["ip"])
	actorID := firstString(event["actor_id"], event["user_id"])
	switch {
	case action == "auth.login_failed" && sourceIP != "":
		if n, _ := s.store.CountRecentAlerts(ctx, tenantID, "auth.login_failed", sourceIP, "", 5*time.Minute); n >= 3 {
			return severityCritical, "Brute Force Attack from " + sourceIP
		}
	case action == "key.exported" && actorID != "":
		if n, _ := s.store.CountRecentAlerts(ctx, tenantID, "key.exported", "", actorID, 10*time.Minute); n >= 5 {
			return severityCritical, "Mass Key Export by " + actorID
		}
	case strings.HasPrefix(action, "admin."):
		now := time.Now().UTC()
		if now.Hour() < 6 || now.Hour() >= 22 {
			return severityHigh, ""
		}
	case strings.HasPrefix(action, "dataprotect.detokenize") && actorID != "":
		if n, _ := s.store.CountRecentAlerts(ctx, tenantID, "dataprotect.detokenize%", "", actorID, 1*time.Minute); n >= 100 {
			return severityCritical, "Mass Detokenization by " + actorID + " - possible data exfiltration"
		}
	case action == "fips.violation_blocked":
		if n, _ := s.store.CountRecentAlerts(ctx, tenantID, "fips.violation_blocked", "", "", 5*time.Minute); n >= 10 {
			return severityCritical, "FIPS Violation Spike"
		}
	case action == "cluster.node_failed":
		if n, _ := s.store.CountRecentAlerts(ctx, tenantID, "cluster.node_failed", "", "", 10*time.Minute); n >= 2 {
			return severityCritical, "Cluster Quorum Risk"
		}
	}
	return "", ""
}

// evaluateAlertRules checks enabled tenant rules against the incoming event.
// Returns true if any rule matched, along with the matched rule's ID and severity.
func (s *Service) evaluateAlertRules(ctx context.Context, tenantID string, action string, ev map[string]interface{}) (matched bool, ruleID string, ruleSeverity string) {
	rules, err := s.store.ListRules(ctx, tenantID)
	if err != nil || len(rules) == 0 {
		return false, "", ""
	}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(rule.Condition)) {
		case "threshold":
			if !matchPattern(action, rule.EventPattern) {
				continue
			}
			if rule.Threshold <= 1 {
				return true, rule.ID, normalizeSeverity(rule.Severity)
			}
			window := time.Duration(rule.WindowSecond) * time.Second
			if window <= 0 {
				window = 5 * time.Minute
			}
			count, cerr := s.store.CountRecentAlerts(ctx, tenantID, rule.EventPattern, "", "", window)
			if cerr != nil {
				continue
			}
			if count+1 >= rule.Threshold {
				return true, rule.ID, normalizeSeverity(rule.Severity)
			}
		case "expression":
			expr := strings.TrimSpace(rule.Expression)
			if expr == "" {
				continue
			}
			fields := map[string]string{
				"action":      action,
				"severity":    strings.ToLower(firstString(ev["severity"])),
				"actor_id":    firstString(ev["actor_id"], ev["user_id"]),
				"source_ip":   firstString(ev["source_ip"], ev["ip"]),
				"service":     firstString(ev["service"]),
				"target_type": firstString(ev["target_type"], ev["resource_type"]),
				"target_id":   firstString(ev["target_id"], ev["resource_id"]),
			}
			result, eerr := EvaluateExpression(expr, fields)
			if eerr != nil {
				continue
			}
			if result {
				return true, rule.ID, normalizeSeverity(rule.Severity)
			}
		}
	}
	return false, "", ""
}

func categoryForAction(action string) string {
	switch {
	case strings.HasPrefix(action, "auth."), strings.HasPrefix(action, "admin."), strings.HasPrefix(action, "audit."):
		return "security"
	case strings.HasPrefix(action, "policy."), strings.HasPrefix(action, "compliance."), strings.HasPrefix(action, "fips."):
		return "compliance"
	case strings.HasPrefix(action, "key."), strings.HasPrefix(action, "cert."), strings.HasPrefix(action, "payment."), strings.HasPrefix(action, "pqc."):
		return "crypto"
	case strings.HasPrefix(action, "cluster."), strings.HasPrefix(action, "qkd."), strings.HasPrefix(action, "ekm."), strings.HasPrefix(action, "cloud."):
		return "operational"
	default:
		return "system"
	}
}

func titleForAction(action string, ev map[string]interface{}) string {
	target := firstString(ev["target_id"], ev["resource_id"], ev["id"])
	if target == "" {
		target = "n/a"
	}
	return strings.ReplaceAll(strings.Title(strings.ReplaceAll(action, ".", " ")), " ", " ") + ": " + target
}

func descriptionForEvent(ev map[string]interface{}) string {
	if d := firstString(ev["description"], ev["message"]); d != "" {
		return d
	}
	return "Generated from audit event correlation pipeline"
}

func (s *Service) ensureDefaultChannels(ctx context.Context, tenantID string) ([]NotificationChannel, error) {
	existing, err := s.store.ListChannels(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		return filterRetiredChannels(existing), nil
	}
	defaults := []NotificationChannel{
		{TenantID: tenantID, Name: "screen", Enabled: true, Config: map[string]interface{}{"show_info": true}},
		{TenantID: tenantID, Name: "email", Enabled: true, Config: map[string]interface{}{"severity_filter": []string{"critical", "high", "warning"}}},
		{TenantID: tenantID, Name: "slack", Enabled: true, Config: map[string]interface{}{"severity_filter": []string{"critical", "high", "warning"}}},
		{TenantID: tenantID, Name: "teams", Enabled: true, Config: map[string]interface{}{"severity_filter": []string{"critical", "high"}}},
		{TenantID: tenantID, Name: "webhook", Enabled: false, Config: map[string]interface{}{"severity_filter": []string{"critical", "high", "warning"}}},
		{TenantID: tenantID, Name: "siem", Enabled: true, Config: map[string]interface{}{"include_info": true}},
	}
	for _, ch := range defaults {
		_ = s.store.UpsertChannel(ctx, ch)
	}
	seeded, err := s.store.ListChannels(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return filterRetiredChannels(seeded), nil
}

func isRetiredChannel(name string) bool {
	v := strings.ToLower(strings.TrimSpace(name))
	return v == "pager" || v == "pagerduty"
}

func filterRetiredChannels(items []NotificationChannel) []NotificationChannel {
	out := make([]NotificationChannel, 0, len(items))
	for _, it := range items {
		if isRetiredChannel(it.Name) {
			continue
		}
		out = append(out, it)
	}
	return out
}

func (s *Service) dispatchChannels(tenantID string, severity string, action string) ([]NotificationChannel, []string, map[string]string) {
	channels, _ := s.ensureDefaultChannels(context.Background(), tenantID)
	sent := []string{"screen"}
	status := map[string]string{"screen": "delivered"}
	severity = normalizeSeverity(severity)

	for _, ch := range channels {
		if !ch.Enabled {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(ch.Name))
		if name == "screen" || isRetiredChannel(name) {
			continue
		}
		if !channelAllowsSeverity(ch.Config, severity) {
			continue
		}
		if name == "siem" || severityRank(severity) >= severityRank(severityHigh) || name == "email" && severity == severityWarning {
			sent = append(sent, name)
			status[name] = "sent"
		}
	}
	return channels, uniqueStrings(sent), status
}

func channelAllowsSeverity(cfg map[string]interface{}, severity string) bool {
	if cfg == nil {
		return true
	}
	if includeInfo, ok := cfg["include_info"]; ok && !extractBool(includeInfo) && severity == severityInfo {
		return false
	}
	raw, ok := cfg["severity_filter"]
	if !ok {
		return true
	}
	switch x := raw.(type) {
	case []interface{}:
		allowed := []string{}
		for _, v := range x {
			allowed = append(allowed, strings.ToLower(firstString(v)))
		}
		for _, a := range allowed {
			if a == severity {
				return true
			}
		}
		return false
	case []string:
		for _, a := range x {
			if strings.ToLower(strings.TrimSpace(a)) == severity {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func (s *Service) attachIncident(ctx context.Context, tenantID string, title string, severity string, at time.Time) (string, error) {
	incidents, err := s.store.ListIncidents(ctx, tenantID, 100, 0)
	if err == nil {
		for _, it := range incidents {
			if strings.EqualFold(it.Title, title) && it.Status != "closed" {
				_ = s.store.UpdateIncidentCounts(ctx, tenantID, it.ID, severity, at, 1)
				return it.ID, nil
			}
		}
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	item := Incident{
		ID:           newID("inc"),
		TenantID:     tenantID,
		Title:        title,
		Severity:     normalizeSeverity(severity),
		Status:       "open",
		AlertCount:   1,
		FirstAlertAt: at,
		LastAlertAt:  at,
	}
	if err := s.store.CreateIncident(ctx, item); err != nil {
		return "", err
	}
	return item.ID, nil
}

func (s *Service) ListAlerts(ctx context.Context, tenantID string, q AlertQuery) ([]Alert, error) {
	_ = s.SyncAlertsFromAudit(ctx, tenantID, 400)
	return s.store.ListAlerts(ctx, tenantID, q)
}

func (s *Service) GetAlert(ctx context.Context, tenantID string, id string) (Alert, map[string]interface{}, error) {
	item, err := s.store.GetAlert(ctx, tenantID, id)
	if err != nil {
		return Alert{}, nil, err
	}
	if s.audit == nil || strings.TrimSpace(item.AuditEventID) == "" {
		return item, map[string]interface{}{}, nil
	}
	ev, _ := s.audit.GetEvent(ctx, tenantID, item.AuditEventID)
	if ev == nil {
		ev = map[string]interface{}{}
	}
	return item, ev, nil
}

func (s *Service) CountUnread(ctx context.Context, tenantID string) (map[string]int, error) {
	return s.store.CountUnreadBySeverity(ctx, tenantID)
}

func (s *Service) AcknowledgeAlert(ctx context.Context, tenantID string, id string, actor string) error {
	return s.store.UpdateAlertStatus(ctx, tenantID, id, "acknowledged", actor, "")
}

func (s *Service) ResolveAlert(ctx context.Context, tenantID string, id string, actor string, note string) error {
	return s.store.UpdateAlertStatus(ctx, tenantID, id, "resolved", actor, note)
}

func (s *Service) MarkFalsePositive(ctx context.Context, tenantID string, id string, actor string, note string) error {
	return s.store.UpdateAlertStatus(ctx, tenantID, id, "false_positive", actor, note)
}

func (s *Service) EscalateAlert(ctx context.Context, tenantID string, id string, severity string) error {
	if err := s.store.EscalateAlert(ctx, tenantID, id, severity); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.reporting.alert_escalated", tenantID, map[string]interface{}{"alert_id": id, "severity": normalizeSeverity(severity)})
	return nil
}

func (s *Service) BulkAlertStatus(ctx context.Context, tenantID string, ids []string, q AlertQuery, status string, actor string, note string) (int, error) {
	return s.store.BulkUpdateAlertStatus(ctx, tenantID, ids, q, status, actor, note)
}

func (s *Service) ListIncidents(ctx context.Context, tenantID string, limit int, offset int) ([]Incident, error) {
	return s.store.ListIncidents(ctx, tenantID, limit, offset)
}

func (s *Service) GetIncident(ctx context.Context, tenantID string, id string) (Incident, []Alert, error) {
	inc, err := s.store.GetIncident(ctx, tenantID, id)
	if err != nil {
		return Incident{}, nil, err
	}
	alerts, _ := s.store.ListAlerts(ctx, tenantID, AlertQuery{Limit: 500})
	items := []Alert{}
	for _, a := range alerts {
		if a.IncidentID == id {
			items = append(items, a)
		}
	}
	return inc, items, nil
}

func (s *Service) UpdateIncidentStatus(ctx context.Context, tenantID string, id string, status string, notes string) error {
	return s.store.UpdateIncidentStatus(ctx, tenantID, id, status, notes)
}

func (s *Service) AssignIncident(ctx context.Context, tenantID string, id string, user string) error {
	return s.store.AssignIncident(ctx, tenantID, id, user)
}

func (s *Service) ListRules(ctx context.Context, tenantID string) ([]AlertRule, error) {
	return s.store.ListRules(ctx, tenantID)
}

func (s *Service) CreateRule(ctx context.Context, tenantID string, item AlertRule) (AlertRule, error) {
	item.ID = newID("rule")
	item.TenantID = tenantID
	item.Severity = normalizeSeverity(item.Severity)
	item.Enabled = true
	if strings.EqualFold(strings.TrimSpace(item.Condition), "expression") {
		if err := ValidateExpression(item.Expression); err != nil {
			return AlertRule{}, newServiceError(400, "bad_request", "invalid expression: "+err.Error())
		}
	}
	if err := s.store.CreateRule(ctx, item); err != nil {
		return AlertRule{}, err
	}
	_ = s.publishAudit(ctx, "audit.reporting.rule_created", tenantID, map[string]interface{}{"rule_id": item.ID, "name": item.Name})
	return item, nil
}

func (s *Service) UpdateRule(ctx context.Context, tenantID string, id string, item AlertRule) error {
	item.ID = id
	item.TenantID = tenantID
	item.Severity = normalizeSeverity(item.Severity)
	if strings.EqualFold(strings.TrimSpace(item.Condition), "expression") {
		if err := ValidateExpression(item.Expression); err != nil {
			return newServiceError(400, "bad_request", "invalid expression: "+err.Error())
		}
	}
	if err := s.store.UpdateRule(ctx, item); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.reporting.rule_updated", tenantID, map[string]interface{}{"rule_id": id})
	return nil
}

func (s *Service) DeleteRule(ctx context.Context, tenantID string, id string) error {
	if err := s.store.DeleteRule(ctx, tenantID, id); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.reporting.rule_deleted", tenantID, map[string]interface{}{"rule_id": id})
	return nil
}

func (s *Service) GetSeverityConfig(ctx context.Context, tenantID string) (map[string]string, error) {
	out := severityDefaults()
	overrides, err := s.store.ListSeverityOverrides(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, o := range overrides {
		out[strings.ToLower(strings.TrimSpace(o.AuditAction))] = normalizeSeverity(o.Severity)
	}
	return out, nil
}

func (s *Service) UpdateSeverityConfig(ctx context.Context, tenantID string, updates map[string]string) error {
	for action, sev := range updates {
		if strings.TrimSpace(action) == "" {
			continue
		}
		if err := s.store.UpsertSeverityOverride(ctx, SeverityOverride{TenantID: tenantID, AuditAction: strings.ToLower(strings.TrimSpace(action)), Severity: normalizeSeverity(sev)}); err != nil {
			return err
		}
	}
	_ = s.publishAudit(ctx, "audit.reporting.severity_config_updated", tenantID, map[string]interface{}{"count": len(updates)})
	return nil
}

func (s *Service) ListChannels(ctx context.Context, tenantID string) ([]NotificationChannel, error) {
	return s.ensureDefaultChannels(ctx, tenantID)
}

func (s *Service) UpdateChannels(ctx context.Context, tenantID string, items []NotificationChannel) error {
	accepted := 0
	for _, it := range items {
		if isRetiredChannel(it.Name) {
			continue
		}
		it.TenantID = tenantID
		if err := s.store.UpsertChannel(ctx, it); err != nil {
			return err
		}
		accepted++
	}
	_ = s.publishAudit(ctx, "audit.reporting.channels_updated", tenantID, map[string]interface{}{"count": accepted})
	return nil
}

func (s *Service) Templates() []ReportTemplate {
	return []ReportTemplate{
		{ID: "key_generation", Name: "Key Generation Report", Description: "Created keys by algorithm, tenant, and actor activity.", Formats: []string{"pdf", "csv", "json"}},
		{ID: "key_rotation", Name: "Key Rotation Report", Description: "Rotation operations, recency, and rotation coverage.", Formats: []string{"pdf", "csv", "json"}},
		{ID: "kms_operations", Name: "KMS Operations Report", Description: "Cross-service cryptographic operations and audit activity.", Formats: []string{"pdf", "csv", "json"}},
		{ID: "hyok_activity", Name: "HYOK Activity Report", Description: "HYOK proxy operations and event timeline.", Formats: []string{"pdf", "csv", "json"}},
		{ID: "byok_activity", Name: "BYOK Activity Report", Description: "Cloud key sync/import/rotation operations by connector.", Formats: []string{"pdf", "csv", "json"}},
		{ID: "certificate_lifecycle", Name: "Certificate Lifecycle Report", Description: "Issue, renew, revoke, and expiry-related certificate events.", Formats: []string{"pdf", "csv", "json"}},
		{ID: "compliance_audit", Name: "Compliance Audit Report", Description: "Framework-specific evidence-backed posture report.", Formats: []string{"pdf", "json"}},
		{ID: "posture_summary", Name: "Posture Summary", Description: "Posture trends and gap summary.", Formats: []string{"pdf", "json"}},
		{ID: "evidence_pack", Name: "Evidence Pack", Description: "One-click audit package with posture findings, actions, approvals, alerts, and timestamps.", Formats: []string{"pdf", "json"}},
		{ID: "alert_summary", Name: "Alert Summary", Description: "Severity volume and MTTR metrics.", Formats: []string{"pdf", "csv", "json"}},
		{ID: "custom", Name: "Custom Report", Description: "User-defined report template and filters.", Formats: []string{"pdf", "csv", "json"}},
	}
}

func (s *Service) GenerateReport(ctx context.Context, tenantID string, templateID string, format string, requestedBy string, filters map[string]interface{}) (ReportJob, error) {
	templateID = strings.ToLower(strings.TrimSpace(templateID))
	format = strings.ToLower(strings.TrimSpace(format))
	if templateID == "" {
		return ReportJob{}, newServiceError(400, "bad_request", "template_id is required")
	}
	if format == "" {
		format = "pdf"
	}
	job := ReportJob{
		ID:          newID("rjob"),
		TenantID:    tenantID,
		TemplateID:  templateID,
		Format:      format,
		Status:      "queued",
		Filters:     filters,
		RequestedBy: defaultString(requestedBy, "system"),
	}
	if err := s.store.CreateReportJob(ctx, job); err != nil {
		return ReportJob{}, err
	}
	go s.processReportJob(job)
	_ = s.publishAudit(ctx, "audit.reporting.report_requested", tenantID, map[string]interface{}{"job_id": job.ID, "template_id": templateID, "format": format})
	return job, nil
}

func (s *Service) processReportJob(job ReportJob) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	job.Status = "running"
	_ = s.store.UpdateReportJob(ctx, job)
	content, contentType, err := s.renderReport(ctx, job)
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
		job.CompletedAt = time.Now().UTC()
		_ = s.store.UpdateReportJob(ctx, job)
		return
	}
	job.Status = "completed"
	job.ResultContent = content
	job.ResultContentType = contentType
	job.CompletedAt = time.Now().UTC()
	_ = s.store.UpdateReportJob(ctx, job)
}

func (s *Service) renderReport(ctx context.Context, job ReportJob) (string, string, error) {
	alerts, _ := s.store.ListAlerts(ctx, job.TenantID, AlertQuery{Limit: 2000})
	incidents, _ := s.store.ListIncidents(ctx, job.TenantID, 500, 0)
	posture := map[string]interface{}{}
	if s.compliance != nil {
		posture, _ = s.compliance.GetPosture(ctx, job.TenantID)
	}
	if normalizeTemplateID(job.TemplateID) == "evidence_pack" {
		return s.renderEvidencePack(ctx, job, alerts, incidents, posture)
	}
	selectedAlerts := filterAlertsByTemplate(alerts, job.TemplateID)
	severityCounts := map[string]int{
		severityCritical: 0,
		severityHigh:     0,
		severityWarning:  0,
		severityInfo:     0,
	}
	actionCounts := map[string]int{}
	dailyTrend := map[string]int{}
	for _, it := range selectedAlerts {
		sev := normalizeSeverity(it.Severity)
		severityCounts[sev]++
		actionCounts[it.AuditAction]++
		day := it.CreatedAt.UTC().Format("2006-01-02")
		dailyTrend[day]++
	}

	scope := reportScopeLabel(job.TemplateID)
	topActions := topKV(actionCounts, 15)
	payload := map[string]interface{}{
		"job_id":         job.ID,
		"template_id":    job.TemplateID,
		"tenant_id":      job.TenantID,
		"generated_at":   time.Now().UTC(),
		"scope":          scope,
		"alert_count":    len(selectedAlerts),
		"incident_count": len(incidents),
		"posture":        posture,
		"summary": map[string]interface{}{
			"critical": severityCounts[severityCritical],
			"high":     severityCounts[severityHigh],
			"warning":  severityCounts[severityWarning],
			"info":     severityCounts[severityInfo],
		},
		"top_actions": topActions,
		"daily_trend": dailyTrend,
		"alerts":      selectedAlerts,
		"incidents":   incidents,
	}
	switch strings.ToLower(job.Format) {
	case "json":
		raw, _ := json.MarshalIndent(payload, "", "  ")
		return string(raw), "application/json", nil
	case "csv":
		buf := &bytes.Buffer{}
		w := csv.NewWriter(buf)
		_ = w.Write([]string{"alert_id", "severity", "status", "audit_action", "service", "actor_id", "target_id", "created_at"})
		for _, a := range selectedAlerts {
			_ = w.Write([]string{a.ID, a.Severity, a.Status, a.AuditAction, a.Service, a.ActorID, a.TargetID, a.CreatedAt.Format(time.RFC3339)})
		}
		w.Flush()
		return buf.String(), "text/csv", nil
	case "pdf":
		lines := []string{
			"Vecta KMS Report",
			"Template: " + job.TemplateID,
			"Scope: " + scope,
			"Tenant: " + job.TenantID,
			"Generated: " + time.Now().UTC().Format(time.RFC3339),
			fmt.Sprintf("Alerts: %d", len(selectedAlerts)),
			fmt.Sprintf("Incidents: %d", len(incidents)),
			fmt.Sprintf("Critical/High/Warning/Info: %d / %d / %d / %d",
				severityCounts[severityCritical],
				severityCounts[severityHigh],
				severityCounts[severityWarning],
				severityCounts[severityInfo],
			),
		}
		if score := firstString(posture["overall_score"]); score != "" {
			lines = append(lines, "Posture score: "+score)
		}
		lines = append(lines, "", "Top Actions")
		for _, entry := range topActions {
			lines = append(lines, fmt.Sprintf("- %s: %d", entry.Key, entry.Count))
		}
		lines = append(lines, "", "Recent Events")
		for idx, it := range selectedAlerts {
			if idx >= 300 {
				lines = append(lines, fmt.Sprintf("... %d additional events omitted ...", len(selectedAlerts)-idx))
				break
			}
			lines = append(lines, fmt.Sprintf(
				"%04d. %s | %s | %s | %s | %s",
				idx+1,
				it.CreatedAt.UTC().Format(time.RFC3339),
				defaultString(it.AuditAction, "-"),
				defaultString(it.Severity, "-"),
				defaultString(it.Status, "-"),
				defaultString(it.TargetID, "-"),
			))
		}
		pdf, err := pdfutil.RenderTextPDF("Vecta KMS Report", lines)
		if err != nil {
			return "", "", err
		}
		return encodeBase64(pdf), "application/pdf", nil
	default:
		return "", "", newServiceError(400, "bad_request", "unsupported report format")
	}
}

func (s *Service) renderEvidencePack(ctx context.Context, job ReportJob, alerts []Alert, incidents []Incident, posture map[string]interface{}) (string, string, error) {
	postureFindings := []map[string]interface{}{}
	postureActions := []map[string]interface{}{}
	if s.posture != nil {
		postureFindings, _ = s.posture.ListFindings(ctx, job.TenantID, 250)
		postureActions, _ = s.posture.ListActions(ctx, job.TenantID, 250)
	}
	mttr, _ := s.MTTRStats(ctx, job.TenantID)
	mttd, _ := s.MTTDStats(ctx, job.TenantID)
	payload := map[string]interface{}{
		"job_id":           job.ID,
		"template_id":      job.TemplateID,
		"tenant_scope":     job.TenantID,
		"generated_at":     time.Now().UTC(),
		"posture":          posture,
		"alerts":           alerts,
		"incidents":        incidents,
		"posture_findings": postureFindings,
		"posture_actions":  postureActions,
		"approval_actions": filterApprovalActions(postureActions),
		"timings": map[string]interface{}{
			"mttr_minutes": mttr,
			"mttd_minutes": mttd,
		},
		"summary": map[string]interface{}{
			"alert_count":           len(alerts),
			"incident_count":        len(incidents),
			"posture_finding_count": len(postureFindings),
			"posture_action_count":  len(postureActions),
			"approval_action_count": len(filterApprovalActions(postureActions)),
		},
	}
	switch strings.ToLower(job.Format) {
	case "json":
		raw, _ := json.MarshalIndent(payload, "", "  ")
		return string(raw), "application/json", nil
	case "pdf":
		lines := []string{
			"Vecta KMS Evidence Pack",
			"Tenant Scope: " + job.TenantID,
			"Generated: " + time.Now().UTC().Format(time.RFC3339),
			fmt.Sprintf("Posture findings: %d", len(postureFindings)),
			fmt.Sprintf("Posture actions: %d", len(postureActions)),
			fmt.Sprintf("Approval-required actions: %d", len(filterApprovalActions(postureActions))),
			fmt.Sprintf("Alerts: %d", len(alerts)),
			fmt.Sprintf("Incidents: %d", len(incidents)),
			"",
			"Posture Findings",
		}
		for idx, item := range postureFindings {
			if idx >= 80 {
				lines = append(lines, fmt.Sprintf("... %d additional findings omitted ...", len(postureFindings)-idx))
				break
			}
			lines = append(lines, fmt.Sprintf("%04d. %s | %s | %s", idx+1, firstString(item["title"]), firstString(item["severity"]), firstString(item["status"])))
		}
		lines = append(lines, "", "Remediation Actions")
		for idx, item := range postureActions {
			if idx >= 80 {
				lines = append(lines, fmt.Sprintf("... %d additional actions omitted ...", len(postureActions)-idx))
				break
			}
			lines = append(lines, fmt.Sprintf("%04d. %s | %s | approval=%s", idx+1, firstString(item["action_type"]), firstString(item["status"]), firstString(item["approval_required"])))
		}
		lines = append(lines, "", "Evidence Timing")
		for sev, value := range mttd {
			lines = append(lines, fmt.Sprintf("MTTD %s: %.1f minutes", sev, value))
		}
		for sev, value := range mttr {
			lines = append(lines, fmt.Sprintf("MTTR %s: %.1f minutes", sev, value))
		}
		pdf, err := pdfutil.RenderTextPDF("Vecta KMS Evidence Pack", lines)
		if err != nil {
			return "", "", err
		}
		return encodeBase64(pdf), "application/pdf", nil
	default:
		return "", "", newServiceError(400, "bad_request", "unsupported report format")
	}
}

func reportScopeLabel(templateID string) string {
	switch normalizeTemplateID(templateID) {
	case "key_generation":
		return "Key generation events"
	case "key_rotation":
		return "Key rotation events"
	case "kms_operations":
		return "KMS cryptographic operations"
	case "hyok_activity":
		return "HYOK operations"
	case "byok_activity":
		return "BYOK cloud connector operations"
	case "certificate_lifecycle":
		return "Certificate lifecycle operations"
	case "evidence_pack":
		return "Audit-ready evidence pack"
	default:
		return "All reporting events"
	}
}

func normalizeTemplateID(templateID string) string {
	return strings.ToLower(strings.TrimSpace(templateID))
}

func filterAlertsByTemplate(alerts []Alert, templateID string) []Alert {
	tid := normalizeTemplateID(templateID)
	if tid == "" || tid == "custom" || tid == "alert_summary" || tid == "compliance_audit" || tid == "posture_summary" || tid == "evidence_pack" {
		return alerts
	}
	out := make([]Alert, 0, len(alerts))
	for _, it := range alerts {
		action := strings.ToLower(strings.TrimSpace(it.AuditAction))
		if action == "" {
			continue
		}
		if matchesReportTemplate(tid, action) {
			out = append(out, it)
		}
	}
	return out
}

func matchesReportTemplate(templateID string, action string) bool {
	switch templateID {
	case "key_generation":
		return action == "key.created" || strings.HasPrefix(action, "key.create")
	case "key_rotation":
		return action == "key.rotated" || strings.HasPrefix(action, "key.rotate")
	case "kms_operations":
		return strings.HasPrefix(action, "key.") || strings.HasPrefix(action, "crypto.") || strings.HasPrefix(action, "payment.") || strings.HasPrefix(action, "policy.")
	case "hyok_activity":
		return strings.HasPrefix(action, "hyok.")
	case "byok_activity":
		return strings.HasPrefix(action, "cloud.") || strings.Contains(action, "byok")
	case "certificate_lifecycle":
		return strings.HasPrefix(action, "cert.")
	default:
		return true
	}
}

func encodeBase64(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

func (s *Service) GetReportJob(ctx context.Context, tenantID string, id string) (ReportJob, error) {
	return s.store.GetReportJob(ctx, tenantID, id)
}

func (s *Service) ListReportJobs(ctx context.Context, tenantID string, limit int, offset int) ([]ReportJob, error) {
	return s.store.ListReportJobs(ctx, tenantID, limit, offset)
}

func (s *Service) DeleteReportJob(ctx context.Context, tenantID string, id string, actor string) error {
	tenantID = strings.TrimSpace(tenantID)
	id = strings.TrimSpace(id)
	if tenantID == "" {
		return newServiceError(400, "bad_request", "tenant_id is required")
	}
	if id == "" {
		return newServiceError(400, "bad_request", "report job id is required")
	}
	job, err := s.store.GetReportJob(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := s.store.DeleteReportJob(ctx, tenantID, id); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.reporting.report_deleted", tenantID, map[string]interface{}{
		"job_id":       job.ID,
		"template_id":  job.TemplateID,
		"format":       job.Format,
		"requested_by": job.RequestedBy,
		"actor":        defaultString(actor, "system"),
		"severity":     "info",
		"audit_level":  "info",
	})
	return nil
}

func (s *Service) ScheduleReport(ctx context.Context, tenantID string, name string, templateID string, format string, schedule string, recipients []string, filters map[string]interface{}) (ScheduledReport, error) {
	item := ScheduledReport{
		ID:         newID("sched"),
		TenantID:   tenantID,
		Name:       defaultString(name, "scheduled-report"),
		TemplateID: strings.ToLower(strings.TrimSpace(templateID)),
		Format:     strings.ToLower(strings.TrimSpace(format)),
		Schedule:   strings.ToLower(strings.TrimSpace(schedule)),
		Recipients: uniqueStrings(recipients),
		Filters:    filters,
		Enabled:    true,
		NextRunAt:  nextRunTime(time.Now().UTC(), schedule),
	}
	if item.TemplateID == "" {
		item.TemplateID = "alert_summary"
	}
	if item.Format == "" {
		item.Format = "pdf"
	}
	if item.Schedule == "" {
		item.Schedule = "daily"
	}
	if err := s.store.CreateScheduledReport(ctx, item); err != nil {
		return ScheduledReport{}, err
	}
	_ = s.publishAudit(ctx, "audit.reporting.report_scheduled", tenantID, map[string]interface{}{"schedule_id": item.ID})
	return item, nil
}

func (s *Service) ListScheduledReports(ctx context.Context, tenantID string) ([]ScheduledReport, error) {
	return s.store.ListScheduledReports(ctx, tenantID)
}

func (s *Service) CaptureErrorTelemetry(ctx context.Context, tenantID string, item ErrorTelemetryEvent) (ErrorTelemetryEvent, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return ErrorTelemetryEvent{}, newServiceError(400, "bad_request", "tenant_id is required")
	}
	msg := strings.TrimSpace(item.Message)
	if msg == "" {
		return ErrorTelemetryEvent{}, newServiceError(400, "bad_request", "message is required")
	}
	if len(msg) > 4096 {
		msg = msg[:4096]
	}
	stack := strings.TrimSpace(item.StackTrace)
	if len(stack) > 32768 {
		stack = stack[:32768]
	}
	normalized := ErrorTelemetryEvent{
		ID:          newID("tel"),
		TenantID:    tenantID,
		Source:      strings.ToLower(defaultString(item.Source, "backend")),
		Service:     strings.ToLower(defaultString(item.Service, "unknown")),
		Component:   strings.ToLower(strings.TrimSpace(item.Component)),
		Level:       normalizeTelemetryLevel(item.Level),
		Message:     msg,
		StackTrace:  stack,
		Context:     item.Context,
		Fingerprint: strings.TrimSpace(item.Fingerprint),
		RequestID:   strings.TrimSpace(item.RequestID),
		ReleaseTag:  strings.TrimSpace(item.ReleaseTag),
		BuildVer:    strings.TrimSpace(item.BuildVer),
		CreatedAt:   time.Now().UTC(),
	}
	if normalized.Context == nil {
		normalized.Context = map[string]interface{}{}
	}
	if err := s.store.CreateErrorTelemetry(ctx, normalized); err != nil {
		return ErrorTelemetryEvent{}, err
	}
	return normalized, nil
}

func (s *Service) ListErrorTelemetry(ctx context.Context, tenantID string, q ErrorTelemetryQuery) ([]ErrorTelemetryEvent, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, newServiceError(400, "bad_request", "tenant_id is required")
	}
	return s.store.ListErrorTelemetry(ctx, tenantID, q)
}

func (s *Service) PurgeErrorTelemetry(ctx context.Context) error {
	if s.telemetryRetention <= 0 {
		return nil
	}
	cutoff := time.Now().UTC().Add(-s.telemetryRetention)
	_, err := s.store.PurgeErrorTelemetryBefore(ctx, cutoff, s.telemetryPurgeBatch)
	return err
}

func (s *Service) RunDueSchedules(ctx context.Context) error {
	items, err := s.store.ListDueScheduledReports(ctx, time.Now().UTC(), 200)
	if err != nil {
		return err
	}
	for _, item := range items {
		_, _ = s.GenerateReport(ctx, item.TenantID, item.TemplateID, item.Format, "scheduler", item.Filters)
		now := time.Now().UTC()
		next := nextRunTime(now, item.Schedule)
		_ = s.store.UpdateScheduledReportRun(ctx, item.TenantID, item.ID, now, next)
	}
	return nil
}

func nextRunTime(now time.Time, schedule string) time.Time {
	switch strings.ToLower(strings.TrimSpace(schedule)) {
	case "hourly":
		return now.Add(time.Hour)
	case "weekly":
		return now.Add(7 * 24 * time.Hour)
	default:
		return now.Add(24 * time.Hour)
	}
}

func (s *Service) AlertStats(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	items, err := s.store.ListAlerts(ctx, tenantID, AlertQuery{Limit: 5000})
	if err != nil {
		return nil, err
	}
	bySeverity := map[string]int{severityCritical: 0, severityHigh: 0, severityWarning: 0, severityInfo: 0}
	byStatus := map[string]int{}
	byAction := map[string]int{}
	dayTrend := map[string]int{}
	for _, it := range items {
		bySeverity[normalizeSeverity(it.Severity)]++
		byStatus[it.Status]++
		byAction[it.AuditAction]++
		day := it.CreatedAt.UTC().Format("2006-01-02")
		dayTrend[day]++
	}
	return map[string]interface{}{
		"total":        len(items),
		"by_severity":  bySeverity,
		"by_status":    byStatus,
		"top_actions":  topKV(byAction, 10),
		"daily_trend":  dayTrend,
		"generated_at": time.Now().UTC(),
	}, nil
}

func (s *Service) MTTRStats(ctx context.Context, tenantID string) (map[string]float64, error) {
	items, err := s.store.ListAlerts(ctx, tenantID, AlertQuery{Limit: 5000})
	if err != nil {
		return nil, err
	}
	type agg struct {
		sum float64
		n   int
	}
	acc := map[string]agg{}
	for _, it := range items {
		if !it.ResolvedAt.IsZero() && !it.CreatedAt.IsZero() {
			d := it.ResolvedAt.Sub(it.CreatedAt).Minutes()
			sev := normalizeSeverity(it.Severity)
			cur := acc[sev]
			cur.sum += d
			cur.n++
			acc[sev] = cur
		}
	}
	out := map[string]float64{}
	for sev, a := range acc {
		if a.n > 0 {
			out[sev] = a.sum / float64(a.n)
		}
	}
	return out, nil
}

func (s *Service) MTTDStats(ctx context.Context, tenantID string) (map[string]float64, error) {
	items, err := s.store.ListAlerts(ctx, tenantID, AlertQuery{Limit: 5000})
	if err != nil {
		return nil, err
	}
	type agg struct {
		sum float64
		n   int
	}
	acc := map[string]agg{}
	for _, it := range items {
		if s.audit == nil || strings.TrimSpace(it.AuditEventID) == "" || it.CreatedAt.IsZero() {
			continue
		}
		ev, err := s.audit.GetEvent(ctx, tenantID, it.AuditEventID)
		if err != nil {
			continue
		}
		ts := parseTimeString(firstString(ev["timestamp"], ev["created_at"]))
		if ts.IsZero() || it.CreatedAt.Before(ts) {
			continue
		}
		sev := normalizeSeverity(it.Severity)
		cur := acc[sev]
		cur.sum += it.CreatedAt.Sub(ts).Minutes()
		cur.n++
		acc[sev] = cur
	}
	out := map[string]float64{}
	for sev, a := range acc {
		if a.n > 0 {
			out[sev] = a.sum / float64(a.n)
		}
	}
	return out, nil
}

func (s *Service) TopSources(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	items, err := s.store.ListAlerts(ctx, tenantID, AlertQuery{Limit: 5000})
	if err != nil {
		return nil, err
	}
	actors := map[string]int{}
	ips := map[string]int{}
	services := map[string]int{}
	for _, it := range items {
		if it.ActorID != "" {
			actors[it.ActorID]++
		}
		if it.SourceIP != "" {
			ips[it.SourceIP]++
		}
		if it.Service != "" {
			services[it.Service]++
		}
	}
	return map[string]interface{}{
		"actors":   topKV(actors, 10),
		"ips":      topKV(ips, 10),
		"services": topKV(services, 10),
	}, nil
}

func filterApprovalActions(actions []map[string]interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0)
	for _, item := range actions {
		if !extractBool(item["approval_required"]) {
			continue
		}
		out = append(out, item)
	}
	return out
}

type kv struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func topKV(m map[string]int, n int) []kv {
	items := make([]kv, 0, len(m))
	for k, v := range m {
		items = append(items, kv{Key: k, Count: v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	if len(items) > n {
		items = items[:n]
	}
	return items
}

func (s *Service) publishAudit(ctx context.Context, subject string, tenantID string, data map[string]interface{}) error {
	if s.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"service":   "reporting",
		"action":    subject,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return s.events.Publish(ctx, subject, raw)
}
