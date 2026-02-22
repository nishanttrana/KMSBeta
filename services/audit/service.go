package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	pkgevents "vecta-kms/pkg/events"
)

type Service struct {
	store     Store
	cfg       AuditConfig
	wal       *WALBuffer
	publisher EventPublisher
}

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

func NewService(store Store, cfg AuditConfig, wal *WALBuffer, publisher EventPublisher) *Service {
	return &Service{
		store:     store,
		cfg:       cfg,
		wal:       wal,
		publisher: publisher,
	}
}

func (s *Service) PublishAudit(ctx context.Context, subject string, event AuditEvent) (bool, error) {
	if s.publisher == nil {
		if s.cfg.FailClosed {
			return false, errors.New("publisher unavailable")
		}
		return true, s.wal.Append("publish", subject, mustJSON(event))
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return false, err
	}
	if err := s.publisher.Publish(ctx, subject, payload); err != nil {
		if s.cfg.FailClosed {
			return false, err
		}
		if walErr := s.wal.Append("publish", subject, payload); walErr != nil {
			return false, walErr
		}
		return true, nil
	}
	return false, nil
}

func (s *Service) HandleNATSMessage(ctx context.Context, msg *nats.Msg) error {
	event, err := parseIncomingEvent(msg.Subject, msg.Data)
	if err != nil {
		return err
	}
	_, _, err = s.ProcessEvent(ctx, event)
	if err == nil {
		return nil
	}
	if s.cfg.FailClosed {
		return err
	}
	if walErr := s.wal.Append("ingest", msg.Subject, msg.Data); walErr != nil {
		return walErr
	}
	return nil
}

func (s *Service) ProcessEvent(ctx context.Context, event AuditEvent) (AuditEvent, Alert, error) {
	enriched, alert, err := s.classifyAndCorrelate(ctx, event)
	if err != nil {
		return AuditEvent{}, Alert{}, err
	}
	dispatch := dispatchPlan(alert.Severity)
	alert.DispatchedChannels = dispatch.Channels
	alert.DispatchStatus = dispatch.Status

	evt, al, err := s.store.PersistEventAndAlert(
		ctx,
		enriched,
		alert,
		s.cfg.DedupWindowSeconds,
		s.cfg.EscalationThreshold,
		time.Duration(s.cfg.EscalationMinutes)*time.Minute,
	)
	if err != nil {
		return AuditEvent{}, Alert{}, err
	}
	return evt, al, nil
}

func (s *Service) classifyAndCorrelate(ctx context.Context, event AuditEvent) (AuditEvent, Alert, error) {
	if event.ID == "" {
		event.ID = newID("evt")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.Result == "" {
		event.Result = "success"
	}
	if event.ActorID == "" {
		event.ActorID = "system"
	}
	if event.ActorType == "" {
		event.ActorType = "system"
	}
	if event.Service == "" {
		event.Service = serviceFromAction(event.Action)
	}
	if event.CorrelationID == "" {
		switch {
		case event.SessionID != "":
			event.CorrelationID = "sess:" + event.SessionID
		case event.TargetID != "":
			event.CorrelationID = "target:" + event.TargetID
		default:
			event.CorrelationID = "evt:" + event.ID
		}
	}

	severity := classifySeverity(event.Action, event.Result)
	category := classifyCategory(event.Action)
	risk := baseRisk(severity, event.Action)
	if event.RiskScore > risk {
		risk = event.RiskScore
	}

	distinctIPs, err := s.store.CountDistinctIPsForTarget(ctx, event.TenantID, event.TargetID, time.Now().UTC().Add(-5*time.Minute))
	if err == nil && distinctIPs >= 3 {
		risk = max(risk, 85)
		event.Tags = appendIfMissing(event.Tags, "anomaly.ip_spread")
	}
	event.RiskScore = risk

	title := defaultAlertTitle(event.Action, event.TargetID)
	rules, err := s.store.ListRules(ctx, event.TenantID)
	if err == nil {
		for _, r := range rules {
			if ruleMatches(r, event) {
				severity = strings.ToUpper(strings.TrimSpace(r.Severity))
				if strings.TrimSpace(r.Title) != "" {
					title = renderRuleTitle(r.Title, event)
				}
				break
			}
		}
	}
	alert := Alert{
		ID:            newID("alr"),
		TenantID:      event.TenantID,
		AuditEventID:  event.ID,
		Severity:      severity,
		Category:      category,
		Title:         title,
		Description:   defaultAlertDescription(event),
		SourceService: event.Service,
		ActorID:       event.ActorID,
		TargetID:      event.TargetID,
		RiskScore:     risk,
		Status:        "open",
		DedupKey:      dedupKey(event, s.cfg.DedupWindowSeconds),
	}
	return event, alert, nil
}

func (s *Service) StartSubscriber(ctx context.Context, sub *pkgevents.Subscriber) (*nats.Subscription, error) {
	return sub.SubscribeDurable("audit.>", "kms-audit", func(msg *nats.Msg) {
		if err := s.HandleNATSMessage(ctx, msg); err != nil {
			if s.cfg.FailClosed {
				_ = msg.Nak()
				return
			}
		}
		_ = msg.Ack()
	})
}

func (s *Service) DrainWAL(ctx context.Context) error {
	return s.wal.Drain(func(rec WALRecord, payload []byte) error {
		switch rec.Type {
		case "publish":
			if s.publisher == nil {
				return errors.New("publisher unavailable")
			}
			return s.publisher.Publish(ctx, rec.Subject, payload)
		case "ingest":
			event, err := parseIncomingEvent(rec.Subject, payload)
			if err != nil {
				return err
			}
			_, _, err = s.ProcessEvent(ctx, event)
			return err
		default:
			return nil
		}
	})
}

func (s *Service) VerifyChain(ctx context.Context, tenantID string) (bool, []map[string]interface{}, error) {
	ok, breaks, err := s.store.VerifyChain(ctx, tenantID)
	if err != nil {
		return false, nil, err
	}
	if !ok {
		_, _, _ = s.ProcessEvent(ctx, AuditEvent{
			TenantID:  tenantID,
			Service:   "audit",
			Action:    "audit.audit.chain_broken",
			ActorID:   "system",
			ActorType: "system",
			Result:    "failure",
			Details: map[string]interface{}{
				"breaks": breaks,
			},
		})
	}
	return ok, breaks, nil
}

func parseIncomingEvent(subject string, payload []byte) (AuditEvent, error) {
	var in map[string]interface{}
	if err := json.Unmarshal(payload, &in); err != nil {
		return AuditEvent{}, err
	}
	event := AuditEvent{
		ID:            str(in["id"]),
		TenantID:      str(in["tenant_id"]),
		Service:       str(in["service"]),
		Action:        str(in["action"]),
		ActorID:       str(in["actor_id"]),
		ActorType:     str(in["actor_type"]),
		TargetType:    str(in["target_type"]),
		TargetID:      str(in["target_id"]),
		Method:        str(in["method"]),
		Endpoint:      str(in["endpoint"]),
		SourceIP:      str(in["source_ip"]),
		UserAgent:     str(in["user_agent"]),
		RequestHash:   str(in["request_hash"]),
		CorrelationID: str(in["correlation_id"]),
		ParentEventID: str(in["parent_event_id"]),
		SessionID:     str(in["session_id"]),
		Result:        str(in["result"]),
		StatusCode:    asInt(in["status_code"]),
		ErrorMessage:  str(in["error_message"]),
		DurationMS:    asFloat(in["duration_ms"]),
		FIPSCompliant: asBool(in["fips_compliant"], true),
		ApprovalID:    str(in["approval_id"]),
		RiskScore:     asInt(in["risk_score"]),
		NodeID:        str(in["node_id"]),
		Details:       map[string]interface{}{},
	}
	if rawTS := str(in["timestamp"]); rawTS != "" {
		if ts, err := time.Parse(time.RFC3339Nano, rawTS); err == nil {
			event.Timestamp = ts
		}
	}
	if event.Action == "" {
		event.Action = subject
	}
	if event.Service == "" {
		event.Service = serviceFromAction(event.Action)
	}
	if details, ok := in["details"].(map[string]interface{}); ok {
		event.Details = details
	} else if data, ok := in["data"].(map[string]interface{}); ok {
		event.Details = data
	}
	if tags, ok := in["tags"].([]interface{}); ok {
		for _, t := range tags {
			event.Tags = append(event.Tags, str(t))
		}
	}
	if event.TenantID == "" {
		return AuditEvent{}, errors.New("tenant_id is required")
	}
	return event, nil
}

func classifySeverity(action string, result string) string {
	a := strings.ToLower(action)
	if meta, ok := auditEventCatalog[a]; ok && meta.Severity != "" {
		return strings.ToUpper(meta.Severity)
	}
	switch {
	case strings.Contains(a, "chain_broken"),
		strings.Contains(a, "fips.violation_blocked"),
		strings.Contains(a, "key.compromised"),
		strings.Contains(a, "key.destroyed"),
		strings.Contains(a, "fde.unlock_failed"),
		strings.Contains(a, "integrity_check_failed"):
		return "CRITICAL"
	case strings.Contains(a, "key.exported"),
		strings.Contains(a, "policy.violated"),
		strings.Contains(a, "auth.login_failed"),
		strings.Contains(a, "auth.mfa_failed"),
		strings.Contains(a, "cluster.node_failed"),
		strings.Contains(a, "fips.mode_changed"):
		return "HIGH"
	case strings.Contains(a, "rotated"),
		strings.Contains(a, "deactivated"),
		strings.Contains(a, "approval_required"),
		strings.Contains(a, "ops_limit_reached"),
		strings.Contains(a, "config_changed"),
		strings.Contains(a, "user_created"),
		strings.Contains(a, "apikey_created"):
		return "MEDIUM"
	case strings.Contains(a, "created"),
		strings.Contains(a, "encrypt"),
		strings.Contains(a, "decrypt"),
		strings.Contains(a, "sign"),
		strings.Contains(a, "verify"),
		strings.Contains(a, "tokenize"):
		return "LOW"
	default:
		if strings.EqualFold(result, "failure") || strings.EqualFold(result, "denied") {
			return "HIGH"
		}
		return "INFO"
	}
}

func classifyCategory(action string) string {
	a := strings.ToLower(action)
	if meta, ok := auditEventCatalog[a]; ok && meta.Category != "" {
		return meta.Category
	}
	parts := strings.Split(a, ".")
	if len(parts) > 1 {
		return parts[1]
	}
	return "audit"
}

func baseRisk(severity string, action string) int {
	switch severity {
	case "CRITICAL":
		return 95
	case "HIGH":
		return 70
	case "MEDIUM":
		return 45
	case "LOW":
		return 20
	default:
		return 5
	}
}

func dispatchPlan(severity string) DispatchPlan {
	s := strings.ToUpper(severity)
	var channels []string
	switch s {
	case "CRITICAL":
		channels = []string{"email", "sms", "pagerduty", "siem", "dashboard", "webhook"}
	case "HIGH":
		channels = []string{"email", "siem", "dashboard", "webhook"}
	case "MEDIUM":
		channels = []string{"siem", "dashboard"}
	case "LOW":
		channels = []string{"siem", "dashboard"}
	default:
		channels = []string{"dashboard", "log"}
	}
	status := map[string]interface{}{}
	for _, c := range channels {
		status[c] = "queued"
	}
	return DispatchPlan{Channels: channels, Status: status}
}

func defaultAlertTitle(action string, targetID string) string {
	if targetID == "" {
		return "Alert: " + action
	}
	return "Alert: " + action + " (" + targetID + ")"
}

func defaultAlertDescription(event AuditEvent) string {
	return "Action=" + event.Action + ", actor=" + event.ActorID + ", result=" + event.Result
}

func serviceFromAction(action string) string {
	parts := strings.Split(strings.ToLower(action), ".")
	if len(parts) > 1 {
		return parts[1]
	}
	return "unknown"
}

func ruleMatches(rule AlertRule, event AuditEvent) bool {
	cond := strings.ToLower(strings.TrimSpace(rule.Condition))
	if cond == "" {
		return false
	}
	if strings.Contains(cond, "event.action ==") {
		q := betweenQuotes(cond)
		return q != "" && strings.EqualFold(q, event.Action)
	}
	if strings.Contains(cond, "event.tags contains") {
		q := betweenQuotes(cond)
		for _, t := range event.Tags {
			if strings.EqualFold(strings.TrimSpace(t), q) {
				return true
			}
		}
	}
	if strings.Contains(cond, "event.source_ip.country") {
		// placeholder: geo context not implemented in this sprint
		return false
	}
	return false
}

func renderRuleTitle(tmpl string, event AuditEvent) string {
	out := strings.ReplaceAll(tmpl, "{event.actor_id}", event.ActorID)
	out = strings.ReplaceAll(out, "{event.action}", event.Action)
	if v, ok := event.Details["batch_size"]; ok {
		out = strings.ReplaceAll(out, "{event.details.batch_size}", str(v))
	}
	return out
}

func betweenQuotes(s string) string {
	start := strings.Index(s, "'")
	if start < 0 {
		return ""
	}
	end := strings.Index(s[start+1:], "'")
	if end < 0 {
		return ""
	}
	return s[start+1 : start+1+end]
}

func appendIfMissing(in []string, item string) []string {
	for _, v := range in {
		if strings.EqualFold(v, item) {
			return in
		}
	}
	return append(in, item)
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func str(v interface{}) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	default:
		return ""
	}
}

func asInt(v interface{}) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	default:
		return 0
	}
}

func asFloat(v interface{}) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	default:
		return 0
	}
}

func asBool(v interface{}, def bool) bool {
	switch x := v.(type) {
	case bool:
		return x
	default:
		return def
	}
}

func mustJSON(v interface{}) []byte {
	raw, _ := json.Marshal(v)
	return raw
}
