package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	pkgevents "vecta-kms/pkg/events"
)

type Service struct {
	store       Store
	cfg         AuditConfig
	wal         *WALBuffer
	publisher   EventPublisher
	broker      *StreamBroker
	risk        *SustainedRiskDetector
	cluster     clusterKeyState
	webhooks    *webhookFanout
	creds       *credVault      // webhook credentials under the audit master key
	checkpoints checkpointState // this process's checkpoint signer (checkpoint.go)
}

// SetWebhookFanout wires delivery of persisted events to webhooks.
func (s *Service) SetWebhookFanout(f *webhookFanout) { s.webhooks = f }

// SetRiskDetector wires the sustained-risk signal (sustained_risk.go). With
// nil the signal is simply not produced.
func (s *Service) SetRiskDetector(d *SustainedRiskDetector) { s.risk = d }

type EventPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

func NewService(store Store, cfg AuditConfig, wal *WALBuffer, publisher EventPublisher) *Service {
	return &Service{
		store:     store,
		cfg:       cfg,
		wal:       wal,
		publisher: publisher,
		cluster:   clusterKeyState{keyFile: clusterAuditKeyFile()},
		creds:     &credVault{},
	}
}

func (s *Service) SetStreamBroker(b *StreamBroker) {
	s.broker = b
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

// errUnparseableEvent marks a message that can never be ingested (not an
// event at all). Redelivering it would block the stream, so the consumer
// terminates it instead of retrying.
var errUnparseableEvent = errors.New("unparseable audit event")

const platformTenantID = "root"

func (s *Service) HandleNATSMessage(ctx context.Context, msg *nats.Msg) error {
	event, err := parseIncomingEvent(msg.Subject, msg.Data)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", errUnparseableEvent, msg.Subject, err)
	}
	if s.isRelayedDuplicate(ctx, event) {
		return nil // another node's event, already here by replication
	}
	_, err = s.ProcessEvent(ctx, event)
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

func (s *Service) ProcessEvent(ctx context.Context, event AuditEvent) (AuditEvent, error) {
	enriched := s.classifyAndCorrelate(ctx, event)
	// Side-effecting detectors run before persistence so a sustained-
	// risk-score signal lands in the chain next to the triggering event.
	s.runDetectors(ctx, enriched)

	evt, err := s.store.PersistEvent(ctx, enriched)
	if err != nil {
		return AuditEvent{}, err
	}
	s.recordOpMetric(ctx, evt)
	s.broadcastToStream(evt)
	if s.webhooks != nil {
		s.webhooks.Enqueue(ctx, evt)
	}
	return evt, nil
}

// runDetectors hands an event to the sustained-risk detector, which decides
// for itself whether the event is relevant.
func (s *Service) runDetectors(ctx context.Context, event AuditEvent) {
	if s.risk != nil {
		_ = s.risk.Evaluate(ctx, event)
	}
}

func (s *Service) broadcastToStream(evt AuditEvent) {
	if s.broker == nil {
		return
	}
	if raw, err := json.Marshal(evt); err == nil {
		s.broker.BroadcastEvent(evt.TenantID, evt.ID, string(raw))
	}
}

// classifyAndCorrelate fills defaults, the FIPS category group, geo and the
// risk score. Alerts are raised by reporting from these events
// (/svc/reporting/alerts); audit keeps no alert store since 2.16.0-beta.
func (s *Service) classifyAndCorrelate(ctx context.Context, event AuditEvent) AuditEvent {
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
	// Populate FIPS 140-3 aligned category group from service name.
	if event.CategoryGroup == "" {
		event.CategoryGroup = categoryGroupForService(event.Service)
	}
	// Enrich geo-location from source IP so rule conditions can reference it.
	if event.CountryCode == "" && event.SourceIP != "" {
		event.CountryCode = resolveCountry(event.SourceIP)
	}
	// Persist country_code in the details JSONB so it survives DB round-trips.
	if event.CountryCode != "" {
		if event.Details == nil {
			event.Details = map[string]interface{}{}
		}
		if _, alreadySet := event.Details["country_code"]; !alreadySet {
			event.Details["country_code"] = event.CountryCode
		}
	}
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

	return event
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
			_, err = s.ProcessEvent(ctx, event)
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
		s.reportChainBroken(ctx, AuditEvent{
			TenantID:  tenantID,
			Service:   "audit",
			Action:    "audit.audit.chain_broken",
			ActorID:   "system",
			ActorType: "system",
			Result:    "failure",
			Details: map[string]interface{}{
				"scope":       "chain",
				"break_count": len(breaks),
				"breaks":      breaks,
			},
		})
	}
	return ok, breaks, nil
}

// reportChainBroken puts a chain_broken event on the AUDIT stream, where
// ingest records it in the chain and subscribers (playbooks, SIEM export)
// see it. Recording it directly would keep it out of the stream. When the
// stream is unavailable it is recorded directly, so a break is never lost.
func (s *Service) reportChainBroken(ctx context.Context, evt AuditEvent) {
	evt.ID = newID("evt")
	evt.Timestamp = time.Now().UTC()
	if s.publisher != nil {
		if payload, err := json.Marshal(evt); err == nil && s.publisher.Publish(ctx, evt.Action, payload) == nil {
			return
		}
	}
	_, _ = s.ProcessEvent(ctx, evt)
}

// maxAuditPayloadBytes caps each NATS audit event so a malformed or hostile
// publisher cannot exhaust the audit pipeline's memory. Genuine events are
// well below this size; the cap is a safety belt, not a tuning knob.
const maxAuditPayloadBytes = 256 * 1024

func parseIncomingEvent(subject string, payload []byte) (AuditEvent, error) {
	if len(payload) == 0 {
		return AuditEvent{}, errors.New("audit payload is empty")
	}
	if len(payload) > maxAuditPayloadBytes {
		return AuditEvent{}, errors.New("audit payload exceeds maximum allowed size")
	}
	if strings.TrimSpace(subject) == "" {
		return AuditEvent{}, errors.New("audit subject is required")
	}
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
		CountryCode:   str(in["country_code"]),
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
	// Wire-schema fields without dedicated columns are preserved in Details
	// so downstream consumers and the UI can distinguish agent-originated
	// events without a storage migration.
	for _, k := range []string{"origin", "agent_id", "actor_role"} {
		if v := str(in[k]); v != "" {
			if event.Details == nil {
				event.Details = map[string]interface{}{}
			}
			if _, exists := event.Details[k]; !exists {
				event.Details[k] = v
			}
		}
	}
	if tags, ok := in["tags"].([]interface{}); ok {
		for _, t := range tags {
			event.Tags = append(event.Tags, str(t))
		}
	}
	if event.TenantID == "" {
		// A platform-scoped event (no tenant: health, enrolment, platform
		// settings) belongs to the platform operator's root tenant, as
		// platform events already do. Rejecting it would redeliver it forever
		// and stall ingestion of everything behind it.
		event.TenantID = platformTenantID
		if event.Details == nil {
			event.Details = map[string]interface{}{}
		}
		event.Details["tenant_scope"] = "platform"
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

func serviceFromAction(action string) string {
	parts := strings.Split(strings.ToLower(action), ".")
	if len(parts) > 1 {
		return parts[1]
	}
	return "unknown"
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
