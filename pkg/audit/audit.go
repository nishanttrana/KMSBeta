// Package audit is the single sanctioned audit pipeline for all Vecta KMS
// services. Every service emits events through Client.Emit onto the one
// shared JetStream stream (AUDIT, subjects audit.>). The audit service owns
// the stream and is its primary durable consumer; downstream visibility
// services (dam, governance, reporting, metrics) attach their own durable
// consumers so fan-out never re-implements the pipeline.
//
// Services MUST NOT create their own AUDIT_* streams or publish audit
// events outside this package; scripts/conformance.sh enforces this.
package audit

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

// StreamName is the single JetStream stream holding all audit events.
const StreamName = "AUDIT"

// SubjectRoot is the subject space owned by the audit pipeline.
const SubjectRoot = "audit.>"

// DeadLetterSubject receives events that could not be published after retries.
// It is deliberately outside audit.> so it is not consumed as a normal event.
const DeadLetterSubject = "auditdlq.events"

// Event is the canonical audit event wire schema, matching what the audit
// service's ingest parses and persists. Service and Action are set by Emit;
// everything else is supplied by the caller. Populate Target*, CorrelationID
// and RiskScore wherever possible — downstream services (dam, governance,
// reporting, metrics) run their logic on these fields alone.
type Event struct {
	TenantID      string                 `json:"tenant_id"`
	Service       string                 `json:"service"`
	Action        string                 `json:"action"`
	ActorID       string                 `json:"actor_id,omitempty"`
	ActorType     string                 `json:"actor_type,omitempty"` // user | service | agent
	ActorRole     string                 `json:"actor_role,omitempty"`
	TargetType    string                 `json:"target_type,omitempty"` // e.g. key, secret, cert, tenant
	TargetID      string                 `json:"target_id,omitempty"`
	Result        string                 `json:"result"` // "success" or "failure"
	StatusCode    int                    `json:"status_code,omitempty"`
	ErrorMessage  string                 `json:"error_message,omitempty"`
	SourceIP      string                 `json:"source_ip,omitempty"`
	UserAgent     string                 `json:"user_agent,omitempty"`
	Method        string                 `json:"method,omitempty"`
	Endpoint      string                 `json:"endpoint,omitempty"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
	ParentEventID string                 `json:"parent_event_id,omitempty"`
	SessionID     string                 `json:"session_id,omitempty"`
	RiskScore     int                    `json:"risk_score,omitempty"`
	DurationMS    float64                `json:"duration_ms,omitempty"`
	Tags          []string               `json:"tags,omitempty"`
	Origin        string                 `json:"origin,omitempty"`   // "service" (default) | "agent"
	AgentID       string                 `json:"agent_id,omitempty"` // set when Origin == "agent"
	NodeID        string                 `json:"node_id,omitempty"`
	Details       map[string]interface{} `json:"details,omitempty"`
	Timestamp     string                 `json:"timestamp"`
}

// Client emits audit events for one service. It is publish-only: stream
// management belongs exclusively to the audit service via EnsureStream.
type Client struct {
	pub     *pkgevents.Publisher
	service string
}

// NewClient returns an emitter for the named service. It best-effort ensures
// the unified stream exists so emitters work regardless of startup order; the
// attempt fails harmlessly while legacy AUDIT_* streams still hold subjects,
// and the audit service converges them via EnsureStream.
func NewClient(js nats.JetStreamContext, service string) (*Client, error) {
	service = strings.ToLower(strings.TrimSpace(service))
	if service == "" {
		return nil, errors.New("audit: service name is required")
	}
	_, _ = js.AddStream(StreamConfig())
	return &Client{
		pub:     pkgevents.NewPublisher(js, 3, DeadLetterSubject),
		service: service,
	}, nil
}

// Publisher exposes the underlying publisher for legacy call sites
// (e.g. pkg/auditmw) that expect the EventPublisher interface.
func (c *Client) Publisher() *pkgevents.Publisher { return c.pub }

// Emit publishes one audit event to audit.<service>.<action>. The subject is
// derived; callers cannot publish outside their own service namespace.
func (c *Client) Emit(ctx context.Context, action string, evt Event) error {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		return errors.New("audit: action is required")
	}
	evt.Service = c.service
	evt.Action = fmt.Sprintf("audit.%s.%s", c.service, action)
	if evt.Result == "" {
		evt.Result = "success"
	}
	if evt.Origin == "" {
		evt.Origin = "service"
	}
	if evt.Timestamp == "" {
		evt.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	return c.pub.Publish(ctx, evt.Action, payload)
}

// EnsureStream creates (or converges) the single AUDIT stream. Only the audit
// service calls this. Legacy per-service AUDIT_* streams claim subjects inside
// audit.>, which JetStream forbids overlapping with the unified stream, so any
// stream named AUDIT_* is deleted first. Those streams were write-only sinks
// (no consumer ever attached), so removing them drops only unread backlog —
// the audit database already holds everything that was delivered.
func EnsureStream(js nats.JetStreamContext, logf func(string, ...interface{})) error {
	if logf == nil {
		logf = func(string, ...interface{}) {}
	}
	for name := range js.StreamNames() {
		if name != StreamName && strings.HasPrefix(name, "AUDIT_") {
			if err := js.DeleteStream(name); err != nil {
				logf("audit: failed to delete legacy stream %s: %v", name, err)
			} else {
				logf("audit: deleted legacy per-service stream %s (unified into %s)", name, StreamName)
			}
		}
	}
	cfg := StreamConfig()
	if _, err := js.AddStream(cfg); err != nil {
		if _, uerr := js.UpdateStream(cfg); uerr != nil {
			return fmt.Errorf("audit: ensure stream %s: add: %v / update: %v", StreamName, err, uerr)
		}
	}
	return nil
}

// StreamConfig is the canonical config of the unified AUDIT stream.
func StreamConfig() *nats.StreamConfig {
	return &nats.StreamConfig{
		Name:      StreamName,
		Subjects:  []string{SubjectRoot},
		Retention: nats.LimitsPolicy,
		MaxAge:    90 * 24 * time.Hour,
		Storage:   nats.FileStorage,
		Replicas:  1,
	}
}

// SubscribeDurable attaches a named durable consumer to the AUDIT stream.
// The audit service uses durable "audit-ingest"; downstream visibility
// services (dam, governance, reporting, metrics) attach their own durables
// so each gets the full event flow independently with replay on restart.
func SubscribeDurable(js nats.JetStreamContext, durable string, handler func(*Event, *nats.Msg)) (*nats.Subscription, error) {
	if durable == "" {
		return nil, errors.New("audit: durable consumer name is required")
	}
	return js.Subscribe(SubjectRoot, func(msg *nats.Msg) {
		var evt Event
		if err := json.Unmarshal(msg.Data, &evt); err != nil {
			// Malformed events are acked (terminal) — they will never parse.
			_ = msg.Ack()
			return
		}
		if evt.Action == "" {
			evt.Action = msg.Subject
		}
		handler(&evt, msg)
	}, nats.Durable(durable), nats.ManualAck(), nats.AckExplicit(), nats.BindStream(StreamName))
}
