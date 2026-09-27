package main

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"vecta-kms/pkg/clusterstate"
)

// webhookFanout delivers persisted audit events to the tenant's enabled
// webhooks whose subscriptions match. It runs on the node that ingested the
// event (each event is processed once, on its own node), records every
// delivery in the node-local webhook_deliveries table, and audits each
// delivery as audit.audit.webhook_delivered. Those events are never
// delivered themselves.
type webhookFanout struct {
	store   Store
	disp    *WebhookDispatcher
	audit   func(ctx context.Context, ev AuditEvent)
	primary func(context.Context) bool
	queue   chan AuditEvent
	logger  *log.Logger

	mu    sync.Mutex
	cache map[string]cachedWebhooks
	ttl   time.Duration
}

type cachedWebhooks struct {
	at    time.Time
	hooks []Webhook
}

const (
	webhookWorkers   = 8
	webhookQueueSize = 4096
)

func newWebhookFanout(store Store, audit func(context.Context, AuditEvent), logger *log.Logger) *webhookFanout {
	return &webhookFanout{
		store: store, disp: NewWebhookDispatcher(), audit: audit, primary: clusterstate.RunsPrimaryJobs,
		queue: make(chan AuditEvent, webhookQueueSize), logger: logger,
		cache: map[string]cachedWebhooks{}, ttl: 15 * time.Second,
	}
}

func (f *webhookFanout) Start(ctx context.Context) {
	for i := 0; i < webhookWorkers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case ev := <-f.queue:
					f.deliverEvent(ctx, ev)
				}
			}
		}()
	}
}

// Invalidate drops a tenant's cached subscriptions after a change on this node.
func (f *webhookFanout) Invalidate(tenantID string) {
	f.mu.Lock()
	delete(f.cache, tenantID)
	f.mu.Unlock()
}

// Enqueue hands an event to the workers. A full queue is not dropped
// silently: it is recorded against each matching webhook and audited.
func (f *webhookFanout) Enqueue(ctx context.Context, ev AuditEvent) {
	if strings.HasPrefix(ev.Action, webhookSelfPrefix) {
		return
	}
	hooks := f.matching(ctx, ev)
	if len(hooks) == 0 {
		return
	}
	select {
	case f.queue <- ev:
	default:
		for _, wh := range hooks {
			f.record(ctx, wh, ev, 0, 0, 0, "delivery queue full; event not delivered")
		}
	}
}

func (f *webhookFanout) subscriptions(ctx context.Context, tenantID string) []Webhook {
	f.mu.Lock()
	c, ok := f.cache[tenantID]
	f.mu.Unlock()
	if ok && time.Since(c.at) < f.ttl {
		return c.hooks
	}
	all, err := f.store.ListWebhooks(ctx, tenantID)
	if err != nil {
		f.logger.Printf("webhooks: list for %s: %v", tenantID, err)
		return c.hooks
	}
	var enabled []Webhook
	for _, wh := range all {
		if wh.Enabled {
			enabled = append(enabled, wh)
		}
	}
	f.mu.Lock()
	f.cache[tenantID] = cachedWebhooks{at: time.Now(), hooks: enabled}
	f.mu.Unlock()
	return enabled
}

func (f *webhookFanout) matching(ctx context.Context, ev AuditEvent) []Webhook {
	if strings.TrimSpace(ev.TenantID) == "" {
		return nil
	}
	var out []Webhook
	for _, wh := range f.subscriptions(ctx, ev.TenantID) {
		if eventMatches(wh.Events, ev.Action) {
			out = append(out, wh)
		}
	}
	return out
}

func (f *webhookFanout) deliverEvent(ctx context.Context, ev AuditEvent) {
	for _, wh := range f.matching(ctx, ev) {
		f.deliver(ctx, wh, ev)
	}
}

// deliver sends one event to one webhook and records the result.
func (f *webhookFanout) deliver(ctx context.Context, wh Webhook, ev AuditEvent) WebhookDelivery {
	payload, err := formatWebhookPayload(wh.Format, ev)
	if err != nil {
		return f.record(ctx, wh, ev, 0, 0, 0, err.Error())
	}
	start := time.Now()
	status, attempts, derr := f.disp.Deliver(ctx, wh, ev.Action, ev.ID, payload)
	errMsg := ""
	if derr != nil {
		errMsg = derr.Error()
	}
	return f.record(ctx, wh, ev, status, attempts, int(time.Since(start).Milliseconds()), errMsg, payload...)
}

func (f *webhookFanout) record(ctx context.Context, wh Webhook, ev AuditEvent, status, attempts, latency int, errMsg string, payload ...byte) WebhookDelivery {
	d := WebhookDelivery{
		ID: newID("wd"), TenantID: wh.TenantID, WebhookID: wh.ID, EventType: ev.Action,
		PayloadPreview: truncateString(string(payload), 512), HTTPStatus: status,
		DeliveredAt: time.Now().UTC(), LatencyMs: latency, Attempt: attempts, Status: "success", Error: errMsg,
	}
	if errMsg != "" {
		d.Status = "failure"
	}
	if err := f.store.RecordDelivery(ctx, d); err != nil {
		f.logger.Printf("webhooks: record delivery %s: %v", wh.ID, err)
	}
	// The webhook row is replicated: only the primary updates it. Members
	// keep their attempts in their own webhook_deliveries.
	if f.primary(ctx) {
		_ = f.store.UpdateLastDelivery(ctx, wh.TenantID, wh.ID, d.Status, d.DeliveredAt)
		if d.Status != "success" {
			_ = f.store.IncrementFailureCount(ctx, wh.TenantID, wh.ID)
		}
	}
	if f.audit != nil {
		severity := "info"
		if d.Status != "success" {
			severity = "warning"
		}
		f.audit(ctx, AuditEvent{
			TenantID: wh.TenantID, Service: "audit", Action: webhookSelfPrefix + "delivered",
			ActorID: "audit-webhooks", ActorType: "service", TargetType: "webhook", TargetID: wh.ID,
			Result: d.Status, StatusCode: status, ErrorMessage: errMsg, CorrelationID: ev.CorrelationID,
			ParentEventID: ev.ID, Timestamp: d.DeliveredAt,
			Details: map[string]interface{}{
				"severity": severity, "event_id": ev.ID, "event_action": ev.Action, "delivery_id": d.ID,
				"format": wh.Format, "http_status": status, "attempts": attempts, "latency_ms": latency,
			},
		})
	}
	return d
}
