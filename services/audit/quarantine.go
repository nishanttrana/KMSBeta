package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// QuarantineDecision is the side-effect a risk-score evaluation requests.
// The audit handler turns Decisions into audit events; downstream
// services consume those events and apply the freeze.
type QuarantineDecision struct {
	TenantID   string
	TargetKind string // "tenant" or "key"
	TargetID   string
	RiskScore  int
	Reason     string
}

// QuarantineEvaluator turns a stream of incoming AuditEvent risk scores
// into Decisions. It maintains a tiny per-target rolling state so a single
// high-risk event doesn't flap the quarantine — the threshold must be
// crossed sustainedly for a short window.
type QuarantineEvaluator struct {
	mu                sync.Mutex
	state             map[string]*qstate
	publisher         EventPublisher
	scoreThreshold    int
	sustainedSeconds  int64
}

type qstate struct {
	hits      int
	firstHit  time.Time
	alerted   bool
}

// NewQuarantineEvaluator constructs an evaluator. Defaults trigger when a
// target accumulates 3 events scoring ≥80 within a 5-minute window.
func NewQuarantineEvaluator(publisher EventPublisher) *QuarantineEvaluator {
	return &QuarantineEvaluator{
		state:            make(map[string]*qstate),
		publisher:        publisher,
		scoreThreshold:   80,
		sustainedSeconds: 300,
	}
}

// SetThreshold overrides the trigger configuration. Zero values are
// ignored so callers can change one field at a time.
func (q *QuarantineEvaluator) SetThreshold(score int, sustainedSeconds int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if score > 0 {
		q.scoreThreshold = score
	}
	if sustainedSeconds > 0 {
		q.sustainedSeconds = sustainedSeconds
	}
}

// Evaluate inspects an event and, if its risk score meets the sustained
// threshold for its target, returns a decision and emits an audit event
// requesting that downstream services freeze the target. Returns nil
// when no action is warranted.
func (q *QuarantineEvaluator) Evaluate(ctx context.Context, event AuditEvent) *QuarantineDecision {
	if event.RiskScore < q.scoreThreshold {
		return nil
	}
	targetKind, targetID := quarantineTarget(event)
	if targetID == "" {
		return nil
	}
	key := targetKind + ":" + targetID
	q.mu.Lock()
	defer q.mu.Unlock()
	st, ok := q.state[key]
	now := time.Now().UTC()
	if !ok || now.Sub(st.firstHit) > time.Duration(q.sustainedSeconds)*time.Second {
		st = &qstate{hits: 1, firstHit: now}
		q.state[key] = st
		return nil
	}
	st.hits++
	if st.hits < 3 || st.alerted {
		return nil
	}
	st.alerted = true
	d := &QuarantineDecision{
		TenantID:   event.TenantID,
		TargetKind: targetKind,
		TargetID:   targetID,
		RiskScore:  event.RiskScore,
		Reason:     "sustained high risk score threshold breached",
	}
	q.publish(ctx, d)
	return d
}

func (q *QuarantineEvaluator) publish(ctx context.Context, d *QuarantineDecision) {
	if q.publisher == nil {
		return
	}
	evt := AuditEvent{
		TenantID:  d.TenantID,
		Service:   "audit",
		Action:    "audit.security.auto_quarantined",
		Result:    "warning",
		Timestamp: time.Now().UTC(),
		RiskScore: d.RiskScore,
		Details: map[string]interface{}{
			"target_kind": d.TargetKind,
			"target_id":   d.TargetID,
			"reason":      d.Reason,
		},
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		return
	}
	_ = q.publisher.Publish(ctx, evt.Action, payload)
}

// quarantineTarget selects the most specific target identifier present on
// the event. Key-level findings quarantine the key; tenant-level findings
// quarantine the whole tenant.
func quarantineTarget(event AuditEvent) (string, string) {
	if strings.EqualFold(event.TargetType, "key") && event.TargetID != "" {
		return "key", event.TargetID
	}
	if event.TargetID != "" {
		return strings.ToLower(strings.TrimSpace(event.TargetType)), event.TargetID
	}
	if event.TenantID != "" {
		return "tenant", event.TenantID
	}
	return "", ""
}
