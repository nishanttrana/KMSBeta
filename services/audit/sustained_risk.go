package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// sustainedRiskSubject is the signal SustainedRiskDetector publishes. It is a
// playbook trigger (sustained_risk_detected): a playbook, acting for someone
// who holds the permission, can disable or deactivate the key. The detector
// itself changes nothing. Until 5.3.0-beta it was named audit.security.auto_quarantined,
// although nothing was ever quarantined.
const sustainedRiskSubject = "audit.security.sustained_risk_detected"

// RiskFinding is one target whose events kept a high risk score.
type RiskFinding struct {
	TenantID   string
	TargetKind string // "key", another target type, or "tenant"
	TargetID   string
	RiskScore  int
	Reason     string
}

// SustainedRiskDetector watches the risk score audit assigns each event. A
// single high-risk event doesn't fire: the target must collect 3 events at
// or above the threshold within the window, and then fires once per window.
type SustainedRiskDetector struct {
	mu               sync.Mutex
	state            map[string]*riskState
	publisher        EventPublisher
	scoreThreshold   int
	sustainedSeconds int64
}

type riskState struct {
	hits     int
	firstHit time.Time
	alerted  bool
}

// NewSustainedRiskDetector constructs a detector that fires when a target
// accumulates 3 events scoring ≥80 within a 5-minute window.
func NewSustainedRiskDetector(publisher EventPublisher) *SustainedRiskDetector {
	return &SustainedRiskDetector{
		state:            make(map[string]*riskState),
		publisher:        publisher,
		scoreThreshold:   80,
		sustainedSeconds: 300,
	}
}

// Evaluate inspects an event and, when its target has now crossed the
// sustained threshold, publishes audit.security.sustained_risk_detected and
// returns the finding. Returns nil when nothing fires.
func (d *SustainedRiskDetector) Evaluate(ctx context.Context, event AuditEvent) *RiskFinding {
	// The finding carries the score that fired it; it must not count as
	// another hit on its own target.
	if event.RiskScore < d.scoreThreshold || event.Action == sustainedRiskSubject {
		return nil
	}
	targetKind, targetID := riskTarget(event)
	if targetID == "" {
		return nil
	}
	key := targetKind + ":" + targetID
	d.mu.Lock()
	defer d.mu.Unlock()
	st, ok := d.state[key]
	now := time.Now().UTC()
	if !ok || now.Sub(st.firstHit) > time.Duration(d.sustainedSeconds)*time.Second {
		st = &riskState{hits: 1, firstHit: now}
		d.state[key] = st
		return nil
	}
	st.hits++
	if st.hits < 3 || st.alerted {
		return nil
	}
	st.alerted = true
	f := &RiskFinding{
		TenantID:   event.TenantID,
		TargetKind: targetKind,
		TargetID:   targetID,
		RiskScore:  event.RiskScore,
		Reason:     "sustained high risk score threshold breached",
	}
	d.publish(ctx, f)
	return f
}

func (d *SustainedRiskDetector) publish(ctx context.Context, f *RiskFinding) {
	if d.publisher == nil {
		return
	}
	evt := AuditEvent{
		TenantID:   f.TenantID,
		Service:    "audit",
		Action:     sustainedRiskSubject,
		Result:     "warning",
		Timestamp:  time.Now().UTC(),
		RiskScore:  f.RiskScore,
		TargetType: f.TargetKind,
		TargetID:   f.TargetID,
		Details: map[string]interface{}{
			"target_kind":     f.TargetKind,
			"target_id":       f.TargetID,
			"reason":          f.Reason,
			"score_threshold": d.scoreThreshold,
			"window_seconds":  d.sustainedSeconds,
		},
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		return
	}
	_ = d.publisher.Publish(ctx, evt.Action, payload)
}

// riskTarget selects the most specific target identifier present on the
// event: the key, another named target, or else the tenant.
func riskTarget(event AuditEvent) (string, string) {
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
