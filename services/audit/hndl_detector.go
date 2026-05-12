package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// HNDLDetector flags "harvest-now-decrypt-later" patterns: bulk encryption
// volume against classical-only keys destined for long-retention data. The
// detector keeps a small in-memory sliding window per tenant; on threshold
// breach it emits an audit event so the alert pipeline can page or
// quarantine.
//
// This is a heuristic, not a model. The thresholds are tunable via env so
// operators can dial sensitivity to their normal traffic shape.
type HNDLDetector struct {
	mu            sync.Mutex
	tenants       map[string]*hndlState
	windowSeconds int64
	opsThreshold  int64
	bytesThreshold int64
	publisher     EventPublisher
}

type hndlState struct {
	windowStart time.Time
	ops         int64
	bytes       int64
	alerted     bool
}

// NewHNDLDetector constructs a detector. Window length and thresholds
// default to a conservative "10k ops or 1 GiB of classical encryption per
// 5-minute window per tenant" trigger; operators tune via the setters.
func NewHNDLDetector(publisher EventPublisher) *HNDLDetector {
	return &HNDLDetector{
		tenants:        make(map[string]*hndlState),
		windowSeconds:  300,
		opsThreshold:   10_000,
		bytesThreshold: 1 << 30,
		publisher:      publisher,
	}
}

// SetThresholds overrides the default trigger levels. Zero values are
// ignored so callers can change one field at a time.
func (d *HNDLDetector) SetThresholds(ops, bytes int64, windowSeconds int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ops > 0 {
		d.opsThreshold = ops
	}
	if bytes > 0 {
		d.bytesThreshold = bytes
	}
	if windowSeconds > 0 {
		d.windowSeconds = windowSeconds
	}
}

// Observe records one encryption operation. Only operations on classical-
// only keys against long-retention targets contribute to the score; other
// callers will short-circuit before reaching the detector.
func (d *HNDLDetector) Observe(ctx context.Context, tenantID string, opName string, bytes int64) {
	if !isHNDLCandidate(opName) {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	state, ok := d.tenants[tenantID]
	now := time.Now().UTC()
	if !ok || now.Sub(state.windowStart) > time.Duration(d.windowSeconds)*time.Second {
		state = &hndlState{windowStart: now}
		d.tenants[tenantID] = state
	}
	state.ops++
	state.bytes += bytes
	if state.alerted {
		return
	}
	if state.ops < d.opsThreshold && state.bytes < d.bytesThreshold {
		return
	}
	state.alerted = true
	d.emit(ctx, tenantID, state)
}

func (d *HNDLDetector) emit(ctx context.Context, tenantID string, s *hndlState) {
	if d.publisher == nil {
		return
	}
	evt := AuditEvent{
		TenantID:  tenantID,
		Service:   "audit",
		Action:    "audit.security.hndl_pattern_detected",
		Result:    "warning",
		Timestamp: time.Now().UTC(),
		Details: map[string]interface{}{
			"window_seconds":    d.windowSeconds,
			"ops_in_window":     s.ops,
			"bytes_in_window":   s.bytes,
			"ops_threshold":     d.opsThreshold,
			"bytes_threshold":   d.bytesThreshold,
			"remediation_hint":  "rotate target keys to hybrid PQC; review long-retention encrypt patterns",
		},
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		return
	}
	_ = d.publisher.Publish(ctx, evt.Action, payload)
}

// isHNDLCandidate returns true for the operations that meaningfully
// contribute to a harvest-now-decrypt-later signal. Decrypt, key
// management, and admin operations are excluded because they don't
// produce ciphertext that an adversary could harvest.
func isHNDLCandidate(opName string) bool {
	op := strings.ToLower(strings.TrimSpace(opName))
	switch op {
	case "key.encrypt", "key.wrap", "key.envelope_encrypt",
		"kmip.encrypt", "kmip.mac",
		"crypto.bulk_encrypt":
		return true
	}
	return strings.HasSuffix(op, ".encrypt") || strings.HasSuffix(op, ".bulk_encrypt")
}
