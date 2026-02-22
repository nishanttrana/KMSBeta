package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func eventHashInput(e AuditEvent) []byte {
	payload := map[string]interface{}{
		"tenant_id":       e.TenantID,
		"timestamp":       canonicalTimestamp(e.Timestamp),
		"service":         e.Service,
		"action":          e.Action,
		"actor_id":        e.ActorID,
		"actor_type":      e.ActorType,
		"target_type":     e.TargetType,
		"target_id":       e.TargetID,
		"method":          e.Method,
		"endpoint":        e.Endpoint,
		"source_ip":       e.SourceIP,
		"user_agent":      e.UserAgent,
		"request_hash":    e.RequestHash,
		"correlation_id":  e.CorrelationID,
		"parent_event_id": e.ParentEventID,
		"session_id":      e.SessionID,
		"result":          e.Result,
		"status_code":     e.StatusCode,
		"error_message":   e.ErrorMessage,
		"duration_ms":     e.DurationMS,
		"fips_compliant":  e.FIPSCompliant,
		"approval_id":     e.ApprovalID,
		"risk_score":      e.RiskScore,
		"tags":            e.Tags,
		"node_id":         e.NodeID,
		"details":         e.Details,
	}
	raw, _ := json.Marshal(payload)
	return raw
}

func canonicalTimestamp(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	t := ts.UTC().Truncate(time.Second)
	return strings.TrimSpace(t.Format(time.RFC3339))
}

func chainHash(previous string, input []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(previous))
	_, _ = h.Write(input)
	return hex.EncodeToString(h.Sum(nil))
}

func dedupKey(event AuditEvent, windowSeconds int) string {
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	bucket := event.Timestamp.UTC().Unix() / int64(windowSeconds)
	return event.TenantID + "|" + event.Action + "|" + event.SourceIP + "|" + event.ActorID + "|" + itoa(bucket)
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + (v % 10))
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
