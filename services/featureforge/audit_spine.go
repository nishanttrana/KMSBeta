package main

import (
	"context"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
)

// spineAudit mirrors pipeline transitions onto the platform's single audit
// stream via pkg/audit. The local ff_events trail stays the queryable
// per-intent view; this is the tamper-evident compliance record.
type spineAudit struct {
	c *pkgaudit.Client
}

// NewSpineAudit wraps a pkg/audit client as the forge's AuditClient.
func NewSpineAudit(c *pkgaudit.Client) AuditClient { return spineAudit{c: c} }

// auditAction maps a pipeline outcome to the audit action name. "received"
// and "deployed_prod" get their lifecycle names (proposed / promoted); the
// rest already read as transitions.
func auditAction(outcome string) string {
	switch outcome {
	case "received":
		return "intent.proposed"
	case "deployed_prod":
		return "intent.promoted"
	default:
		return "intent." + outcome
	}
}

func (a spineAudit) Emit(ctx context.Context, ev AuditEvent) error {
	result := "success"
	risk := 0
	switch ev.Outcome {
	case "rejected", "failed", "approval_denied":
		result = "failure"
		risk = 40
	case "deployed_prod":
		risk = 30 // prod-affecting change: always worth surfacing downstream
	}
	return a.c.Emit(ctx, auditAction(ev.Outcome), pkgaudit.Event{
		TenantID:      ev.TenantID,
		ActorID:       ev.Actor,
		ActorType:     "user",
		TargetType:    "feature_intent",
		TargetID:      ev.IntentID,
		Result:        result,
		CorrelationID: ev.RequestID,
		RiskScore:     risk,
		Details: map[string]interface{}{
			"stage":          string(ev.Stage),
			"outcome":        ev.Outcome,
			"detail":         ev.Detail,
			"catalog_action": ev.Action,
		},
		Timestamp: ev.Timestamp.UTC().Format(time.RFC3339Nano),
	})
}
