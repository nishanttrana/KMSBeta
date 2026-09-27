package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Keycore's threat detection (unusual key use and canary trips) reaches
// posture as audit.keycore.threat_signal_raised events, which the scheduled
// audit sync already brings into posture_events_hot. Each signal becomes one
// finding. It is raised once: resolving it is final, and the event still in
// the hot window never reopens it. Critical and high signals also become
// reporting alerts from the same audit event (services/reporting).
const threatSignalAction = "audit.keycore.threat_signal_raised"

type threatFindingKind struct {
	title    string
	risk     int
	guidance string
}

var threatFindingKinds = map[string]threatFindingKind{
	"canary_tripped": {
		title: "Canary key probed", risk: 95,
		guidance: "Treat the caller's credential as compromised: revoke it, find where the canary ID was planted and what else that location exposed, and review the actor's recent key operations.",
	},
	"new_actor": {
		title: "New actor on an established key", risk: 70,
		guidance: "Confirm the actor is expected to use this key. If not, revoke its access and review the operations it performed.",
	},
	"volume_spike": {
		title: "Key usage spike", risk: 65,
		guidance: "Check whether a deployment or batch job explains the volume. If not, look for bulk decryption or exfiltration by the actors using the key.",
	},
	"dormant_key_activity": {
		title: "Dormant key used again", risk: 45,
		guidance: "Confirm who reactivated this key and why. Consider disabling keys that should stay retired.",
	},
}

// threatSeverity maps keycore's severity onto posture's scale.
func threatSeverity(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "critical":
		return severityCritical
	case "high":
		return severityHigh
	case "medium":
		return severityWarning
	default:
		return severityInfo
	}
}

// raiseThreatFindings creates a finding for each threat signal synced since
// `since` that has none yet, and returns how many it created.
func (s *Service) raiseThreatFindings(ctx context.Context, tenantID string, since time.Time, now time.Time) int {
	events, err := s.store.ListEventsByAction(ctx, tenantID, threatSignalAction, since, 500)
	if err != nil {
		logger.Printf("threat findings: list events tenant=%s: %v", tenantID, err)
		return 0
	}
	created := 0
	for _, ev := range events {
		signalID := firstString(ev.Details["signal_id"])
		signalType := firstString(ev.Details["signal_type"])
		kind, known := threatFindingKinds[signalType]
		if signalID == "" || !known {
			continue
		}
		fp := fingerprint(tenantID, "threat", signalID)
		if _, err := s.store.GetFindingByFingerprint(ctx, tenantID, fp); err == nil {
			continue
		}
		keyID := firstString(ev.Details["key_id"], ev.ResourceID)
		actorID := firstString(ev.Details["actor_id"])
		desc := firstString(ev.Details["description"])
		if desc == "" {
			desc = fmt.Sprintf("Keycore raised %s on key %s", signalType, keyID)
		}
		sev := threatSeverity(firstString(ev.Details["severity"]))
		item, err := s.store.UpsertFindingByFingerprint(ctx, tenantID, FindingCandidate{
			Engine:            "corrective",
			FindingType:       "threat_" + signalType,
			Title:             kind.title,
			Description:       desc,
			Severity:          sev,
			RiskScore:         kind.risk,
			RecommendedAction: kind.guidance,
			Fingerprint:       fp,
			Evidence: map[string]interface{}{
				"signal_id":      signalID,
				"signal_type":    signalType,
				"key_id":         keyID,
				"actor_id":       actorID,
				"detected_at":    firstString(ev.Details["detected_at"]),
				"audit_event_id": ev.ID,
				"node_id":        ev.NodeID,
			},
		}, now)
		if err != nil {
			logger.Printf("threat finding upsert failed tenant=%s signal=%s: %v", tenantID, signalID, err)
			continue
		}
		created++
		_ = s.publish(ctx, "audit.posture.threat_finding_raised", tenantID, map[string]interface{}{
			"finding_id":  item.ID,
			"signal_id":   signalID,
			"signal_type": signalType,
			"key_id":      keyID,
			"actor_id":    actorID,
			"severity":    sev,
		})
	}
	return created
}
