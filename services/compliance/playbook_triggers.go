package main

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	pkgevents "vecta-kms/pkg/events"
)

// TriggerListener subscribes to audit events via NATS and triggers matching playbooks.
type TriggerListener struct {
	store    Store
	executor *PlaybookExecutor
	logger   *log.Logger

	// dedup tracks recent playbook triggers to prevent re-execution within the cooldown window
	mu       sync.Mutex
	lastFire map[string]time.Time
}

const dedupCooldown = 60 * time.Second

// NewTriggerListener creates a listener wired to the playbook executor.
func NewTriggerListener(store Store, executor *PlaybookExecutor, logger *log.Logger) *TriggerListener {
	return &TriggerListener{
		store:    store,
		executor: executor,
		logger:   logger,
		lastFire: make(map[string]time.Time),
	}
}

// StartListening subscribes to all audit events and triggers matching playbooks.
// It requires a NATS JetStream context; if js is nil, the listener is a no-op.
func (tl *TriggerListener) StartListening(ctx context.Context, js nats.JetStreamContext) {
	if js == nil {
		tl.logger.Printf("trigger-listener: NATS unavailable, playbook triggers disabled")
		return
	}

	sub := pkgevents.NewSubscriber(js)

	// Subscribe to all audit events using wildcard
	subscription, err := sub.SubscribeDurable("audit.>", "playbook-trigger-listener", func(msg *nats.Msg) {
		tl.handleAuditEvent(ctx, msg)
		_ = msg.Ack()
	})
	if err != nil {
		tl.logger.Printf("trigger-listener: failed to subscribe to audit.>: %v", err)
		return
	}
	tl.logger.Printf("trigger-listener: listening on audit.> for playbook triggers")

	// Periodically clean up old dedup entries
	go tl.dedupCleaner(ctx)

	// Block until context is cancelled, then unsubscribe
	<-ctx.Done()
	_ = subscription.Unsubscribe()
	tl.logger.Printf("trigger-listener: stopped")
}

// handleAuditEvent maps a NATS subject to a trigger type and fires matching playbooks.
func (tl *TriggerListener) handleAuditEvent(ctx context.Context, msg *nats.Msg) {
	subject := msg.Subject

	triggerType := mapSubjectToTrigger(subject)
	if triggerType == "" {
		return
	}

	// Parse the event payload for context
	var eventData map[string]interface{}
	if len(msg.Data) > 0 {
		_ = json.Unmarshal(msg.Data, &eventData)
	}

	// Extract tenant_id from the event if present
	tenantID, _ := eventData["tenant_id"].(string)
	if tenantID == "" {
		tenantID, _ = eventData["TenantID"].(string)
	}
	if tenantID == "" {
		// Cannot match playbooks without a tenant
		return
	}

	// List all playbooks for this tenant and find ones matching the trigger
	playbooks, err := tl.store.ListPlaybooks(ctx, tenantID)
	if err != nil {
		tl.logger.Printf("trigger-listener: failed to list playbooks for tenant=%s: %v", tenantID, err)
		return
	}

	eventJSON, _ := json.Marshal(eventData)
	triggerEventStr := string(eventJSON)

	for _, pb := range playbooks {
		if !pb.Enabled {
			continue
		}
		if pb.Trigger.Type != triggerType {
			continue
		}

		// Dedup check: don't re-trigger the same playbook within the cooldown window
		dedupKey := pb.ID + ":" + triggerType
		if tl.isRecentlyFired(dedupKey) {
			tl.logger.Printf("trigger-listener: dedup skip playbook=%s trigger=%s (fired within %s)", pb.ID, triggerType, dedupCooldown)
			continue
		}
		tl.markFired(dedupKey)

		tl.logger.Printf("trigger-listener: firing playbook=%s name=%q trigger=%s tenant=%s", pb.ID, pb.Name, triggerType, tenantID)

		// Execute in a goroutine so we don't block the NATS handler
		pbCopy := pb
		go func() {
			execCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if _, err := tl.executor.ExecutePlaybook(execCtx, pbCopy, triggerEventStr); err != nil {
				tl.logger.Printf("trigger-listener: playbook=%s execution error: %v", pbCopy.ID, err)
			}
		}()
	}
}

// mapSubjectToTrigger converts a NATS audit subject to a playbook trigger type.
func mapSubjectToTrigger(subject string) string {
	// Direct subject-to-trigger mappings
	subjectMap := map[string]string{
		// Key Lifecycle
		"audit.keycore.key_created":      "key_created",
		"audit.keycore.key_rotated":      "key_rotated",
		"audit.keycore.key_expired":      "key_expired",
		"audit.keycore.key_destroyed":    "key_destroyed",
		"audit.keycore.key_compromised":  "key_compromised",
		"audit.keycore.key_import_failed": "key_import_failed",
		"audit.keycore.rotation_overdue": "rotation_overdue",
		"audit.keycore.key_expiry_imminent": "key_expiry_imminent",

		// Certificate
		"audit.certs.cert_expiring_30d":  "cert_expiring_30d",
		"audit.certs.cert_expiring_7d":   "cert_expiring_7d",
		"audit.certs.cert_expired":       "cert_expired",
		"audit.certs.cert_revoked":       "cert_revoked",
		"audit.certs.ca_rotation_due":    "ca_rotation_due",

		// Access & Auth
		"audit.auth.account_locked":               "auth_failure_spike",
		"audit.auth.login_failed":                 "auth_failure_spike",
		"audit.auth.unauthorized_key_access":      "unauthorized_key_access",
		"audit.auth.privilege_escalation_attempt": "privilege_escalation_attempt",
		"audit.auth.api_key_compromised":          "api_key_compromised",
		"audit.auth.session_anomaly":              "session_anomaly",

		// Compliance
		"audit.compliance.compliance_drop":             "compliance_drop",
		"audit.compliance.compliance_score_drop":       "compliance_score_drop",
		"audit.compliance.fips_violation_detected":     "fips_violation_detected",
		"audit.compliance.policy_violation":            "policy_violation",
		"audit.compliance.audit_gap_detected":          "audit_gap_detected",
		"audit.compliance.framework_assessment_failed": "framework_assessment_failed",

		// Infrastructure
		"audit.infra.hsm_health_degraded":        "hsm_health_degraded",
		"audit.infra.cluster_node_down":          "cluster_node_down",
		"audit.infra.replication_lag_high":       "replication_lag_high",
		"audit.infra.backup_failed":              "backup_failed",
		"audit.infra.storage_threshold_exceeded": "storage_threshold_exceeded",

		// Data Protection
		"audit.data.encryption_failure":   "encryption_failure",
		"audit.data.decryption_anomaly":   "decryption_anomaly",
		"audit.data.data_leak_detected":   "data_leak_detected",
		"audit.data.dlp_policy_triggered": "dlp_policy_triggered",

		// Operational
		"audit.ops.rate_limit_exceeded":     "rate_limit_exceeded",
		"audit.ops.service_health_degraded": "service_health_degraded",
		"audit.ops.latency_spike":           "latency_spike",
		"audit.ops.error_rate_high":         "error_rate_high",

		// Incident Response
		"audit.canary.tripped":        "canary_tripped",
		"audit.risk.score_critical":   "risk_score_critical",
	}

	if trigger, ok := subjectMap[subject]; ok {
		return trigger
	}

	// Wildcard matching for compliance sub-events
	if strings.HasPrefix(subject, "audit.compliance.") {
		suffix := strings.TrimPrefix(subject, "audit.compliance.")
		if validTriggerTypes[suffix] {
			return suffix
		}
	}

	// Wildcard matching for keycore sub-events
	if strings.HasPrefix(subject, "audit.keycore.") {
		suffix := strings.TrimPrefix(subject, "audit.keycore.")
		if validTriggerTypes[suffix] {
			return suffix
		}
	}

	return ""
}

// isRecentlyFired checks if a playbook+trigger combo was fired within the dedup window.
func (tl *TriggerListener) isRecentlyFired(key string) bool {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	if last, ok := tl.lastFire[key]; ok {
		return time.Since(last) < dedupCooldown
	}
	return false
}

// markFired records the current time for a playbook+trigger dedup key.
func (tl *TriggerListener) markFired(key string) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	tl.lastFire[key] = time.Now()
}

// dedupCleaner periodically removes expired dedup entries to prevent memory leaks.
func (tl *TriggerListener) dedupCleaner(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tl.mu.Lock()
			now := time.Now()
			for k, t := range tl.lastFire {
				if now.Sub(t) > dedupCooldown*2 {
					delete(tl.lastFire, k)
				}
			}
			tl.mu.Unlock()
		}
	}
}
