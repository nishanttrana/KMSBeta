package main

import (
	"strings"

	"vecta-kms/pkg/quota"
)

// QuotaPolicy is the per-service in-memory tracker. Lives on Service so
// every evaluation has access without an extra lookup.
type QuotaPolicy struct {
	tracker *quota.Tracker
}

// NewQuotaPolicy constructs an empty tracker.
func NewQuotaPolicy() *QuotaPolicy {
	return &QuotaPolicy{tracker: quota.New()}
}

// SetBudget exposes the tracker's budget setter so REST handlers can
// configure tenant quotas at runtime.
func (q *QuotaPolicy) SetBudget(b quota.Budget) {
	q.tracker.SetBudget(b)
}

// Snapshot returns the current usage view for every tenant. Used by the
// reconciler when it publishes telemetry.
func (q *QuotaPolicy) Snapshot() []quota.TenantUsage {
	return q.tracker.Snapshot()
}

// Usage returns the snapshot for a single tenant.
func (q *QuotaPolicy) Usage(tenantID string) (int64, quota.Budget, bool) {
	return q.tracker.Usage(tenantID)
}

// AdviseDecision is called from the evaluator before per-policy rules run.
// It returns one of three modifiers that the evaluator overlays on top of
// the per-policy outcome:
//
//   - "" (empty): no quota signal, evaluator behaves normally
//   - "warn":     evaluator should add a non-blocking warning outcome
//   - "deny":     evaluator should short-circuit with DENY
//
// The quota-derived deny composes with policy denies (deny wins over
// allow); a quota warn is dropped if the policy is already denying.
func (q *QuotaPolicy) AdviseDecision(tenantID string, opName string) string {
	if q == nil || q.tracker == nil {
		return ""
	}
	// Mutating ops increment the counter; read-only ops only observe.
	if isMutatingOp(opName) {
		switch q.tracker.Add(tenantID, 1) {
		case quota.Deny:
			return "deny"
		case quota.Warn:
			return "warn"
		}
		return ""
	}
	switch q.tracker.Evaluate(tenantID) {
	case quota.Deny:
		return "deny"
	case quota.Warn:
		return "warn"
	}
	return ""
}

// isMutatingOp returns true for operations that should consume quota.
// Pure read operations (get, list, query) are deliberately free so the
// quota meters productive load, not introspection.
func isMutatingOp(op string) bool {
	o := strings.ToLower(strings.TrimSpace(op))
	switch {
	case strings.HasSuffix(o, ".encrypt"),
		strings.HasSuffix(o, ".decrypt"),
		strings.HasSuffix(o, ".sign"),
		strings.HasSuffix(o, ".wrap"),
		strings.HasSuffix(o, ".unwrap"),
		strings.HasSuffix(o, ".rotate"),
		strings.HasSuffix(o, ".destroy"),
		strings.HasSuffix(o, ".create"),
		strings.HasSuffix(o, ".derive"),
		strings.HasSuffix(o, ".bulk_encrypt"):
		return true
	}
	return false
}
