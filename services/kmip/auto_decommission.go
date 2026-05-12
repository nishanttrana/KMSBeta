package main

import (
	"strings"
	"time"
)

// DecommissionPolicy controls when a KMIP client moves from active to
// dormant and from dormant to revoked. The defaults match a "no traffic
// in 90 days → dormant, no traffic in 180 days → revoked" stance, which
// keeps stale certs out of the trust list without surprising legitimate
// long-lived integrations.
type DecommissionPolicy struct {
	DormantAfter time.Duration
	RevokeAfter  time.Duration
}

// DefaultDecommissionPolicy returns the shipped defaults.
func DefaultDecommissionPolicy() DecommissionPolicy {
	return DecommissionPolicy{
		DormantAfter: 90 * 24 * time.Hour,
		RevokeAfter:  180 * 24 * time.Hour,
	}
}

// DecommissionAction is what the reconciler decided to do for one client.
// "none" means the client is healthy and the reconciler wrote nothing.
type DecommissionAction string

const (
	DecommissionNone    DecommissionAction = "none"
	DecommissionDormant DecommissionAction = "set-dormant"
	DecommissionRevoke  DecommissionAction = "revoke"
)

// ClientActivity is the minimal projection the decommission evaluator
// needs. The store builds one of these per KMIP client at scan time so
// the evaluator stays free of the full client record.
type ClientActivity struct {
	ID         string
	TenantID   string
	Status     string
	LastSeenAt time.Time // most recent session, op, or update
	CreatedAt  time.Time
}

// EvaluateDecommission returns the action to apply for a client given its
// last-seen timestamp and current status. Pure function — the caller
// owns persistence and audit so the same logic can drive REST handlers
// and the cron reconciler without duplication.
func EvaluateDecommission(client ClientActivity, now time.Time, policy DecommissionPolicy) DecommissionAction {
	status := strings.ToLower(strings.TrimSpace(client.Status))
	if status == "revoked" {
		return DecommissionNone
	}
	last := client.LastSeenAt
	if last.IsZero() {
		last = client.CreatedAt
	}
	if last.IsZero() {
		return DecommissionNone
	}
	silence := now.Sub(last)
	switch {
	case silence > policy.RevokeAfter && status != "revoked":
		return DecommissionRevoke
	case silence > policy.DormantAfter && status != "dormant" && status != "revoked":
		return DecommissionDormant
	default:
		return DecommissionNone
	}
}

// DescribeAction returns a short human-readable phrase used in the audit
// event payload. Kept here so action strings and descriptions can't
// drift out of sync.
func DescribeAction(a DecommissionAction) string {
	switch a {
	case DecommissionDormant:
		return "client marked dormant after inactivity threshold"
	case DecommissionRevoke:
		return "client revoked after extended inactivity"
	default:
		return ""
	}
}
