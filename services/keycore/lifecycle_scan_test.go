package main

import (
	"testing"
	"time"
)

// The lifecycle scan only ever asks the reconciler to rotate. A compromised
// key or one deactivated long ago is left to a person (or a playbook behind
// a governance approval): automatic destroy was refused by keycore anyway
// and is irreversible.
func TestEvaluateLifecycleRotatesAndNeverDestroys(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	old := now.Add(-3 * 365 * 24 * time.Hour)
	cp := NewCryptoperiodPolicy()
	cases := []struct {
		name string
		c    LifecycleCandidate
		want string
	}{
		{"operator expiry", LifecycleCandidate{Status: "active", CreatedAt: now, ExpiryDate: &past}, "rotate"},
		{"cryptoperiod", LifecycleCandidate{Status: "active", CreatedAt: old, Purpose: "signing", Algorithm: "ECDSA-P256"}, "rotate"},
		{"ops threshold", LifecycleCandidate{Status: "active", CreatedAt: now, OpsLimit: 100, OpsTotal: 80}, "rotate"},
		{"fresh key", LifecycleCandidate{Status: "active", CreatedAt: now, OpsLimit: 100, OpsTotal: 79}, ""},
		{"compromised", LifecycleCandidate{Status: "compromised", CreatedAt: old, UpdatedAt: old}, ""},
		{"deactivated past grace", LifecycleCandidate{Status: "deactivated", CreatedAt: old, UpdatedAt: old}, ""},
	}
	for _, tc := range cases {
		if got, _ := EvaluateLifecycle(tc.c, cp, now); got != tc.want {
			t.Errorf("%s: action %q, want %q", tc.name, got, tc.want)
		}
	}
}
