// Package cbom (Cryptographic Bill of Materials) inventories the
// algorithms, parameter sets, and key counts in active use across the KMS.
// Auditors and PQC-migration tooling consume the inventory; the policy
// service compares it against the operator-defined floor and the latest
// NIST guidance to flag deprecated entries.
package cbom

import (
	"sort"
	"strings"
	"time"
)

// Tier classifies an algorithm or parameter set against the current best-
// practice posture. Operators set the floor; anything below the floor
// surfaces in the diff endpoint.
type Tier string

const (
	TierClassical128 Tier = "classical-128"
	TierClassical192 Tier = "classical-192"
	TierClassical256 Tier = "classical-256"
	TierPQCHybrid    Tier = "pqc-hybrid"
	TierPQCOnly      Tier = "pqc-only"
	TierDeprecated   Tier = "deprecated"
)

// Entry is one algorithm-or-parameter-set row of the inventory.
type Entry struct {
	Algorithm   string    `json:"algorithm"`
	Parameters  string    `json:"parameters,omitempty"`
	KeyCount    int       `json:"key_count"`
	Tier        Tier      `json:"tier"`
	FirstSeenAt time.Time `json:"first_seen_at,omitempty"`
	LastUsedAt  time.Time `json:"last_used_at,omitempty"`
	// Deprecated flags algorithms that the current NIST guidance no longer
	// recommends (e.g., SHA-1, RSA-1024, ML-KEM-512 once superseded).
	Deprecated bool `json:"deprecated,omitempty"`
	// Note carries a short human-readable hint that explains why an entry
	// is flagged, e.g. "below tenant min_algorithm_tier=pqc-hybrid".
	Note string `json:"note,omitempty"`
}

// Inventory is a CBOM snapshot. ReadinessPercent reports the share of keys
// at or above the configured floor; it is the headline metric on the PQC-
// readiness dashboard.
type Inventory struct {
	TenantID         string    `json:"tenant_id"`
	GeneratedAt      time.Time `json:"generated_at"`
	Entries          []Entry   `json:"entries"`
	TotalKeys        int       `json:"total_keys"`
	FloorTier        Tier      `json:"floor_tier,omitempty"`
	ReadinessPercent float64   `json:"readiness_percent"`
}

// Build assembles an Inventory from a flat list of (algorithm, parameters,
// tier) tuples. Counts are summed across duplicates and the result is
// sorted for stable diffs.
func Build(tenantID string, floor Tier, samples []Entry) Inventory {
	agg := make(map[string]*Entry, len(samples))
	total := 0
	for _, s := range samples {
		key := strings.ToLower(s.Algorithm) + "|" + strings.ToLower(s.Parameters)
		if existing, ok := agg[key]; ok {
			existing.KeyCount += s.KeyCount
			if s.LastUsedAt.After(existing.LastUsedAt) {
				existing.LastUsedAt = s.LastUsedAt
			}
			if existing.FirstSeenAt.IsZero() || (!s.FirstSeenAt.IsZero() && s.FirstSeenAt.Before(existing.FirstSeenAt)) {
				existing.FirstSeenAt = s.FirstSeenAt
			}
		} else {
			cp := s
			agg[key] = &cp
		}
		total += s.KeyCount
	}
	entries := make([]Entry, 0, len(agg))
	for _, e := range agg {
		if e.Tier == "" {
			e.Tier = ClassifyTier(e.Algorithm, e.Parameters)
		}
		if floor != "" && !meetsFloor(e.Tier, floor) {
			e.Note = "below floor " + string(floor)
		}
		entries = append(entries, *e)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Algorithm == entries[j].Algorithm {
			return entries[i].Parameters < entries[j].Parameters
		}
		return entries[i].Algorithm < entries[j].Algorithm
	})
	readiness := 0.0
	if total > 0 && floor != "" {
		ok := 0
		for _, e := range entries {
			if meetsFloor(e.Tier, floor) {
				ok += e.KeyCount
			}
		}
		readiness = float64(ok) / float64(total) * 100.0
	}
	return Inventory{
		TenantID:         tenantID,
		GeneratedAt:      time.Now().UTC(),
		Entries:          entries,
		TotalKeys:        total,
		FloorTier:        floor,
		ReadinessPercent: readiness,
	}
}

// ClassifyTier returns the security tier for a given algorithm + parameter
// set. Unknown algorithms fall through to TierDeprecated so they surface
// in audits rather than silently passing.
func ClassifyTier(algorithm, parameters string) Tier {
	a := strings.ToUpper(strings.TrimSpace(algorithm))
	p := strings.ToUpper(strings.TrimSpace(parameters))
	switch {
	case strings.HasPrefix(a, "ML-KEM"), strings.HasPrefix(a, "ML-DSA"), strings.HasPrefix(a, "SLH-DSA"):
		if strings.Contains(p, "HYBRID") || strings.Contains(a, "HYBRID") {
			return TierPQCHybrid
		}
		return TierPQCOnly
	case strings.HasPrefix(a, "XMSS"), strings.HasPrefix(a, "LMS"):
		return TierPQCOnly
	case strings.HasPrefix(a, "AES-256"), a == "RSA-4096", strings.HasPrefix(a, "ECDSA-P384"), strings.HasPrefix(a, "ECDSA-P521"):
		return TierClassical256
	case strings.HasPrefix(a, "AES-192"), a == "RSA-3072":
		return TierClassical192
	case strings.HasPrefix(a, "AES-128"), a == "RSA-2048", strings.HasPrefix(a, "ECDSA-P256"):
		return TierClassical128
	case strings.HasPrefix(a, "3DES"), strings.HasPrefix(a, "DES"),
		strings.HasPrefix(a, "MD5"), strings.HasPrefix(a, "SHA-1"),
		a == "RSA-1024":
		return TierDeprecated
	default:
		return TierDeprecated
	}
}

// meetsFloor compares two tiers using a strict ordering classical < hybrid <
// pqc-only. "Deprecated" never meets any floor.
func meetsFloor(actual, floor Tier) bool {
	if actual == TierDeprecated {
		return false
	}
	return tierOrder(actual) >= tierOrder(floor)
}

func tierOrder(t Tier) int {
	switch t {
	case TierClassical128:
		return 1
	case TierClassical192:
		return 2
	case TierClassical256:
		return 3
	case TierPQCHybrid:
		return 4
	case TierPQCOnly:
		return 5
	default:
		return 0
	}
}
