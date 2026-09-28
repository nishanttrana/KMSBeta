// Package cbom (Cryptographic Bill of Materials) inventories the
// algorithms, parameter sets, and key counts in active use across the KMS.
// Auditors and PQC-migration tooling consume the inventory; the policy
// service compares it against the operator-defined floor and the latest
// catalogue facts to flag weak entries.
package cbom

import (
	"sort"
	"strings"
	"time"

	"vecta-kms/pkg/cryptocatalog"
)

// Tier classifies an algorithm or parameter set against the current best-
// practice posture. Operators set the floor; anything below the floor
// surfaces in the diff endpoint. Classical tiers are the security strength
// from pkg/cryptocatalog.
type Tier string

const (
	TierClassical112 Tier = "classical-112"
	TierClassical128 Tier = "classical-128"
	TierClassical192 Tier = "classical-192"
	TierClassical256 Tier = "classical-256"
	TierPQCHybrid    Tier = "pqc-hybrid"
	TierPQCOnly      Tier = "pqc-only"
	// TierDeprecated: the algorithm is weak (broken, below 112 bits, or an
	// unsafe mode such as ECB).
	TierDeprecated Tier = "deprecated"
	// TierNotAssessed: the catalogue cannot identify the parameter set.
	TierNotAssessed Tier = "not-assessed"
)

// Floors are the tiers a policy may require, weakest first.
var Floors = []Tier{TierClassical112, TierClassical128, TierClassical192, TierClassical256, TierPQCHybrid, TierPQCOnly}

// ParseTier accepts a floor name. Deprecated and not-assessed are
// classifications, never floors.
func ParseTier(s string) (Tier, bool) {
	t := Tier(strings.ToLower(strings.TrimSpace(s)))
	return t, tierOrder(t) > 0
}

// Entry is one algorithm-or-parameter-set row of the inventory.
type Entry struct {
	Algorithm   string    `json:"algorithm"`
	Parameters  string    `json:"parameters,omitempty"`
	KeyCount    int       `json:"key_count"`
	Tier        Tier      `json:"tier"`
	FirstSeenAt time.Time `json:"first_seen_at,omitempty"`
	LastUsedAt  time.Time `json:"last_used_at,omitempty"`
	// Deprecated flags weak algorithms (broken, below 112 bits, or an unsafe
	// mode), e.g. SHA-1, RSA-1024, 3DES, AES-ECB.
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
		if ce, ok := cryptocatalog.Lookup(e.Algorithm); ok && ce.Weak {
			e.Deprecated = true
			e.Note = "weak algorithm"
		}
		if floor != "" && !MeetsFloor(e.Tier, floor) {
			e.Note = strings.TrimPrefix(e.Note+"; below floor "+string(floor), "; ")
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
			if MeetsFloor(e.Tier, floor) {
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

// ClassifyTier returns the tier of an algorithm from its catalogue entry.
// Parameters mark a post-quantum algorithm used in a hybrid with "hybrid".
// An algorithm the catalogue cannot identify is not assessed, and like a
// deprecated one it meets no floor.
func ClassifyTier(algorithm, parameters string) Tier {
	e, ok := cryptocatalog.Lookup(algorithm)
	if !ok {
		return TierNotAssessed
	}
	switch {
	case e.Weak:
		return TierDeprecated
	case e.Hybrid, e.PostQuantum && strings.Contains(strings.ToUpper(parameters), "HYBRID"):
		return TierPQCHybrid
	case e.PostQuantum:
		return TierPQCOnly
	case e.SecurityBits >= 256:
		return TierClassical256
	case e.SecurityBits >= 192:
		return TierClassical192
	case e.SecurityBits >= 128:
		return TierClassical128
	case e.SecurityBits >= 112:
		return TierClassical112
	case e.SecurityBits > 0:
		return TierDeprecated
	}
	return TierNotAssessed
}

// MeetsFloor reports whether actual is at or above floor, ordered
// classical-112 < classical-128 < classical-192 < classical-256 < pqc-hybrid
// < pqc-only. Deprecated and not-assessed meet no floor, and an unknown floor
// is met by nothing: a mistyped policy fails closed.
func MeetsFloor(actual, floor Tier) bool {
	a, f := tierOrder(actual), tierOrder(floor)
	return a > 0 && f > 0 && a >= f
}

func tierOrder(t Tier) int {
	for i, f := range Floors {
		if t == f {
			return i + 1
		}
	}
	return 0
}
