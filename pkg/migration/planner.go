// Package migration plans PQC migration runs. Given a target ("all signing
// keys hybrid by Q4"), the planner enumerates the keys that fall below the
// target tier, ranks them by risk, and produces a schedule of rotations
// that respects rate limits, approval requirements, and downstream client
// coordination windows.
//
// The planner is pure: it operates on the snapshot supplied by the caller
// and emits a Plan. Execution is a separate concern owned by the reconciler.
package migration

import (
	"sort"
	"time"

	"vecta-kms/pkg/cbom"
)

// Candidate represents one key being considered for migration. Score is
// the Y2Q (years-to-quantum) risk multiplied by sensitivity; higher values
// migrate first.
type Candidate struct {
	KeyID        string    `json:"key_id"`
	TenantID     string    `json:"tenant_id"`
	Algorithm    string    `json:"algorithm"`
	Parameters   string    `json:"parameters"`
	CurrentTier  cbom.Tier `json:"current_tier"`
	Y2QScore     float64   `json:"y2q_score"`
	Dependencies []string  `json:"dependencies,omitempty"`
}

// Step is one scheduled rotation. ScheduledAt is the planner's
// recommendation; the reconciler may shift it to satisfy operational
// windows.
type Step struct {
	KeyID         string    `json:"key_id"`
	TenantID      string    `json:"tenant_id"`
	FromAlgorithm string    `json:"from_algorithm"`
	ToAlgorithm   string    `json:"to_algorithm"`
	ScheduledAt   time.Time `json:"scheduled_at"`
	RequiresApproval bool   `json:"requires_approval"`
	Dependencies  []string  `json:"dependencies,omitempty"`
}

// Plan is the planner's output. RollbackHint suggests which step is the
// last safe point if the migration must be reversed.
type Plan struct {
	TargetTier   cbom.Tier `json:"target_tier"`
	GeneratedAt  time.Time `json:"generated_at"`
	Steps        []Step    `json:"steps"`
	TotalKeys    int       `json:"total_keys"`
	RollbackHint string    `json:"rollback_hint,omitempty"`
}

// Options shape the schedule. RatePerHour caps how many rotations the
// planner will schedule in a single hour; WindowStart is the earliest
// time a step may be scheduled.
type Options struct {
	TargetTier      cbom.Tier
	WindowStart     time.Time
	RatePerHour     int
	RequireApproval func(c Candidate) bool
	ToAlgorithm     func(c Candidate) string
}

// Build returns a migration plan. Candidates are sorted by Y2Q score
// descending so the highest-risk keys land in the earliest hours; if two
// candidates tie they are ordered deterministically by KeyID so plans are
// reproducible.
func Build(candidates []Candidate, opts Options) Plan {
	if opts.RatePerHour <= 0 {
		opts.RatePerHour = 50
	}
	if opts.WindowStart.IsZero() {
		opts.WindowStart = time.Now().UTC().Add(1 * time.Hour)
	}
	if opts.ToAlgorithm == nil {
		opts.ToAlgorithm = defaultToAlgorithm(opts.TargetTier)
	}
	sorted := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		if c.CurrentTier == opts.TargetTier {
			continue
		}
		sorted = append(sorted, c)
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Y2QScore == sorted[j].Y2QScore {
			return sorted[i].KeyID < sorted[j].KeyID
		}
		return sorted[i].Y2QScore > sorted[j].Y2QScore
	})

	steps := make([]Step, 0, len(sorted))
	for i, c := range sorted {
		hour := i / opts.RatePerHour
		at := opts.WindowStart.Add(time.Duration(hour) * time.Hour)
		requires := false
		if opts.RequireApproval != nil {
			requires = opts.RequireApproval(c)
		}
		steps = append(steps, Step{
			KeyID:            c.KeyID,
			TenantID:         c.TenantID,
			FromAlgorithm:    c.Algorithm,
			ToAlgorithm:      opts.ToAlgorithm(c),
			ScheduledAt:      at,
			RequiresApproval: requires,
			Dependencies:     c.Dependencies,
		})
	}
	hint := ""
	if len(steps) > 0 {
		hint = steps[0].KeyID
	}
	return Plan{
		TargetTier:   opts.TargetTier,
		GeneratedAt:  time.Now().UTC(),
		Steps:        steps,
		TotalKeys:    len(steps),
		RollbackHint: hint,
	}
}

// defaultToAlgorithm picks a sensible target algorithm for a candidate
// based on the requested tier. Operators can override via Options.ToAlgorithm.
func defaultToAlgorithm(target cbom.Tier) func(Candidate) string {
	return func(c Candidate) string {
		switch target {
		case cbom.TierPQCHybrid:
			// Pair the existing classical algorithm with the matched-strength
			// PQC primitive. Symmetric algorithms are wrapped under a hybrid
			// KEM, so they migrate to a wrap-key swap rather than a primitive
			// change; we record that explicitly.
			switch {
			case startsWith(c.Algorithm, "AES-"):
				return "AES-256-GCM+ML-KEM-768"
			case startsWith(c.Algorithm, "RSA-"):
				return "ML-KEM-1024+RSA-3072"
			case startsWith(c.Algorithm, "ECDSA"):
				return "ML-DSA-65+ECDSA-P256"
			case startsWith(c.Algorithm, "ECDH"):
				return "ML-KEM-768+ECDH-P256"
			default:
				return "ML-KEM-768"
			}
		case cbom.TierPQCOnly:
			switch {
			case startsWith(c.Algorithm, "RSA-"):
				return "ML-KEM-1024"
			case startsWith(c.Algorithm, "ECDSA"):
				return "ML-DSA-87"
			case startsWith(c.Algorithm, "ECDH"):
				return "ML-KEM-1024"
			default:
				return "ML-DSA-65"
			}
		default:
			return c.Algorithm
		}
	}
}

func startsWith(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if s[i] != prefix[i] {
			return false
		}
	}
	return true
}

// Y2QScore computes the Y2Q risk score from the two operator-controlled
// inputs: data sensitivity (0..1, where 1 is top-secret) and the expected
// decryption window in years (how long the data must remain confidential).
// The score is monotonic, dimensionless, and stable across re-runs.
func Y2QScore(sensitivity float64, decryptionWindowYears float64) float64 {
	if sensitivity < 0 {
		sensitivity = 0
	}
	if sensitivity > 1 {
		sensitivity = 1
	}
	if decryptionWindowYears < 0 {
		decryptionWindowYears = 0
	}
	// Multiply by a constant so scores fall in a human-readable range (~0..1000).
	return sensitivity * decryptionWindowYears * 10.0
}
