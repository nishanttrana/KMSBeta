package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"vecta-kms/pkg/cryptocatalog"
)

// The customer decides what to migrate and when. An AgilityRule covers a set
// of algorithms and, from the customer's effective date, marks keys that use
// them deprecated (still usable, flagged), decrypt_only (new protection
// refused; decrypt, verify, unwrap and decapsulate still work) or disallowed
// (every cryptographic operation refused). Keycore enforces the rules on
// every key operation (agility_enforce.go). The product ships no rules and no
// dates of its own; pkg/cryptocatalog supplies only technical facts.

const (
	ActionDeprecated  = "deprecated"
	ActionDecryptOnly = "decrypt_only"
	ActionDisallowed  = "disallowed"
)

var actionRank = map[string]int{ActionDeprecated: 1, ActionDecryptOnly: 2, ActionDisallowed: 3}

// Match kinds: an exact algorithm, a family (RSA, ECDSA, AES…), every
// quantum-vulnerable algorithm, every weak algorithm, or everything below a
// security strength in bits.
const (
	MatchAlgorithm         = "algorithm"
	MatchFamily            = "family"
	MatchQuantumVulnerable = "quantum_vulnerable"
	MatchWeak              = "weak"
	MatchBelowStrength     = "below_strength"
)

// AgilityRule is one rule of the tenant's migration policy.
type AgilityRule struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	Name            string    `json:"name"`
	MatchKind       string    `json:"match_kind"`
	MatchValue      string    `json:"match_value,omitempty"`
	Action          string    `json:"action"`
	EffectiveDate   time.Time `json:"effective_date"`
	TargetAlgorithm string    `json:"target_algorithm,omitempty"`
	Note            string    `json:"note,omitempty"`
	CreatedBy       string    `json:"created_by,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// matches reports whether the rule covers algorithm alg.
func (r AgilityRule) matches(alg string) bool {
	e, known := cryptocatalog.Lookup(alg)
	switch r.MatchKind {
	case MatchAlgorithm:
		return strings.EqualFold(strings.TrimSpace(alg), r.MatchValue) || (known && strings.EqualFold(e.Algorithm, r.MatchValue))
	case MatchFamily:
		return known && strings.EqualFold(e.Family, r.MatchValue)
	case MatchQuantumVulnerable:
		return known && e.QuantumVulnerable
	case MatchWeak:
		return known && e.Weak
	case MatchBelowStrength:
		n, err := strconv.Atoi(r.MatchValue)
		return err == nil && known && e.SecurityBits > 0 && e.SecurityBits < n
	}
	return false
}

// PolicyChange is a future step of the tenant's policy for an algorithm.
type PolicyChange struct {
	Date            string `json:"date"`
	Action          string `json:"action"`
	RuleID          string `json:"rule_id"`
	RuleName        string `json:"rule_name"`
	TargetAlgorithm string `json:"target_algorithm,omitempty"`
}

// policyFor is the strictest rule covering alg that is in force on day now,
// and the next stricter rule scheduled after it.
func policyFor(rules []AgilityRule, alg string, now time.Time) (current *AgilityRule, next *AgilityRule) {
	for i := range rules {
		r := &rules[i]
		if !r.matches(alg) {
			continue
		}
		if !r.EffectiveDate.After(now) {
			if current == nil || actionRank[r.Action] > actionRank[current.Action] {
				current = r
			}
		}
	}
	for i := range rules {
		r := &rules[i]
		if !r.matches(alg) || !r.EffectiveDate.After(now) {
			continue
		}
		if current != nil && actionRank[r.Action] <= actionRank[current.Action] {
			continue
		}
		if next == nil || r.EffectiveDate.Before(next.EffectiveDate) ||
			(r.EffectiveDate.Equal(next.EffectiveDate) && actionRank[r.Action] > actionRank[next.Action]) {
			next = r
		}
	}
	return current, next
}

// AlgorithmUsage is one algorithm in the tenant's live keys, with its
// technical facts (pkg/cryptocatalog) and what the tenant's policy says
// about it. Assessed is false when the name does not identify a parameter
// set (e.g. "RSA" without a size).
type AlgorithmUsage struct {
	Algorithm         string  `json:"algorithm"`
	KeyCount          int     `json:"key_count"`
	Percentage        float64 `json:"percentage"`
	Assessed          bool    `json:"assessed"`
	Canonical         string  `json:"canonical,omitempty"`
	Family            string  `json:"family,omitempty"`
	SecurityBits      int     `json:"security_bits,omitempty"`
	PQCCategory       int     `json:"pqc_category,omitempty"`
	QuantumVulnerable bool    `json:"quantum_vulnerable"`
	PostQuantum       bool    `json:"post_quantum"`
	Weak              bool    `json:"weak"`
	Note              string  `json:"note,omitempty"`
	// PolicyStatus is "allowed" when no rule is in force.
	PolicyStatus    string        `json:"policy_status"`
	PolicyRule      string        `json:"policy_rule,omitempty"`
	TargetAlgorithm string        `json:"target_algorithm,omitempty"`
	NextChange      *PolicyChange `json:"next_change,omitempty"`
}

// PolicyMilestone is a future step of the tenant's policy and the live keys
// it reaches.
type PolicyMilestone struct {
	PolicyChange
	KeyCount   int      `json:"key_count"`
	Algorithms []string `json:"algorithms"`
}

// AgilityPosture is the tenant's live keys measured against its own
// migration policy.
type AgilityPosture struct {
	// Assessed is false when the tenant has no live keys.
	Assessed              bool              `json:"assessed"`
	AsOf                  string            `json:"as_of"`
	TotalKeys             int               `json:"total_keys"`
	NotAssessedKeys       int               `json:"not_assessed_keys"`
	QuantumVulnerableKeys int               `json:"quantum_vulnerable_keys"`
	PostQuantumKeys       int               `json:"post_quantum_keys"`
	WeakKeys              int               `json:"weak_keys"`
	UncoveredKeys         int               `json:"uncovered_keys"` // weak or quantum-vulnerable with no rule
	PolicyRules           int               `json:"policy_rules"`
	StatusCounts          map[string]int    `json:"status_counts"` // live keys by policy status today
	Milestones            []PolicyMilestone `json:"milestones"`
	Algorithms            []AlgorithmUsage  `json:"algorithms"`
	Findings              []string          `json:"findings"`
}

// KeysByAlgorithm lists keys grouped under a specific algorithm.
type KeysByAlgorithm struct {
	Algorithm string `json:"algorithm"`
	Keys      []Key  `json:"keys"`
}

// MigrationPlan describes a planned algorithm migration.
type MigrationPlan struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	Name          string     `json:"name"`
	FromAlgorithm string     `json:"from_algorithm"`
	ToAlgorithm   string     `json:"to_algorithm"`
	AffectedKeys  int        `json:"affected_keys"`  // live from_algorithm keys when the plan was created
	CompletedKeys int        `json:"completed_keys"` // derived: affected_keys - remaining_keys, floored at 0
	RemainingKeys int        `json:"remaining_keys"` // derived: live from_algorithm keys now
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	TargetDate    *time.Time `json:"target_date,omitempty"`
}

func changeOf(r *AgilityRule) *PolicyChange {
	if r == nil {
		return nil
	}
	return &PolicyChange{Date: r.EffectiveDate.UTC().Format("2006-01-02"), Action: r.Action, RuleID: r.ID, RuleName: r.Name, TargetAlgorithm: r.TargetAlgorithm}
}

// computeAgilityPosture annotates the live-key distribution with catalogue
// facts and the tenant's rules, on day now.
func computeAgilityPosture(algos []AlgorithmUsage, rules []AgilityRule, now time.Time) AgilityPosture {
	p := AgilityPosture{
		AsOf: now.UTC().Format("2006-01-02"), Algorithms: algos, PolicyRules: len(rules),
		StatusCounts: map[string]int{}, Milestones: []PolicyMilestone{}, Findings: []string{},
	}
	for i := range algos {
		p.TotalKeys += algos[i].KeyCount
	}
	if p.TotalKeys == 0 {
		return p
	}
	p.Assessed = true
	milestones := map[string]*PolicyMilestone{}
	for i := range algos {
		a := &algos[i]
		a.Percentage = float64(a.KeyCount) / float64(p.TotalKeys) * 100
		current, next := policyFor(rules, a.Algorithm, now)
		a.PolicyStatus = "allowed"
		if current != nil {
			a.PolicyStatus, a.PolicyRule, a.TargetAlgorithm = current.Action, current.Name, current.TargetAlgorithm
		}
		if next != nil {
			a.NextChange = changeOf(next)
			if a.TargetAlgorithm == "" {
				a.TargetAlgorithm = next.TargetAlgorithm
			}
			k := next.ID
			if milestones[k] == nil {
				milestones[k] = &PolicyMilestone{PolicyChange: *changeOf(next), Algorithms: []string{}}
			}
			milestones[k].KeyCount += a.KeyCount
			milestones[k].Algorithms = append(milestones[k].Algorithms, a.Algorithm)
		}
		p.StatusCounts[a.PolicyStatus] += a.KeyCount
		e, ok := cryptocatalog.Lookup(a.Algorithm)
		if !ok {
			p.NotAssessedKeys += a.KeyCount
			continue
		}
		a.Assessed, a.Canonical, a.Family = true, e.Algorithm, e.Family
		a.SecurityBits, a.PQCCategory = e.SecurityBits, e.PQCCategory
		a.QuantumVulnerable, a.PostQuantum, a.Weak, a.Note = e.QuantumVulnerable, e.PostQuantum, e.Weak, e.Note
		if e.QuantumVulnerable {
			p.QuantumVulnerableKeys += a.KeyCount
		}
		if e.PostQuantum {
			p.PostQuantumKeys += a.KeyCount
		}
		if e.Weak {
			p.WeakKeys += a.KeyCount
		}
		if (e.Weak || e.QuantumVulnerable) && current == nil && next == nil {
			p.UncoveredKeys += a.KeyCount
		}
	}
	for _, m := range milestones {
		p.Milestones = append(p.Milestones, *m)
	}
	sort.Slice(p.Milestones, func(i, j int) bool { return p.Milestones[i].Date < p.Milestones[j].Date })
	p.Findings = agilityFindings(p)
	return p
}

// agilityFindings states what the measurements mean. It adds nothing when
// there is nothing to act on.
func agilityFindings(p AgilityPosture) []string {
	out := []string{}
	pick := func(match func(AlgorithmUsage) bool) (int, string) {
		n, names := 0, []string{}
		for _, a := range p.Algorithms {
			if match(a) {
				n += a.KeyCount
				names = append(names, a.Algorithm)
			}
		}
		return n, strings.Join(names, ", ")
	}
	if n, names := pick(func(a AlgorithmUsage) bool { return a.PolicyStatus == ActionDisallowed }); n > 0 {
		out = append(out, fmt.Sprintf("Your policy disallows %s (every operation refused): %s. Migrate or destroy them.", keysN(n), names))
	}
	if n, names := pick(func(a AlgorithmUsage) bool { return a.PolicyStatus == ActionDecryptOnly }); n > 0 {
		out = append(out, fmt.Sprintf("Your policy limits %s to decrypt and verify: %s. Re-protect their data under the target algorithm.", keysN(n), names))
	}
	if n, names := pick(func(a AlgorithmUsage) bool {
		return a.Weak && a.PolicyStatus == "allowed" && a.NextChange == nil
	}); n > 0 {
		out = append(out, fmt.Sprintf("No rule covers %s on weak algorithms: %s. Add a rule to your migration policy.", keysN(n), names))
	}
	if n, names := pick(func(a AlgorithmUsage) bool {
		return a.QuantumVulnerable && !a.Weak && a.PolicyStatus == "allowed" && a.NextChange == nil
	}); n > 0 {
		out = append(out, fmt.Sprintf("No rule covers %s on quantum-vulnerable algorithms: %s. Decide when to move them to ML-KEM or ML-DSA and add a rule.", keysN(n), names))
	}
	if n, names := pick(func(a AlgorithmUsage) bool { return !a.Assessed }); n > 0 {
		out = append(out, fmt.Sprintf("Not assessed (the algorithm name states no parameter set): %s on %s.", keysN(n), names))
	}
	return out
}

func keysN(n int) string {
	if n == 1 {
		return "1 live key"
	}
	return strconv.Itoa(n) + " live keys"
}
