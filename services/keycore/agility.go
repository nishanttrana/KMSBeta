package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"vecta-kms/pkg/cryptocatalog"
)

// AlgorithmUsage is one algorithm in the tenant's live keys, with what NIST
// says about it (pkg/cryptocatalog). Assessed is false when the name does
// not identify a parameter set (e.g. "RSA" without a size): no status is
// shown for it.
type AlgorithmUsage struct {
	Algorithm         string               `json:"algorithm"`
	KeyCount          int                  `json:"key_count"`
	Percentage        float64              `json:"percentage"`
	Assessed          bool                 `json:"assessed"`
	Canonical         string               `json:"canonical,omitempty"`
	Family            string               `json:"family,omitempty"`
	SecurityBits      int                  `json:"security_bits,omitempty"`
	PQCCategory       int                  `json:"pqc_category,omitempty"`
	QuantumVulnerable bool                 `json:"quantum_vulnerable"`
	PostQuantum       bool                 `json:"post_quantum"`
	Status            cryptocatalog.Status `json:"nist_status,omitempty"`
	NextChange        *cryptocatalog.Step  `json:"next_change,omitempty"`
	Schedule          []cryptocatalog.Step `json:"schedule,omitempty"`
	Note              string               `json:"note,omitempty"`
}

// TransitionMilestone is a dated NIST status change and the live keys it
// reaches.
type TransitionMilestone struct {
	cryptocatalog.Milestone
	Citation   string   `json:"citation"`
	KeyCount   int      `json:"key_count"`
	Algorithms []string `json:"algorithms"`
}

// AgilityPosture is the tenant's key inventory measured against NIST's
// transition schedule (CSWP 39-upd1 §2.3: SP 800-131Ar3 and IR 8547). Every
// count is of live keys; every status and date is cited.
type AgilityPosture struct {
	// Assessed is false when the tenant has no live keys.
	Assessed              bool                         `json:"assessed"`
	AsOf                  string                       `json:"as_of"`
	TotalKeys             int                          `json:"total_keys"`
	NotAssessedKeys       int                          `json:"not_assessed_keys"`
	QuantumVulnerableKeys int                          `json:"quantum_vulnerable_keys"`
	PostQuantumKeys       int                          `json:"post_quantum_keys"`
	StatusCounts          map[cryptocatalog.Status]int `json:"status_counts"`
	Milestones            []TransitionMilestone        `json:"milestones"`
	Algorithms            []AlgorithmUsage             `json:"algorithms"`
	Findings              []string                     `json:"findings"`
	Sources               []cryptocatalog.Source       `json:"sources"`
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

// computeAgilityPosture annotates the live-key distribution with catalogue
// entries and measures it on day now.
func computeAgilityPosture(algos []AlgorithmUsage, now time.Time) AgilityPosture {
	p := AgilityPosture{
		AsOf: now.UTC().Format("2006-01-02"), Algorithms: algos,
		StatusCounts: map[cryptocatalog.Status]int{}, Milestones: []TransitionMilestone{},
		Findings: []string{}, Sources: []cryptocatalog.Source{},
	}
	for i := range algos {
		p.TotalKeys += algos[i].KeyCount
	}
	if p.TotalKeys == 0 {
		return p
	}
	p.Assessed = true
	var entries []cryptocatalog.Entry
	sourceSeen := map[string]bool{}
	for i := range algos {
		a := &algos[i]
		a.Percentage = float64(a.KeyCount) / float64(p.TotalKeys) * 100
		e, ok := cryptocatalog.Lookup(a.Algorithm)
		if !ok {
			p.NotAssessedKeys += a.KeyCount
			continue
		}
		entries = append(entries, e)
		a.Assessed, a.Canonical, a.Family = true, e.Algorithm, e.Family
		a.SecurityBits, a.PQCCategory = e.SecurityBits, e.PQCCategory
		a.QuantumVulnerable, a.PostQuantum = e.QuantumVulnerable, e.PostQuantum
		a.Status, a.Schedule, a.Note = e.StatusAt(now), e.Schedule, e.Note
		if next, ok := e.Next(now); ok {
			a.NextChange = &next
		}
		p.StatusCounts[a.Status] += a.KeyCount
		if e.QuantumVulnerable {
			p.QuantumVulnerableKeys += a.KeyCount
		}
		if e.PostQuantum {
			p.PostQuantumKeys += a.KeyCount
		}
		for _, s := range e.Sources() {
			if !sourceSeen[s.ID] {
				sourceSeen[s.ID] = true
				p.Sources = append(p.Sources, s)
			}
		}
	}
	for _, m := range cryptocatalog.Milestones(entries, now) {
		tm := TransitionMilestone{Milestone: m, Citation: cryptocatalog.Cite(m.Source, m.Ref), Algorithms: []string{}}
		for _, a := range algos {
			for _, s := range a.Schedule {
				if s.From == m.Date && s.Status == m.Status && s.Source == m.Source {
					tm.KeyCount += a.KeyCount
					tm.Algorithms = append(tm.Algorithms, a.Algorithm)
					break
				}
			}
		}
		p.Milestones = append(p.Milestones, tm)
	}
	sort.Slice(p.Sources, func(i, j int) bool { return p.Sources[i].ID < p.Sources[j].ID })
	p.Findings = agilityFindings(p)
	return p
}

// agilityFindings states what the measurements mean, citing the source. It
// adds nothing when there is nothing to act on.
func agilityFindings(p AgilityPosture) []string {
	var out []string
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
	if n, names := pick(func(a AlgorithmUsage) bool {
		return a.Assessed && (a.Status == cryptocatalog.Disallowed || a.Status == cryptocatalog.LegacyUse)
	}); n > 0 {
		out = append(out, fmt.Sprintf("Live keys on algorithms NIST no longer allows for new protection: %d (%s). Keep them only to decrypt or verify existing data, and migrate them (SP 800-131Ar3 ipd).", n, names))
	}
	if n, names := pick(func(a AlgorithmUsage) bool { return a.Status == cryptocatalog.NotApproved }); n > 0 {
		out = append(out, fmt.Sprintf("Live keys on algorithms no NIST standard approves: %d (%s) (SP 800-131Ar3 ipd).", n, names))
	}
	if n, names := pick(func(a AlgorithmUsage) bool { return a.Status == cryptocatalog.Deprecated }); n > 0 {
		out = append(out, fmt.Sprintf("Live keys on algorithms NIST deprecates today: %d (%s). Allowed only while the data owner accepts the risk (SP 800-131Ar3 ipd).", n, names))
	}
	for _, m := range p.Milestones {
		if m.Status == cryptocatalog.Disallowed && m.Source == cryptocatalog.SrcIR8547 && m.KeyCount > 0 {
			out = append(out, fmt.Sprintf("Quantum-vulnerable live keys that become disallowed on %s (%s): %d (%s). Plan their migration to ML-KEM or ML-DSA before then.", m.Date, m.Citation, m.KeyCount, strings.Join(m.Algorithms, ", ")))
		}
	}
	if n, names := pick(func(a AlgorithmUsage) bool { return !a.Assessed }); n > 0 {
		out = append(out, fmt.Sprintf("Live keys whose algorithm name states no parameter set, so their NIST status is not assessed: %d (%s).", n, names))
	}
	if out == nil {
		out = []string{}
	}
	return out
}
