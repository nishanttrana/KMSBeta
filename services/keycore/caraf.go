package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Crypto agility risk assessment (CARAF). The customer names the threats
// that drive their migration and when they expect each (Z, years), and
// profiles their assets: how long the data or device must stay protected
// (X, shelf life), how long moving it would take (Y), the cost of doing so,
// and the algorithms and keys it uses. Keycore computes, per asset, whether
// X + Y outruns the soonest threat that reaches its algorithms, suggests a
// mitigation from the CARAF matrix, and tracks the decision the customer
// records. Every input is the customer's; nothing is estimated.

const (
	TimelineExposed     = "exposed"       // X + Y > Z
	TimelineAtLimit     = "at_limit"      // X + Y = Z
	TimelineTimeToSpare = "time_to_spare" // X + Y < Z
	TimelineNotAssessed = "not_assessed"  // X or Y not recorded
	TimelineNoThreat    = "no_threat"     // no recorded threat reaches its algorithms
)

var (
	carafCategories = map[string]bool{"quantum": true, "cryptanalytic": true, "regulatory": true, "business": true, "other": true}
	carafOwnership  = map[string]bool{"enterprise": true, "third_party": true, "unknown": true}
	carafImpl       = map[string]bool{"software": true, "hardware": true, "hsm": true, "cloud_service": true, "embedded": true, "unknown": true}
	carafPQC        = map[string]bool{"supported": true, "planned": true, "none": true, "unknown": true}
	carafLocation   = map[string]bool{"on_prem": true, "cloud": true, "hybrid": true, "edge": true, "unknown": true}
	carafLevels     = map[string]bool{"low": true, "medium": true, "high": true, "critical": true, "unknown": true}
	carafCost       = map[string]bool{"low": true, "medium": true, "high": true, "unknown": true}
	carafDecisions  = map[string]bool{"secure": true, "accept": true, "phase_out": true, "compensating_control": true}
	carafStatuses   = map[string]bool{"open": true, "in_progress": true, "done": true}
)

// CarafThreat is a threat the customer plans for. Its match fields use the
// migration-rule vocabulary (algorithm, family, quantum_vulnerable, weak,
// below_strength).
type CarafThreat struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	Name          string    `json:"name"`
	Category      string    `json:"category"`
	MatchKind     string    `json:"match_kind"`
	MatchValue    string    `json:"match_value,omitempty"`
	YearsToThreat int       `json:"years_to_threat"` // Z: 0 means it is here now
	Note          string    `json:"note,omitempty"`
	CreatedBy     string    `json:"created_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (t CarafThreat) reaches(alg string) bool {
	return AgilityRule{MatchKind: t.MatchKind, MatchValue: t.MatchValue}.matches(alg)
}

// CarafDecision is the customer's mitigation for an asset.
type CarafDecision struct {
	Decision  string     `json:"decision,omitempty"` // secure, accept, phase_out, compensating_control
	Owner     string     `json:"owner,omitempty"`
	Due       *time.Time `json:"due,omitempty"`       // secure, phase_out, compensating_control
	ReviewBy  *time.Time `json:"review_by,omitempty"` // accept: when the acceptance lapses
	Status    string     `json:"status,omitempty"`    // open, in_progress, done
	Note      string     `json:"note,omitempty"`
	DecidedBy string     `json:"decided_by,omitempty"`
	DecidedAt *time.Time `json:"decided_at,omitempty"`
}

// CarafAsset is a system the customer assesses.
type CarafAsset struct {
	ID             string        `json:"id"`
	TenantID       string        `json:"tenant_id"`
	Name           string        `json:"name"`
	Description    string        `json:"description,omitempty"`
	Owner          string        `json:"owner,omitempty"`
	Ownership      string        `json:"ownership"`
	Implementation string        `json:"implementation"`
	PQCSupport     string        `json:"pqc_support"`
	Location       string        `json:"location"`
	Jurisdiction   string        `json:"jurisdiction,omitempty"`
	Sensitivity    string        `json:"sensitivity"`
	ShelfLifeYears *int          `json:"shelf_life_years,omitempty"` // X
	MigrationYears *int          `json:"migration_years,omitempty"`  // Y
	Cost           string        `json:"cost"`
	Algorithms     []string      `json:"algorithms"`
	KeyIDs         []string      `json:"key_ids"`
	Decision       CarafDecision `json:"decision"`
	CreatedBy      string        `json:"created_by,omitempty"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

// CarafThreatRef is a threat that reaches an asset.
type CarafThreatRef struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	YearsToThreat int      `json:"years_to_threat"`
	Algorithms    []string `json:"algorithms"`
}

// CarafAssetAssessment is one asset measured against the threats.
type CarafAssetAssessment struct {
	Asset         CarafAsset       `json:"asset"`
	Algorithms    []string         `json:"algorithms"`   // recorded plus those of its live linked keys
	MissingKeys   []string         `json:"missing_keys"` // linked IDs that are not live keys
	Threats       []CarafThreatRef `json:"threats"`
	X             *int             `json:"x,omitempty"`
	Y             *int             `json:"y,omitempty"`
	Z             *int             `json:"z,omitempty"`
	Timeline      string           `json:"timeline"`
	MarginYears   *int             `json:"margin_years,omitempty"` // Z - (X + Y)
	Missing       []string         `json:"missing"`
	Suggestion    string           `json:"suggestion,omitempty"`
	DecisionState string           `json:"decision_state"`
}

// CarafRoadmapItem is a recorded decision with its date.
type CarafRoadmapItem struct {
	AssetID  string `json:"asset_id"`
	Asset    string `json:"asset"`
	Decision string `json:"decision"`
	Owner    string `json:"owner"`
	Date     string `json:"date"` // due, or review_by for an acceptance
	State    string `json:"state"`
}

// CarafSummary counts assets by timeline and decision state.
type CarafSummary struct {
	Assets            int `json:"assets"`
	Threats           int `json:"threats"`
	Exposed           int `json:"exposed"`
	AtLimit           int `json:"at_limit"`
	TimeToSpare       int `json:"time_to_spare"`
	NotAssessed       int `json:"not_assessed"`
	NoThreat          int `json:"no_threat"`
	UndecidedAtRisk   int `json:"undecided_at_risk"`
	Overdue           int `json:"overdue"`
	AcceptanceExpired int `json:"acceptance_expired"`
}

// CarafProfile counts how many assets carry each part of their profile:
// how much of the assessment rests on recorded values. A value left
// unknown is not counted.
type CarafProfile struct {
	Owner         int `json:"owner"`
	ShelfLife     int `json:"shelf_life"`     // X
	MigrationTime int `json:"migration_time"` // Y
	Cost          int `json:"cost"`
	Sensitivity   int `json:"sensitivity"`
	LiveKeys      int `json:"live_keys"` // linked to at least one live key
	Complete      int `json:"complete"`  // all of the above
}

// CarafAssessment is the tenant's assessment on one day.
type CarafAssessment struct {
	AsOf    string       `json:"as_of"`
	Summary CarafSummary `json:"summary"`
	Profile CarafProfile `json:"profile"`
	// Heatmap counts assets by sensitivity (low, medium, high, critical,
	// unknown) and timeline.
	Heatmap  map[string]map[string]int `json:"heatmap"`
	Assets   []CarafAssetAssessment    `json:"assets"`
	Roadmap  []CarafRoadmapItem        `json:"roadmap"`
	Findings []string                  `json:"findings"`
}

// carafSuggestion is the CARAF mitigation matrix: with time to spare, a
// cheap asset is phased out and an expensive one's risk accepted; when
// exposed, a cheap asset is secured and an expensive one phased out. Medium
// or unknown cost is the customer's call.
func carafSuggestion(timeline, cost string) string {
	atRisk := timeline == TimelineExposed || timeline == TimelineAtLimit
	switch {
	case timeline == TimelineTimeToSpare && cost == "low":
		return "phase_out"
	case timeline == TimelineTimeToSpare && cost == "high":
		return "accept"
	case atRisk && cost == "low":
		return "secure"
	case atRisk && cost == "high":
		return "phase_out"
	}
	return ""
}

func decisionState(d CarafDecision, today string) string {
	switch {
	case d.Decision == "":
		return "undecided"
	case d.Decision == "accept":
		if d.ReviewBy != nil && d.ReviewBy.Format("2006-01-02") < today {
			return "acceptance_expired"
		}
		return "accepted"
	case d.Status == "done":
		return "done"
	case d.Due != nil && d.Due.Format("2006-01-02") < today:
		return "overdue"
	case d.Status == "":
		return "open"
	}
	return d.Status
}

// computeCarafAssessment measures each asset on day now. liveKeyAlgorithms
// maps each live key ID to its algorithm.
func computeCarafAssessment(assets []CarafAsset, threats []CarafThreat, liveKeyAlgorithms map[string]string, now time.Time) CarafAssessment {
	today := now.UTC().Format("2006-01-02")
	out := CarafAssessment{AsOf: today, Assets: []CarafAssetAssessment{}, Roadmap: []CarafRoadmapItem{}, Findings: []string{}, Heatmap: map[string]map[string]int{}}
	out.Summary.Assets, out.Summary.Threats = len(assets), len(threats)
	for _, a := range assets {
		as := CarafAssetAssessment{Asset: a, MissingKeys: []string{}, Threats: []CarafThreatRef{}, Missing: []string{}, X: a.ShelfLifeYears, Y: a.MigrationYears}
		seen := map[string]bool{}
		add := func(alg string) {
			if alg = strings.TrimSpace(alg); alg != "" && !seen[strings.ToUpper(alg)] {
				seen[strings.ToUpper(alg)] = true
				as.Algorithms = append(as.Algorithms, alg)
			}
		}
		for _, alg := range a.Algorithms {
			add(alg)
		}
		for _, id := range a.KeyIDs {
			if alg, ok := liveKeyAlgorithms[id]; ok {
				add(alg)
			} else {
				as.MissingKeys = append(as.MissingKeys, id)
			}
		}
		if as.Algorithms == nil {
			as.Algorithms = []string{}
		}
		for _, t := range threats {
			ref := CarafThreatRef{ID: t.ID, Name: t.Name, YearsToThreat: t.YearsToThreat, Algorithms: []string{}}
			for _, alg := range as.Algorithms {
				if t.reaches(alg) {
					ref.Algorithms = append(ref.Algorithms, alg)
				}
			}
			if len(ref.Algorithms) > 0 {
				as.Threats = append(as.Threats, ref)
				if as.Z == nil || t.YearsToThreat < *as.Z {
					z := t.YearsToThreat
					as.Z = &z
				}
			}
		}
		if as.X == nil {
			as.Missing = append(as.Missing, "shelf_life_years")
		}
		if as.Y == nil {
			as.Missing = append(as.Missing, "migration_years")
		}
		switch {
		case as.Z == nil:
			as.Timeline = TimelineNoThreat
		case len(as.Missing) > 0:
			as.Timeline = TimelineNotAssessed
		default:
			m := *as.Z - (*as.X + *as.Y)
			as.MarginYears = &m
			as.Timeline = map[bool]string{true: TimelineExposed, false: TimelineTimeToSpare}[m < 0]
			if m == 0 {
				as.Timeline = TimelineAtLimit
			}
		}
		out.Profile.add(a, len(a.KeyIDs) > len(as.MissingKeys))
		sens := a.Sensitivity
		if sens == "" {
			sens = "unknown"
		}
		if out.Heatmap[sens] == nil {
			out.Heatmap[sens] = map[string]int{}
		}
		out.Heatmap[sens][as.Timeline]++
		as.Suggestion = carafSuggestion(as.Timeline, a.Cost)
		as.DecisionState = decisionState(a.Decision, today)
		switch as.Timeline {
		case TimelineExposed:
			out.Summary.Exposed++
		case TimelineAtLimit:
			out.Summary.AtLimit++
		case TimelineTimeToSpare:
			out.Summary.TimeToSpare++
		case TimelineNotAssessed:
			out.Summary.NotAssessed++
		case TimelineNoThreat:
			out.Summary.NoThreat++
		}
		if (as.Timeline == TimelineExposed || as.Timeline == TimelineAtLimit) && as.DecisionState == "undecided" {
			out.Summary.UndecidedAtRisk++
		}
		switch as.DecisionState {
		case "overdue":
			out.Summary.Overdue++
		case "acceptance_expired":
			out.Summary.AcceptanceExpired++
		}
		if d := a.Decision; d.Decision != "" {
			item := CarafRoadmapItem{AssetID: a.ID, Asset: a.Name, Decision: d.Decision, Owner: d.Owner, State: as.DecisionState}
			if d.Decision == "accept" && d.ReviewBy != nil {
				item.Date = d.ReviewBy.Format("2006-01-02")
			} else if d.Due != nil {
				item.Date = d.Due.Format("2006-01-02")
			}
			out.Roadmap = append(out.Roadmap, item)
		}
		out.Assets = append(out.Assets, as)
	}
	sort.SliceStable(out.Roadmap, func(i, j int) bool { return out.Roadmap[i].Date < out.Roadmap[j].Date })
	out.Findings = carafFindings(out)
	return out
}

func (p *CarafProfile) add(a CarafAsset, liveKey bool) {
	known := func(v string) bool { v = strings.TrimSpace(v); return v != "" && v != "unknown" }
	parts := []bool{known(a.Owner), a.ShelfLifeYears != nil, a.MigrationYears != nil, known(a.Cost), known(a.Sensitivity), liveKey}
	counts := []*int{&p.Owner, &p.ShelfLife, &p.MigrationTime, &p.Cost, &p.Sensitivity, &p.LiveKeys}
	complete := true
	for i, ok := range parts {
		if ok {
			*counts[i]++
		}
		complete = complete && ok
	}
	if complete {
		p.Complete++
	}
}

func carafFindings(a CarafAssessment) []string {
	out := []string{}
	names := func(match func(CarafAssetAssessment) bool) (int, string) {
		n, list := 0, []string{}
		for _, x := range a.Assets {
			if match(x) {
				n++
				list = append(list, x.Asset.Name)
			}
		}
		return n, strings.Join(list, ", ")
	}
	if a.Summary.Threats == 0 {
		out = append(out, "No threats recorded: add the threats that drive your migration, with the years you expect each, to assess your assets.")
	}
	if n, l := names(func(x CarafAssetAssessment) bool {
		return (x.Timeline == TimelineExposed || x.Timeline == TimelineAtLimit) && x.DecisionState == "undecided"
	}); n > 0 {
		out = append(out, fmt.Sprintf("Exposed with no decision (%d): %s. Record how each will be secured, accepted or phased out.", n, l))
	}
	if n, l := names(func(x CarafAssetAssessment) bool { return x.DecisionState == "acceptance_expired" }); n > 0 {
		out = append(out, fmt.Sprintf("Risk acceptances past their review date (%d): %s.", n, l))
	}
	if n, l := names(func(x CarafAssetAssessment) bool { return x.DecisionState == "overdue" }); n > 0 {
		out = append(out, fmt.Sprintf("Decisions past their due date (%d): %s.", n, l))
	}
	if n, l := names(func(x CarafAssetAssessment) bool { return x.Timeline == TimelineNotAssessed }); n > 0 {
		out = append(out, fmt.Sprintf("Not assessed until shelf life and migration time are recorded (%d): %s.", n, l))
	}
	if n, l := names(func(x CarafAssetAssessment) bool { return len(x.MissingKeys) > 0 }); n > 0 {
		out = append(out, fmt.Sprintf("Linked keys that are no longer live (%d assets): %s.", n, l))
	}
	return out
}
