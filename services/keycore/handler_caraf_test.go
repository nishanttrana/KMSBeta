package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"vecta-kms/pkg/route/routetest"
)

func iptr(n int) *int { return &n }

// The assessment is arithmetic on the customer's own numbers: X + Y against
// the soonest threat (Z) that reaches the asset's algorithms.
func TestCarafAssessmentComputation(t *testing.T) {
	now := day("2026-09-29")
	past, future := day("2026-01-01"), day("2027-06-30")
	threats := []CarafThreat{
		{ID: "tq", Name: "Quantum computer", Category: "quantum", MatchKind: MatchQuantumVulnerable, YearsToThreat: 10},
		{ID: "tw", Name: "Weak algorithms", Category: "cryptanalytic", MatchKind: MatchWeak, YearsToThreat: 0},
	}
	assets := []CarafAsset{
		{ID: "a1", Name: "IoT fleet", ShelfLifeYears: iptr(12), MigrationYears: iptr(5), Cost: "low", Algorithms: []string{"ECDSA-P256"}},
		{ID: "a2", Name: "Payments", ShelfLifeYears: iptr(3), MigrationYears: iptr(2), Cost: "high", Algorithms: []string{"RSA-2048"},
			Decision: CarafDecision{Decision: "accept", Owner: "cfo", ReviewBy: &past}},
		{ID: "a3", Name: "Legacy app", ShelfLifeYears: iptr(1), MigrationYears: iptr(1), Cost: "high", KeyIDs: []string{"k3des", "kgone"},
			Decision: CarafDecision{Decision: "secure", Owner: "ops", Due: &past, Status: "open"}},
		{ID: "a4", Name: "Web", Cost: "medium", Algorithms: []string{"RSA-3072"}},
		{ID: "a5", Name: "Vault", ShelfLifeYears: iptr(30), MigrationYears: iptr(1), Cost: "low", Algorithms: []string{"AES-256"},
			Decision: CarafDecision{Decision: "phase_out", Owner: "ops", Due: &future, Status: "in_progress"}},
	}
	a := computeCarafAssessment(assets, threats, map[string]string{"k3des": "3DES"}, now)
	by := map[string]CarafAssetAssessment{}
	for _, x := range a.Assets {
		by[x.Asset.ID] = x
	}
	check := func(id, timeline, suggestion, state string, margin *int) {
		t.Helper()
		x := by[id]
		if x.Timeline != timeline || x.Suggestion != suggestion || x.DecisionState != state {
			t.Errorf("%s: timeline=%s suggestion=%s state=%s, want %s %s %s", id, x.Timeline, x.Suggestion, x.DecisionState, timeline, suggestion, state)
		}
		if (margin == nil) != (x.MarginYears == nil) || (margin != nil && *margin != *x.MarginYears) {
			t.Errorf("%s: margin %v, want %v", id, x.MarginYears, margin)
		}
	}
	check("a1", TimelineExposed, "secure", "undecided", iptr(-7))             // 10 - (12 + 5)
	check("a2", TimelineTimeToSpare, "accept", "acceptance_expired", iptr(5)) // 10 - (3 + 2)
	check("a3", TimelineExposed, "phase_out", "overdue", iptr(-2))            // weak: 0 - (1 + 1)
	check("a4", TimelineNotAssessed, "", "undecided", nil)
	check("a5", TimelineNoThreat, "", "in_progress", nil)
	if x := by["a3"]; len(x.Algorithms) != 1 || x.Algorithms[0] != "3DES" || len(x.MissingKeys) != 1 || x.MissingKeys[0] != "kgone" || *x.Z != 0 {
		t.Fatalf("linked keys: %+v", x)
	}
	if x := by["a4"]; len(x.Missing) != 2 {
		t.Fatalf("missing fields: %+v", x.Missing)
	}
	s := a.Summary
	if s.Assets != 5 || s.Threats != 2 || s.Exposed != 2 || s.TimeToSpare != 1 || s.NotAssessed != 1 || s.NoThreat != 1 ||
		s.UndecidedAtRisk != 1 || s.Overdue != 1 || s.AcceptanceExpired != 1 {
		t.Fatalf("summary %+v", s)
	}
	if len(a.Roadmap) != 3 || a.Roadmap[2].AssetID != "a5" || a.Roadmap[2].Date != "2027-06-30" {
		t.Fatalf("roadmap %+v", a.Roadmap)
	}
	joined := strings.Join(a.Findings, "\n")
	for _, want := range []string{"Exposed with no decision (1): IoT fleet", "past their review date (1): Payments", "past their due date (1): Legacy app", "migration time are recorded (1): Web", "no longer live (1 assets): Legacy app"} {
		if !strings.Contains(joined, want) {
			t.Errorf("findings missing %q:\n%s", want, joined)
		}
	}
	if f := computeCarafAssessment(nil, nil, nil, now).Findings; len(f) != 1 || !strings.Contains(f[0], "No threats recorded") {
		t.Fatalf("empty findings %v", f)
	}
}

func TestCarafRoutesValidatedAndAudited(t *testing.T) {
	h, svc := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{TenantID: "t1", Name: "fleet", Algorithm: "ECDSA-P256", KeyType: "symmetric", Purpose: "sign", Owner: "ops", CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		"/agility/caraf/threats": `{"name":"Quantum","category":"quantum","match_kind":"quantum_vulnerable"}`,
		"/agility/caraf/assets":  `{"name":"Fleet","key_ids":["nope"]}`,
	} {
		if rr, _ := agilityCall(t, h, http.MethodPost, path, body); rr.Code != http.StatusBadRequest {
			t.Errorf("%s accepted %s: %d", path, body, rr.Code)
		}
	}
	rr, out := agilityCall(t, h, http.MethodPost, "/agility/caraf/threats", `{"name":"Quantum","category":"quantum","match_kind":"quantum_vulnerable","years_to_threat":10}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("threat: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "caraf_threat_created" || e.Event.Details["years_to_threat"] != 10 {
		t.Fatalf("threat event %+v", e)
	}
	rr, out = agilityCall(t, h, http.MethodPost, "/agility/caraf/assets",
		`{"name":"Fleet","ownership":"third_party","shelf_life_years":12,"migration_years":5,"cost":"low","key_ids":["`+key.ID+`"]}`)
	asset, _ := out["data"].(map[string]any)
	if rr.Code != http.StatusCreated {
		t.Fatalf("asset: %d %s", rr.Code, rr.Body)
	}
	id := asset["id"].(string)
	if rr, _ := agilityCall(t, h, http.MethodPut, "/agility/caraf/assets/"+id+"/decision", `{"decision":"accept","owner":"cfo"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("acceptance without review date: %d", rr.Code)
	}
	if rr, _ := agilityCall(t, h, http.MethodPut, "/agility/caraf/assets/"+id+"/decision", `{"decision":"secure","owner":"ops"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("secure without due date: %d", rr.Code)
	}
	review := time.Now().AddDate(1, 0, 0).Format("2006-01-02")
	if rr, _ := agilityCall(t, h, http.MethodPut, "/agility/caraf/assets/"+id+"/decision", `{"decision":"accept","owner":"cfo","review_by":"`+review+`"}`); rr.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "caraf_decision_recorded" || e.Event.Details["decision"] != "accept" || e.Event.Details["review_by"] != review {
		t.Fatalf("decision event %+v", e)
	}
	// Updating the profile keeps the decision.
	if rr, _ := agilityCall(t, h, http.MethodPut, "/agility/caraf/assets/"+id,
		`{"name":"Fleet","shelf_life_years":12,"migration_years":5,"cost":"low","key_ids":["`+key.ID+`"]}`); rr.Code != http.StatusOK {
		t.Fatalf("update asset: %d %s", rr.Code, rr.Body)
	}
	rr, out = agilityCall(t, h, http.MethodGet, "/agility/caraf/assessment", "")
	data, _ := out["data"].(map[string]any)
	assets, _ := data["assets"].([]any)
	if rr.Code != http.StatusOK || len(assets) != 1 {
		t.Fatalf("assessment: %d %s", rr.Code, rr.Body)
	}
	got := assets[0].(map[string]any)
	if got["timeline"] != TimelineExposed || got["decision_state"] != "accepted" || got["margin_years"] != float64(-7) {
		t.Fatalf("assessed asset %+v", got)
	}
	if e := rec.Last(t); e.Action != "caraf_assessment_read" || e.Event.Details["exposed"] != 1 {
		t.Fatalf("assessment event %+v", e)
	}
	if rr, _ := agilityCall(t, h, http.MethodDelete, "/agility/caraf/assets/"+id, ""); rr.Code != http.StatusOK {
		t.Fatalf("delete: %d", rr.Code)
	}
	if e := rec.Last(t); e.Action != "caraf_asset_deleted" || e.Event.TargetID != id {
		t.Fatalf("delete event %+v", e)
	}
}
