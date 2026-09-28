package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vecta-kms/pkg/cryptocatalog"
	"vecta-kms/pkg/route/routetest"
)

func agilityCall(t *testing.T, h *Handler, method, path, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	serveAsAdmin(h, rr, httptest.NewRequest(method, path, strings.NewReader(body)))
	out := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

// Inventory, posture and plan progress all come from the tenant's keys table:
// affected_keys is counted server-side at creation (a client value is
// rejected), and progress moves only when keys leave from_algorithm.
func TestAgilityFiguresComeFromKeys(t *testing.T) {
	h, svc := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	ctx := context.Background()
	var rsaIDs []string
	for _, alg := range []string{"RSA-2048", "RSA-2048", "AES-256", "RSA"} {
		k, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "k-" + alg, Algorithm: alg, KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "tester"})
		if err != nil {
			t.Fatal(err)
		}
		if alg == "RSA-2048" {
			rsaIDs = append(rsaIDs, k.ID)
		}
	}

	rr, out := agilityCall(t, h, http.MethodGet, "/agility/posture", "")
	posture, _ := out["data"].(map[string]any)
	if rr.Code != http.StatusOK || posture["assessed"] != true || posture["total_keys"] != float64(4) ||
		posture["quantum_vulnerable_keys"] != float64(2) || posture["not_assessed_keys"] != float64(1) {
		t.Fatalf("posture: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "agility_posture_read" || e.Event.Result != "success" || e.Event.Details["quantum_vulnerable_keys"] != 2 {
		t.Fatalf("posture event %+v", e)
	}

	if rr, _ := agilityCall(t, h, http.MethodPost, "/agility/migration-plans",
		`{"tenant_id":"t1","name":"p","from_algorithm":"RSA-2048","to_algorithm":"ML-KEM-768","affected_keys":999}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("client-supplied affected_keys accepted: %d %s", rr.Code, rr.Body)
	}
	rr, out = agilityCall(t, h, http.MethodPost, "/agility/migration-plans",
		`{"tenant_id":"t1","name":"RSA to PQC","from_algorithm":"RSA-2048","to_algorithm":"ML-KEM-768","target_date":"2027-06-30"}`)
	plan, _ := out["data"].(map[string]any)
	if rr.Code != http.StatusCreated || plan["affected_keys"] != float64(2) || plan["completed_keys"] != float64(0) {
		t.Fatalf("create: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "agility_migration_plan_created" || e.Event.Result != "success" || e.Event.TargetID != plan["id"] {
		t.Fatalf("create event %+v", e)
	}

	if err := svc.store.HardDeleteKey(ctx, "t1", rsaIDs[0]); err != nil {
		t.Fatal(err)
	}
	_, out = agilityCall(t, h, http.MethodGet, "/agility/migration-plans", "")
	plans, _ := out["data"].([]any)
	if len(plans) != 1 {
		t.Fatalf("plans %v", out)
	}
	got := plans[0].(map[string]any)
	if got["completed_keys"] != float64(1) || got["remaining_keys"] != float64(1) {
		t.Fatalf("progress not derived from keys: %v", got)
	}

	if rr, _ := agilityCall(t, h, http.MethodPatch, "/agility/migration-plans/"+plan["id"].(string), `{"status":"in_progress","completed_keys":2}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("client-supplied completed_keys accepted: %d", rr.Code)
	}
	rr, out = agilityCall(t, h, http.MethodPatch, "/agility/migration-plans/"+plan["id"].(string), `{"status":"in_progress"}`)
	if upd, _ := out["data"].(map[string]any); rr.Code != http.StatusOK || upd["status"] != "in_progress" || upd["completed_keys"] != float64(1) {
		t.Fatalf("update: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "agility_migration_plan_updated" || e.Event.Details["status"] != "in_progress" {
		t.Fatalf("update event %+v", e)
	}
	for path, action := range map[string]string{
		"/agility/algorithms":                           "agility_inventory_read",
		"/agility/keys-by-algorithm?algorithm=RSA-2048": "agility_keys_by_algorithm_read",
		"/agility/migration-plans":                      "agility_migration_plans_listed",
	} {
		if rr, _ := agilityCall(t, h, http.MethodGet, path, ""); rr.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", path, rr.Code, rr.Body)
		}
		if e := rec.Last(t); e.Action != action || e.Event.Result != "success" {
			t.Fatalf("%s audited as %+v", path, e)
		}
	}
}

// A plan cannot be written into another tenant by naming it in the body (the
// old handler trusted body tenant_id without checking the token).
func TestAgilityPlanTenantSmugglingRefused(t *testing.T) {
	h, _ := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	rr, _ := agilityCall(t, h, http.MethodPost, "/agility/migration-plans",
		`{"tenant_id":"t2","name":"x","from_algorithm":"RSA-2048","to_algorithm":"ML-KEM-768"}`)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant create: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "agility_migration_plan_created" || e.Event.Result != "refused" || e.Event.Details["reason"] != "tenant_mismatch" {
		t.Fatalf("refusal event %+v", e)
	}
}

func TestAgilityRoutesRefusalsAudited(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.agilityRouter(rec), rec)
}

// With no live keys there is nothing to measure: the result says so.
func TestAgilityPostureNotAssessedWithoutKeys(t *testing.T) {
	h, _ := newHandlerForTest(t)
	rr, out := agilityCall(t, h, http.MethodGet, "/agility/posture", "")
	p, _ := out["data"].(map[string]any)
	if rr.Code != http.StatusOK || p["assessed"] != false || p["total_keys"] != float64(0) {
		t.Fatalf("empty tenant assessed: %d %s", rr.Code, rr.Body)
	}
}

// The posture measures live keys against the NIST schedule on a given day.
// Before 3.2.0-beta RSA-2048 and AES-128-CBC were "legacy", SLH-DSA was not
// quantum-safe, and a 0-100 score with invented weights stood in for this.
func TestAgilityPostureAgainstNISTSchedule(t *testing.T) {
	day := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	p := computeAgilityPosture([]AlgorithmUsage{
		{Algorithm: "RSA-2048", KeyCount: 3},
		{Algorithm: "AES-128-CBC", KeyCount: 2},
		{Algorithm: "SLH-DSA-SHA2-128s", KeyCount: 1},
		{Algorithm: "3DES", KeyCount: 1},
		{Algorithm: "ECDSA", KeyCount: 1},
	}, day)
	if !p.Assessed || p.TotalKeys != 8 || p.QuantumVulnerableKeys != 3 || p.PostQuantumKeys != 1 || p.NotAssessedKeys != 1 {
		t.Fatalf("posture counts: %+v", p)
	}
	if p.StatusCounts[cryptocatalog.Acceptable] != 6 || p.StatusCounts[cryptocatalog.LegacyUse] != 1 {
		t.Fatalf("status counts: %+v", p.StatusCounts)
	}
	byAlg := map[string]AlgorithmUsage{}
	for _, a := range p.Algorithms {
		byAlg[a.Algorithm] = a
	}
	if a := byAlg["RSA-2048"]; a.Status != cryptocatalog.Acceptable || a.SecurityBits != 112 || a.NextChange == nil || a.NextChange.From != "2031-01-01" {
		t.Fatalf("RSA-2048: %+v", a)
	}
	if a := byAlg["SLH-DSA-SHA2-128s"]; !a.PostQuantum || a.QuantumVulnerable || a.PQCCategory != 1 {
		t.Fatalf("SLH-DSA: %+v", a)
	}
	if a := byAlg["ECDSA"]; a.Assessed || a.Status != "" {
		t.Fatalf("bare ECDSA must not be assessed: %+v", a)
	}
	if len(p.Milestones) != 2 || p.Milestones[0].Date != "2031-01-01" || p.Milestones[0].KeyCount != 3 ||
		p.Milestones[1].Date != "2036-01-01" || p.Milestones[1].Citation != "IR 8547 ipd, Tables 2 and 4" {
		t.Fatalf("milestones: %+v", p.Milestones)
	}
	joined := strings.Join(p.Findings, "\n")
	for _, want := range []string{"no longer allows for new protection: 1 (3DES)", "become disallowed on 2036-01-01 (IR 8547 ipd, Tables 2 and 4): 3 (RSA-2048)", "not assessed: 1 (ECDSA)"} {
		if !strings.Contains(joined, want) {
			t.Errorf("findings missing %q:\n%s", want, joined)
		}
	}
	for _, s := range p.Sources {
		if s.ID == cryptocatalog.SrcIR8547 && s.Revision != "ipd" {
			t.Fatalf("IR 8547 must be cited as a draft: %+v", s)
		}
	}
}
