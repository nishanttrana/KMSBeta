package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

// Inventory, score and plan progress all come from the tenant's keys table:
// affected_keys is counted server-side at creation (a client value is
// rejected), and progress moves only when keys leave from_algorithm.
func TestAgilityFiguresComeFromKeys(t *testing.T) {
	h, svc := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	ctx := context.Background()
	var rsaIDs []string
	for _, alg := range []string{"RSA-2048", "RSA-2048", "AES-256"} {
		k, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "k-" + alg, Algorithm: alg, KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "tester"})
		if err != nil {
			t.Fatal(err)
		}
		if alg == "RSA-2048" {
			rsaIDs = append(rsaIDs, k.ID)
		}
	}

	rr, out := agilityCall(t, h, http.MethodGet, "/agility/score", "")
	score, _ := out["data"].(map[string]any)
	if rr.Code != http.StatusOK || score["assessed"] != true || score["total_keys"] != float64(3) || score["legacy_key_count"] != float64(2) {
		t.Fatalf("score: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "agility_score_read" || e.Event.Result != "success" {
		t.Fatalf("score event %+v", e)
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

// With no live keys there is nothing to score: the result says so instead of
// reporting a perfect 100/A.
func TestAgilityScoreNotAssessedWithoutKeys(t *testing.T) {
	h, _ := newHandlerForTest(t)
	rr, out := agilityCall(t, h, http.MethodGet, "/agility/score", "")
	score, _ := out["data"].(map[string]any)
	if rr.Code != http.StatusOK || score["assessed"] != false || score["score"] != float64(0) || score["grade"] != "" {
		t.Fatalf("empty tenant scored: %d %s", rr.Code, rr.Body)
	}
}
