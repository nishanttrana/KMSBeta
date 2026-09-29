package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
		posture["quantum_vulnerable_keys"] != float64(2) || posture["not_assessed_keys"] != float64(1) || posture["uncovered_keys"] != float64(2) {
		t.Fatalf("posture: %d %s", rr.Code, rr.Body)
	}
	if strings.Contains(rr.Body.String(), "NIST") || strings.Contains(rr.Body.String(), "ipd") {
		t.Fatalf("posture quotes a standards source: %s", rr.Body)
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
		"/agility/policy/rules":                         "agility_policy_rules_listed",
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

func day(s string) time.Time { t, _ := time.Parse("2006-01-02", s); return t }

// The posture measures live keys against the customer's own rules; the
// product supplies no dates.
func TestAgilityPostureAgainstCustomerPolicy(t *testing.T) {
	now := day("2026-09-29")
	rules := []AgilityRule{
		{ID: "r1", Name: "weak out", MatchKind: MatchWeak, Action: ActionDisallowed, EffectiveDate: day("2026-01-01")},
		{ID: "r2", Name: "RSA read-only", MatchKind: MatchFamily, MatchValue: "RSA", Action: ActionDecryptOnly, EffectiveDate: day("2027-06-30"), TargetAlgorithm: "ML-DSA-65"},
		{ID: "r3", Name: "RSA flagged", MatchKind: MatchAlgorithm, MatchValue: "RSA-2048", Action: ActionDeprecated, EffectiveDate: day("2026-06-01")},
	}
	p := computeAgilityPosture([]AlgorithmUsage{
		{Algorithm: "RSA-2048", KeyCount: 3},
		{Algorithm: "ECDSA-P256", KeyCount: 2},
		{Algorithm: "3DES", KeyCount: 1},
		{Algorithm: "SLH-DSA-SHA2-128s", KeyCount: 1},
		{Algorithm: "ECDSA", KeyCount: 1},
	}, rules, now)
	if !p.Assessed || p.TotalKeys != 8 || p.QuantumVulnerableKeys != 5 || p.PostQuantumKeys != 1 || p.WeakKeys != 1 ||
		p.NotAssessedKeys != 1 || p.UncoveredKeys != 2 || p.PolicyRules != 3 {
		t.Fatalf("posture counts: %+v", p)
	}
	if p.StatusCounts[ActionDisallowed] != 1 || p.StatusCounts[ActionDeprecated] != 3 || p.StatusCounts["allowed"] != 4 {
		t.Fatalf("status counts: %+v", p.StatusCounts)
	}
	by := map[string]AlgorithmUsage{}
	for _, a := range p.Algorithms {
		by[a.Algorithm] = a
	}
	if a := by["RSA-2048"]; a.PolicyStatus != ActionDeprecated || a.SecurityBits != 112 || a.NextChange == nil ||
		a.NextChange.Date != "2027-06-30" || a.NextChange.Action != ActionDecryptOnly || a.TargetAlgorithm != "ML-DSA-65" {
		t.Fatalf("RSA-2048: %+v", a)
	}
	if a := by["3DES"]; a.PolicyStatus != ActionDisallowed || !a.Weak || a.PolicyRule != "weak out" {
		t.Fatalf("3DES: %+v", a)
	}
	if a := by["ECDSA"]; a.Assessed || a.PolicyStatus != "allowed" {
		t.Fatalf("bare ECDSA: %+v", a)
	}
	if len(p.Milestones) != 1 || p.Milestones[0].Date != "2027-06-30" || p.Milestones[0].KeyCount != 3 || p.Milestones[0].RuleName != "RSA read-only" {
		t.Fatalf("milestones: %+v", p.Milestones)
	}
	joined := strings.Join(p.Findings, "\n")
	for _, want := range []string{"Your policy disallows 1 live key (every operation refused): 3DES", "No rule covers 2 live keys on quantum-vulnerable algorithms: ECDSA-P256", "Not assessed (the algorithm name states no parameter set): 1 live key on ECDSA"} {
		if !strings.Contains(joined, want) {
			t.Errorf("findings missing %q:\n%s", want, joined)
		}
	}
}

func TestAgilityPolicyRulesValidatedAndAudited(t *testing.T) {
	h, _ := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	for body, why := range map[string]string{
		`{"name":"x","match_kind":"family","action":"disallowed","effective_date":"2027-01-01"}`:                                                 "family without a value",
		`{"name":"x","match_kind":"weak","action":"forbid","effective_date":"2027-01-01"}`:                                                       "unknown action",
		`{"name":"x","match_kind":"weak","action":"disallowed"}`:                                                                                 "no effective date",
		`{"name":"x","match_kind":"below_strength","match_value":"lots","action":"deprecated","effective_date":"2027-01-01"}`:                    "strength not a number",
		`{"name":"x","match_kind":"family","match_value":"RSA","action":"decrypt_only","effective_date":"2027-01-01","target_algorithm":"3DES"}`: "weak target",
	} {
		if rr, _ := agilityCall(t, h, http.MethodPost, "/agility/policy/rules", body); rr.Code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", why, rr.Code, rr.Body)
		}
	}
	rr, out := agilityCall(t, h, http.MethodPost, "/agility/policy/rules",
		`{"name":"RSA read-only","match_kind":"family","match_value":"RSA","action":"decrypt_only","effective_date":"2027-06-30","target_algorithm":"ML-DSA-65"}`)
	rule, _ := out["data"].(map[string]any)
	if rr.Code != http.StatusCreated || rule["action"] != "decrypt_only" || rule["created_by"] == "" {
		t.Fatalf("create rule: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "agility_policy_rule_created" || e.Event.TargetID != rule["id"] || e.Event.Details["effective_date"] != "2027-06-30" {
		t.Fatalf("create event %+v", e)
	}
	id := rule["id"].(string)
	rr, _ = agilityCall(t, h, http.MethodPut, "/agility/policy/rules/"+id,
		`{"name":"RSA read-only","match_kind":"family","match_value":"RSA","action":"disallowed","effective_date":"2028-01-01"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("update rule: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "agility_policy_rule_updated" || e.Event.Details["action"] != "disallowed" {
		t.Fatalf("update event %+v", e)
	}
	if rr, _ := agilityCall(t, h, http.MethodDelete, "/agility/policy/rules/"+id, ""); rr.Code != http.StatusOK {
		t.Fatalf("delete rule: %d", rr.Code)
	}
	if e := rec.Last(t); e.Action != "agility_policy_rule_deleted" || e.Event.TargetID != id {
		t.Fatalf("delete event %+v", e)
	}
	if rr, _ := agilityCall(t, h, http.MethodDelete, "/agility/policy/rules/"+id, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("second delete: %d", rr.Code)
	}
}

// The customer's rules are enforced on real key operations, and each
// refusal is audited with a specific reason.
func TestCryptoPolicyEnforcedOnKeyOperations(t *testing.T) {
	store := newStoreForTest(t)
	pub := &captureKeycorePublisher{}
	_, svc := newHandlerForTest(t)
	svc.store, svc.events = store, pub
	ctx := adminCtx()
	key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "k", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	enc, err := svc.Encrypt(ctx, key.ID, EncryptRequest{TenantID: "t1", PlaintextB64: base64.StdEncoding.EncodeToString([]byte("secret"))})
	if err != nil {
		t.Fatal(err)
	}
	setRule := func(action, effective string) {
		svc.invalidateAgilityRules("t1")
		rules, _ := store.ListAgilityRules(ctx, "t1")
		for _, r := range rules {
			_ = store.DeleteAgilityRule(ctx, "t1", r.ID)
		}
		if _, err := store.CreateAgilityRule(ctx, AgilityRule{ID: newID("agrule"), TenantID: "t1", Name: "AES-256 " + action,
			MatchKind: MatchAlgorithm, MatchValue: "AES-256", Action: action, EffectiveDate: day(effective)}); err != nil {
			t.Fatal(err)
		}
	}
	decrypt := func() error {
		_, err := svc.Decrypt(ctx, key.ID, DecryptRequest{TenantID: "t1", CiphertextB64: enc.CipherB64, IVB64: enc.IVB64})
		return err
	}
	encrypt := func() error {
		_, err := svc.Encrypt(ctx, key.ID, EncryptRequest{TenantID: "t1", PlaintextB64: base64.StdEncoding.EncodeToString([]byte("more"))})
		return err
	}

	setRule(ActionDecryptOnly, "2099-01-01") // not yet in force
	if err := encrypt(); err != nil {
		t.Fatalf("a future rule refused an operation: %v", err)
	}

	setRule(ActionDecryptOnly, "2020-01-01")
	var refusal cryptoPolicyRefusal
	var denied policyDeniedError
	if err := encrypt(); !errors.As(err, &refusal) || refusal.Reason != "crypto_policy_decrypt_only" || !errors.As(err, &denied) {
		t.Fatalf("encrypt under decrypt_only: %v", err)
	}
	if d := pub.details(t, "audit.key.crypto_policy_refused"); d["reason"] != "crypto_policy_decrypt_only" || d["operation"] != "key.encrypt" || d["rule_action"] != "decrypt_only" {
		t.Fatalf("refusal event %+v", d)
	}
	if d := pub.details(t, "audit.key.encrypt"); d["result"] != "refused" || d["reason"] != "crypto_policy_decrypt_only" {
		t.Fatalf("op event %+v", d)
	}
	if err := decrypt(); err != nil {
		t.Fatalf("decrypt under decrypt_only: %v", err)
	}
	if _, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "new", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", Owner: "ops", CreatedBy: "tester"}); !errors.As(err, &refusal) {
		t.Fatalf("new key under decrypt_only: %v", err)
	}

	setRule(ActionDisallowed, "2020-01-01")
	if err := decrypt(); !errors.As(err, &refusal) || refusal.Reason != "crypto_policy_disallowed" {
		t.Fatalf("decrypt under disallowed: %v", err)
	}

	setRule(ActionDeprecated, "2020-01-01")
	if err := encrypt(); err != nil {
		t.Fatalf("deprecated refused: %v", err)
	}
}

// A quantum_vulnerable decrypt_only rule is the tenant's post-quantum floor:
// new RSA keys are refused, ML-KEM keys (in the certified module, so every
// FIPS mode allows them) are not.
func TestQuantumVulnerableRuleActsAsPQCFloor(t *testing.T) {
	_, svc := newHandlerForTest(t)
	ctx := adminCtx()
	if _, err := svc.store.CreateAgilityRule(ctx, AgilityRule{ID: newID("agrule"), TenantID: "t1", Name: "PQC only for new protection",
		MatchKind: MatchQuantumVulnerable, Action: ActionDecryptOnly, EffectiveDate: day("2020-01-01")}); err != nil {
		t.Fatal(err)
	}
	create := func(alg, purpose string) error {
		_, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "k-" + alg, Algorithm: alg, KeyType: "asymmetric-private", Purpose: purpose, Owner: "ops", CreatedBy: "tester"})
		return err
	}
	var refusal cryptoPolicyRefusal
	if err := create("RSA-3072", "sign-verify"); !errors.As(err, &refusal) || refusal.Reason != "crypto_policy_decrypt_only" {
		t.Fatalf("RSA-3072 under a PQC floor: %v", err)
	}
	if err := create("ML-KEM-768", "key-encapsulation"); err != nil {
		t.Fatalf("ML-KEM-768 under a PQC floor: %v", err)
	}
}
