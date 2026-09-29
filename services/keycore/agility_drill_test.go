package main

import (
	"errors"
	"net/http"
	"testing"

	"vecta-kms/pkg/fips/fipstest"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

// Every measurement comes from a round trip through the key engine that was
// checked: the output sizes are the engine's real outputs, and an algorithm
// keycore can't round-trip is refused rather than guessed.
func TestDrillMeasuresRealRoundTrips(t *testing.T) {
	for alg, want := range map[string]struct {
		op     string
		output int
	}{
		"RSA-2048":    {"sign_verify", 256},
		"ML-DSA-65":   {"sign_verify", 3309},
		"ML-KEM-768":  {"encapsulate_decapsulate", 1088},
		"ML-KEM-1024": {"encapsulate_decapsulate", 1568},
		"ED25519":     {"sign_verify", 64},
		"HMAC-SHA256": {"sign_verify", 32},
		"AES-256":     {"encrypt_decrypt", 0},
		"ECDSA-P256":  {"sign_verify", 0},
	} {
		m, err := measureAlgorithm(alg, 2, drillBudget)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if m.Operation != want.op || m.RoundTrips != 2 || m.PrivateKeyBytes == 0 || m.OutputBytes == 0 {
			t.Errorf("%s: %+v", alg, m)
		}
		if want.output != 0 && m.OutputBytes != want.output {
			t.Errorf("%s: output %d bytes, want %d", alg, m.OutputBytes, want.output)
		}
		if (m.PublicKeyBytes > 0) != (want.op != "encrypt_decrypt" && alg != "HMAC-SHA256") {
			t.Errorf("%s: public key bytes %d", alg, m.PublicKeyBytes)
		}
	}
	for _, alg := range []string{"ECDH-P256", "RSA", "XMSS"} {
		if _, err := measureAlgorithm(alg, 1, drillBudget); err == nil {
			t.Errorf("%s: measured without a round trip", alg)
		}
	}
	// A spent budget stops after the first round; round_trips says so.
	if m, err := measureAlgorithm("AES-256", 5, 0); err != nil || m.RoundTrips != 1 {
		t.Fatalf("budget: %+v %v", m, err)
	}
	if !errors.Is(func() error { _, err := drillOperation("ECDH-P256"); return err }(), errDrillUnsupported) {
		t.Fatal("ECDH should be unsupported for a drill")
	}
	c := compareDrill(DrillMeasure{OperationMicros: 200, OutputBytes: 256, PublicKeyBytes: 294}, DrillMeasure{OperationMicros: 300, OutputBytes: 3309, PublicKeyBytes: 1952})
	if c.OperationRatio != 1.5 || c.OutputBytesDiff != 3053 || c.PublicKeyDiff != 1658 || c.KeygenRatio != 0 {
		t.Fatalf("comparison %+v", c)
	}
}

func TestAgilityDrillRouteValidatedAndAudited(t *testing.T) {
	h, svc := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	if _, err := svc.store.CreateAgilityRule(adminCtx(), AgilityRule{ID: newID("agrule"), TenantID: "t1", Name: "No new RSA-3072",
		MatchKind: MatchAlgorithm, MatchValue: "RSA-3072", Action: ActionDisallowed, EffectiveDate: day("2020-01-01")}); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"from_algorithm":"RSA-2048"}`,
		`{"from_algorithm":"RSA-2048","to_algorithm":"rsa-2048"}`,
		`{"from_algorithm":"RSA-2048","to_algorithm":"ML-KEM-768","iterations":11}`,
		`{"from_algorithm":"ECDH-P256","to_algorithm":"ML-KEM-768"}`,
	} {
		if rr, _ := agilityCall(t, h, http.MethodPost, "/agility/drills", body); rr.Code != http.StatusBadRequest {
			t.Errorf("accepted %s: %d", body, rr.Code)
		}
	}

	// The tenant's own policy forbids the target: refused, like a real key.
	rr, _ := agilityCall(t, h, http.MethodPost, "/agility/drills", `{"from_algorithm":"RSA-2048","to_algorithm":"RSA-3072","iterations":1}`)
	if e := rec.Last(t); rr.Code != http.StatusForbidden || e.Action != "agility_drill_run" || e.Event.Result != route.ResultRefused || e.Event.Details["reason"] != "crypto_policy_disallowed" {
		t.Fatalf("policy refusal: %d %+v", rr.Code, e)
	}

	// Under FIPS mode a non-approved algorithm is refused on either side.
	svc.fipsMode = staticFIPSModeProvider{enabled: true}
	rr, _ = agilityCall(t, h, http.MethodPost, "/agility/drills", `{"from_algorithm":"ED25519","to_algorithm":"ECDSA-P256","iterations":1}`)
	if e := rec.Last(t); rr.Code != http.StatusForbidden || e.Event.Result != route.ResultRefused || e.Event.Details["reason"] != "fips_mode_violation" {
		t.Fatalf("fips refusal: %d %+v", rr.Code, e)
	}

	// ECDSA-P256 to ML-KEM-768 is approved and in the certified module, so it
	// runs in every FIPS mode.
	rr, out := agilityCall(t, h, http.MethodPost, "/agility/drills", `{"from_algorithm":"ECDSA-P256","to_algorithm":"ML-KEM-768","iterations":2}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("drill: %d %s", rr.Code, rr.Body)
	}
	d, _ := out["data"].(map[string]any)
	to, _ := d["to"].(map[string]any)
	if d["result"] != "passed" || to["operation"] != "encapsulate_decapsulate" || to["output_bytes"] != float64(1088) || to["round_trips"] != float64(2) || d["run_by"] == "" {
		t.Fatalf("drill result %+v", d)
	}
	if e := rec.Last(t); e.Action != "agility_drill_run" || e.Event.Result == route.ResultRefused || e.Event.Details["drill_result"] != "passed" || e.Event.TargetID != d["id"] {
		t.Fatalf("drill event %+v", e)
	}
	rr, out = agilityCall(t, h, http.MethodGet, "/agility/drills", "")
	items, _ := out["items"].([]any)
	if rr.Code != http.StatusOK || len(items) != 1 || items[0].(map[string]any)["id"] != d["id"] {
		t.Fatalf("list: %d %s", rr.Code, rr.Body)
	}
	if e := rec.Last(t); e.Action != "agility_drills_listed" {
		t.Fatalf("list event %+v", e)
	}
}

// Strict mode refuses a drill that names ML-DSA, as it refuses the key: the
// implementation is outside the certified module (pkg/fips/impact.go).
func TestAgilityDrillStrictRefusesNonModuleAlgorithm(t *testing.T) {
	fipstest.StrictOnly(t)
	h, _ := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	rr, _ := agilityCall(t, h, http.MethodPost, "/agility/drills", `{"from_algorithm":"RSA-3072","to_algorithm":"ML-DSA-65","iterations":1}`)
	if e := rec.Last(t); rr.Code != http.StatusForbidden || e.Event.Result != route.ResultRefused || e.Event.Details["reason"] != "fips_mode_violation" {
		t.Fatalf("strict drill: %d %+v", rr.Code, e)
	}
}
