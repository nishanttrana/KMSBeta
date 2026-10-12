package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/route/routetest"
)

var textAdmin = &pkgauth.Claims{UserID: "tester", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}

func decodeBody(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("response is not JSON: %s", raw)
	}
	return out
}

func storedDescription(t *testing.T, h *Handler, keyID string) string {
	t.Helper()
	w := callKeycore(h, http.MethodGet, "/keys/"+keyID, "", textAdmin)
	if w.Code != http.StatusOK {
		t.Fatalf("get key: %d %s", w.Code, w.Body)
	}
	key, _ := decodeBody(t, w.Body.Bytes())["key"].(map[string]any)
	d, _ := key["description"].(string)
	return d
}

// A description given at creation is stored and returned; an update that
// leaves it out keeps it, one that names it replaces it, and the audit event
// says it changed without carrying the text.
func TestKeyDescriptionIsStoredReturnedAndUpdated(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	w := callKeycore(h, http.MethodPost, "/keys", `{"tenant_id":"t1","name":"billing-dek","description":"  Envelope key for the billing ledger  ","algorithm":"AES-256","key_type":"symmetric","purpose":"encrypt","created_by":"tester"}`, textAdmin)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	keyID, _ := decodeBody(t, w.Body.Bytes())["key_id"].(string)
	if got := storedDescription(t, h, keyID); got != "Envelope key for the billing ledger" {
		t.Fatalf("description = %q", got)
	}

	krec := &routetest.Recorder{}
	h.kernelAudit = krec
	describe := func(text string) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"description": text})
		if w := callKeycore(h, http.MethodPut, "/keys/"+keyID+"/description", string(body), textAdmin); w.Code != http.StatusOK {
			t.Fatalf("set description: %d %s", w.Code, w.Body)
		}
	}

	// The metadata update names no description and must not touch it.
	if w := callKeycore(h, http.MethodPut, "/keys/"+keyID, `{"name":"billing-dek","purpose":"encrypt"}`, textAdmin); w.Code != http.StatusOK {
		t.Fatalf("metadata update: %d %s", w.Code, w.Body)
	}
	if got := storedDescription(t, h, keyID); got != "Envelope key for the billing ledger" {
		t.Fatalf("a metadata update changed the description to %q", got)
	}

	describe("Retired 2026-10; kept for decrypt")
	if got := storedDescription(t, h, keyID); got != "Retired 2026-10; kept for decrypt" {
		t.Fatalf("description = %q after update", got)
	}
	ev := krec.Last(t)
	if ev.Action != "description_updated" || ev.Event.Result != "success" || ev.Event.TargetID != keyID ||
		ev.Event.Details["changed"] != true || ev.Event.Details["length"] != 33 {
		t.Fatalf("audited as %s %+v", ev.Action, ev.Event)
	}
	if raw, _ := json.Marshal(ev.Event); strings.Contains(string(raw), "Retired") {
		t.Fatalf("the audit event carries the description text: %s", raw)
	}

	describe("Retired 2026-10; kept for decrypt")
	if ev := krec.Last(t); ev.Event.Details["changed"] != false {
		t.Fatalf("setting the same text is audited as a change: %+v", ev.Event.Details)
	}
	describe("")
	if got := storedDescription(t, h, keyID); got != "" {
		t.Fatalf("an empty description did not clear it: %q", got)
	}
}

// A description that is too long or holds control characters is refused,
// audited with its reason, and nothing is stored.
func TestKeyDescriptionRefused(t *testing.T) {
	h, svc, rec := newActorTestHandler(t)
	for name, bad := range map[string]string{
		"too long":          strings.Repeat("x", maxKeyDescription+1),
		"control character": "line one\\nline two",
	} {
		body := `{"tenant_id":"t1","name":"k-` + name[:3] + `","description":"` + bad + `","algorithm":"AES-256","key_type":"symmetric","purpose":"encrypt"}`
		w := callKeycore(h, http.MethodPost, "/keys", body, textAdmin)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "description_invalid") {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body)
		}
		if d := refusalDetails(t, rec, "audit.key.create_refused"); d["reason"] != "description_invalid" || d["operation"] != "key.create" {
			t.Fatalf("%s: audited as %+v", name, d)
		}
	}
	if keys, err := svc.store.ListKeys(context.Background(), "t1", 10, 0); err != nil || len(keys) != 0 {
		t.Fatalf("a refused create stored %d key(s) (%v)", len(keys), err)
	}

	// Import and form go through the same check.
	w := callKeycore(h, http.MethodPost, "/keys/import", `{"tenant_id":"t1","name":"imp","description":"`+strings.Repeat("y", maxKeyDescription+1)+`","algorithm":"AES-256","key_type":"symmetric","purpose":"encrypt","import_method":"raw","material":"MDEyMzQ1Njc4OUFCQ0RFRjAxMjM0NTY3ODlBQkNERUY="}`, textAdmin)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "description_invalid") {
		t.Fatalf("import: %d %s", w.Code, w.Body)
	}
	if d := refusalDetails(t, rec, "audit.key.create_refused"); d["operation"] != "key.import" {
		t.Fatalf("import refusal audited as %+v", d)
	}

	key, err := svc.CreateKey(adminCtx(), CreateKeyRequest{TenantID: "t1", Name: "k", Description: "kept", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	krec := &routetest.Recorder{}
	h.kernelAudit = krec
	w = callKeycore(h, http.MethodPut, "/keys/"+key.ID+"/description", `{"description":"`+strings.Repeat("z", maxKeyDescription+1)+`"}`, textAdmin)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "description_invalid") {
		t.Fatalf("set description: %d %s", w.Code, w.Body)
	}
	if ev := krec.Last(t); ev.Action != "description_updated" || ev.Event.Result != route.ResultRefused || ev.Event.Details["reason"] != "description_invalid" {
		t.Fatalf("refusal audited as %s %+v", ev.Action, ev.Event)
	}
	if got := storedDescription(t, h, key.ID); got != "kept" {
		t.Fatalf("a refused update changed the description to %q", got)
	}

	// A caller without key.update is refused by the kernel, and audited.
	reader := &pkgauth.Claims{UserID: "ro", TenantID: "t1", Role: "readonly", Permissions: []string{"key.read"}}
	w = callKeycore(h, http.MethodPut, "/keys/"+key.ID+"/description", `{"description":"mine now"}`, reader)
	if w.Code != http.StatusForbidden {
		t.Fatalf("readonly caller: %d %s", w.Code, w.Body)
	}
	if ev := krec.Last(t); ev.Action != "description_updated" || ev.Event.Result != route.ResultRefused {
		t.Fatalf("permission refusal audited as %s %+v", ev.Action, ev.Event)
	}
	if got := storedDescription(t, h, key.ID); got != "kept" {
		t.Fatalf("a caller without key.update changed the description to %q", got)
	}
}

// Key material leaves only with a stated reason, and the reason is in the
// audit event. A missing or malformed reason is refused and audited, and no
// material is returned.
func TestExportNeedsAReason(t *testing.T) {
	h, svc, rec := newActorTestHandler(t)
	ctx := adminCtx()
	key, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "data", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt", CreatedBy: "tester", ExportAllowed: true})
	if err != nil {
		t.Fatal(err)
	}
	kek, err := svc.CreateKey(ctx, CreateKeyRequest{TenantID: "t1", Name: "kek", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "wrap-unwrap", CreatedBy: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	export := func(body string) (int, map[string]any) {
		w := callKeycore(h, http.MethodPost, "/keys/"+key.ID+"/export", body, textAdmin)
		return w.Code, decodeBody(t, w.Body.Bytes())
	}
	errorCode := func(body map[string]any) any {
		e, _ := body["error"].(map[string]any)
		return e["code"]
	}

	for reason, want := range map[string]string{
		``:                "export_reason_required",
		`,"reason":"   "`: "export_reason_required",
		`,"reason":"` + strings.Repeat("r", maxExportReason+1) + `"`: "export_reason_invalid",
		`,"reason":"tab\there"`: "export_reason_invalid",
	} {
		code, body := export(`{"wrapping_key_id":"` + kek.ID + `"` + reason + `}`)
		if code != http.StatusBadRequest || errorCode(body) != want {
			t.Fatalf("reason %q: %d %v, want 400 %s", reason, code, body, want)
		}
		if body["wrapped_material"] != nil {
			t.Fatalf("reason %q: material returned with a refusal", reason)
		}
		if d := refusalDetails(t, rec, "audit.key.export_refused"); d["reason"] != want || d["key_id"] != key.ID || d["export_mode"] != "wrapped" {
			t.Fatalf("reason %q: audited as %+v", reason, d)
		}
	}
	if rec.find("audit.key.export") != nil {
		t.Fatal("audit.key.export was emitted for a refused export")
	}

	code, body := export(`{"wrapping_key_id":"` + kek.ID + `","reason":"  Moving the ledger to the DR site (CHG-4412)  "}`)
	if code != http.StatusOK || body["wrapped_material"] == "" || body["wrapped_material"] == nil {
		t.Fatalf("export with a reason: %d %v", code, body)
	}
	ev := rec.find("audit.key.export")
	if ev == nil {
		t.Fatal("no audit.key.export event")
	}
	if d, _ := ev["details"].(map[string]any); d["export_reason"] != "Moving the ledger to the DR site (CHG-4412)" || d["wrapping_key_id"] != kek.ID {
		t.Fatalf("audit.key.export details = %+v", d)
	}

	// A public component may be exported without a reason; a malformed one
	// is still refused before the key is looked at.
	code, body = export(`{"export_mode":"public-plaintext"}`)
	if errorCode(body) == "export_reason_required" {
		t.Fatalf("a public export was refused for a missing reason: %d %v", code, body)
	}
	code, body = export(`{"export_mode":"public-plaintext","reason":"` + strings.Repeat("r", maxExportReason+1) + `"}`)
	if code != http.StatusBadRequest || errorCode(body) != "export_reason_invalid" {
		t.Fatalf("public export, malformed reason: %d %v", code, body)
	}
	if d := refusalDetails(t, rec, "audit.key.export_refused"); d["export_mode"] != "public-plaintext" {
		t.Fatalf("audited as %+v", d)
	}
}
