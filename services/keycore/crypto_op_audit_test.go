package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgauth "vecta-kms/pkg/auth"
)

func keyOpAs(h *Handler, keyID, op string, claims *pkgauth.Claims, body map[string]any) *httptest.ResponseRecorder {
	body["tenant_id"] = "t1"
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/keys/"+keyID+"/"+op+"?tenant_id=t1", bytes.NewReader(raw))
	req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// Every key operation emits audit.key.<op> named after the operation that
// ran, with its duration and result — successes, refusals and failures.
// The Operations metrics are built from exactly these events.
func TestCryptoOpsAuditedWithOutcomeAndDuration(t *testing.T) {
	h, svc, rec := newActorTestHandler(t)
	key := ownedKey(t, svc)
	admin := &pkgauth.Claims{UserID: "root-admin", TenantID: "t1", Role: "admin", Permissions: []string{"*"}}

	if w := keyOpAs(h, key.ID, "encrypt", admin, map[string]any{"plaintext": "aGVsbG8="}); w.Code != http.StatusOK {
		t.Fatalf("encrypt: %d %s", w.Code, w.Body)
	}
	ev := rec.find("audit.key.encrypt")
	if ev == nil || ev["result"] != "success" {
		t.Fatalf("encrypt event: %+v", ev)
	}
	if _, ok := ev["duration_ms"].(float64); !ok {
		t.Fatalf("encrypt event has no duration_ms: %+v", ev)
	}

	// A wrap is recorded as a wrap, never as an encrypt.
	rec.mu.Lock()
	rec.events = nil
	rec.mu.Unlock()
	if w := keyOpAs(h, key.ID, "wrap", admin, map[string]any{"plaintext": "aGVsbG8="}); w.Code != http.StatusOK {
		t.Fatalf("wrap: %d %s", w.Code, w.Body)
	}
	if ev := rec.find("audit.key.wrap"); ev == nil || ev["result"] != "success" {
		t.Fatalf("wrap event: %+v", ev)
	} else if d, _ := ev["details"].(map[string]any); d["metered_op"] != "wrap" {
		t.Fatalf("wrap event not metered: %+v", d)
	}
	if ev := rec.find("audit.key.encrypt"); ev != nil {
		t.Fatalf("wrap was audited as encrypt: %+v", ev)
	}

	// Refused: the operation event carries result refused and the reason.
	mallory := &pkgauth.Claims{UserID: "mallory", TenantID: "t1", Role: "viewer"}
	if w := keyOpAs(h, key.ID, "encrypt", mallory, map[string]any{"plaintext": "aGVsbG8="}); w.Code != http.StatusForbidden {
		t.Fatalf("mallory encrypt: %d %s", w.Code, w.Body)
	}
	if d := refusalDetails(t, rec, "audit.key.encrypt"); d["reason"] != "not_assigned_to_caller" {
		t.Fatalf("refused encrypt details: %+v", d)
	}

	// Failed: a ciphertext that doesn't authenticate is a failure event.
	if w := keyOpAs(h, key.ID, "decrypt", admin, map[string]any{"ciphertext": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "iv": "AAAAAAAAAAAAAAAA"}); w.Code == http.StatusOK {
		t.Fatalf("garbage ciphertext decrypted: %s", w.Body)
	}
	ev = rec.find("audit.key.decrypt")
	if ev == nil || ev["result"] != "failure" || ev["error_message"] == "" {
		t.Fatalf("failed decrypt event: %+v", ev)
	}
}
