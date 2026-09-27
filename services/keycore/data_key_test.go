package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"vecta-kms/pkg/route/routetest"
)

func generateDataKeyAs(t *testing.T, h *Handler, keyID string, body map[string]any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	rr := httptest.NewRecorder()
	serveAsAdmin(h, rr, httptest.NewRequest(http.MethodPost, "/keys/"+keyID+"/generate-data-key", bytes.NewReader(raw)))
	out := map[string]any{}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr, out
}

// The DEK comes back wrapped under the key and unwraps to the same bytes
// through the ordinary /unwrap route; the wrapped-only variant never returns
// the plaintext DEK; each generation is audited under its own action.
func TestGenerateDataKeyRoundTripsThroughUnwrap(t *testing.T) {
	h, svc := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "kek", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}

	rr, out := generateDataKeyAs(t, h, key.ID, map[string]any{"tenant_id": "t1"})
	if rr.Code != http.StatusOK {
		t.Fatalf("generate: %d %s", rr.Code, rr.Body)
	}
	dek, _ := base64.StdEncoding.DecodeString(out["plaintext_dek"].(string))
	if len(dek) != 32 {
		t.Fatalf("dek length %d", len(dek))
	}
	if out["wrapped_dek"] == out["plaintext_dek"] {
		t.Fatal("wrapped DEK equals plaintext DEK")
	}
	if e := rec.Last(t); e.Action != "data_key_generated" || e.Event.Result != "success" || e.Event.TargetID != key.ID {
		t.Fatalf("success event %+v", e)
	}

	raw, _ := json.Marshal(map[string]any{"tenant_id": "t1", "ciphertext": out["wrapped_dek"], "iv": out["wrapped_dek_iv"]})
	ur := httptest.NewRecorder()
	serveAsAdmin(h, ur, httptest.NewRequest(http.MethodPost, "/keys/"+key.ID+"/unwrap", bytes.NewReader(raw)))
	var unwrapped struct {
		Plaintext string `json:"plaintext"`
	}
	_ = json.Unmarshal(ur.Body.Bytes(), &unwrapped)
	if ur.Code != http.StatusOK || unwrapped.Plaintext != out["plaintext_dek"] {
		t.Fatalf("unwrap: %d %s", ur.Code, ur.Body)
	}

	rr, out = generateDataKeyAs(t, h, key.ID, map[string]any{"tenant_id": "t1", "include_plaintext": false, "key_bytes": 16})
	if rr.Code != http.StatusOK || out["wrapped_dek"] == "" {
		t.Fatalf("wrapped-only: %d %s", rr.Code, rr.Body)
	}
	if _, leaked := out["plaintext_dek"]; leaked {
		t.Fatal("wrapped-only response carried the plaintext DEK")
	}

	if rr, _ := generateDataKeyAs(t, h, key.ID, map[string]any{"tenant_id": "t1", "key_bytes": 7}); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad key_bytes accepted: %d", rr.Code)
	}
}

// A key-operation refusal (here the key's ops limit) is audited under the
// route's action with result "refused" and its reason.
func TestGenerateDataKeyRefusalIsAudited(t *testing.T) {
	h, svc := newHandlerForTest(t)
	rec := &routetest.Recorder{}
	h.kernelAudit = rec
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "limited", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Owner: "ops", CreatedBy: "tester", OpsLimit: 1, OpsLimitWindow: "total",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rr, _ := generateDataKeyAs(t, h, key.ID, map[string]any{"tenant_id": "t1"}); rr.Code != http.StatusOK {
		t.Fatalf("first: %d %s", rr.Code, rr.Body)
	}
	rr, out := generateDataKeyAs(t, h, key.ID, map[string]any{"tenant_id": "t1"})
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("over limit: %d %s", rr.Code, rr.Body)
	}
	if _, leaked := out["plaintext_dek"]; leaked {
		t.Fatal("refused call returned a DEK")
	}
	if e := rec.Last(t); e.Action != "data_key_generated" || e.Event.Result != "refused" || e.Event.Details["reason"] != "ops_limit_reached" {
		t.Fatalf("refusal event %+v", e)
	}
}

func TestDataKeyRoutesRefusalsAudited(t *testing.T) {
	h, _, _ := newActorTestHandler(t)
	rec := &routetest.Recorder{}
	routetest.RefusalsAudited(t, h.dataKeyRouter(rec), rec)
}
