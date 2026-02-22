package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type nopEventPublisher struct{}

func (nopEventPublisher) Publish(_ context.Context, _ string, _ []byte) error { return nil }

type failEventPublisher struct{}

func (failEventPublisher) Publish(_ context.Context, _ string, _ []byte) error {
	return errors.New("nats down")
}

func newPolicyHandler(t *testing.T) *Handler {
	t.Helper()
	store := newPolicyStore(t)
	svc := NewService(store, nopEventPublisher{})
	return NewHandler(svc)
}

func TestCreatePolicyAndEvaluate(t *testing.T) {
	h := newPolicyHandler(t)
	createBody := map[string]any{
		"tenant_id": "tenant-a",
		"actor":     "alice",
		"yaml": `apiVersion: kms.vecta.com/v1
kind: CryptoPolicy
metadata:
  name: deny-weak
  tenant: tenant-a
spec:
  type: algorithm
  targets:
    selector: {}
  rules:
    - name: deny-weak-algo
      condition: "key.algorithm in [DES, 3DES]"
      action: enforce
      message: "Weak algorithms blocked"`,
	}
	raw, _ := json.Marshal(createBody)
	req := httptest.NewRequest(http.MethodPost, "/policies", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}

	evalBody := map[string]any{
		"tenant_id":  "tenant-a",
		"operation":  "key.encrypt",
		"key_id":     "k1",
		"algorithm":  "3DES",
		"purpose":    "encrypt",
		"iv_mode":    "internal",
		"ops_total":  1,
		"ops_limit":  100,
		"key_status": "active",
	}
	rawEval, _ := json.Marshal(evalBody)
	eReq := httptest.NewRequest(http.MethodPost, "/policy/evaluate", bytes.NewReader(rawEval))
	eRR := httptest.NewRecorder()
	h.ServeHTTP(eRR, eReq)
	if eRR.Code != http.StatusOK {
		t.Fatalf("evaluate status=%d body=%s", eRR.Code, eRR.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(eRR.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["decision"] != string(DecisionDeny) {
		t.Fatalf("expected DENY got %v", resp["decision"])
	}
}
