package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerProtocolFlow(t *testing.T) {
	h, _, keycore, _, _, _ := newHYOKHandler(t)
	keycore.Seed("tenant-a", "key-1", "AES-256")

	wrapBody := []byte(`{"plaintext":"aGVsbG8=","iv":"aXYxMjM0NTY3ODkw"}`)
	wrapReq := httptest.NewRequest(http.MethodPost, "/hyok/generic/v1/keys/key-1/wrap?tenant_id=tenant-a", bytes.NewReader(wrapBody))
	wrapReq.Header.Set("X-Client-CN", "tenant-a:cloud")
	wrapRR := httptest.NewRecorder()
	h.ServeHTTP(wrapRR, wrapReq)
	if wrapRR.Code != http.StatusOK {
		t.Fatalf("wrap status=%d body=%s", wrapRR.Code, wrapRR.Body.String())
	}
	var wrapResp struct {
		Result ProxyCryptoResponse `json:"result"`
	}
	_ = json.Unmarshal(wrapRR.Body.Bytes(), &wrapResp)
	if !strings.HasPrefix(wrapResp.Result.CiphertextB64, "wrap:") {
		t.Fatalf("unexpected wrap response: %s", wrapRR.Body.String())
	}

	unwrapBody, _ := json.Marshal(map[string]interface{}{
		"ciphertext": wrapResp.Result.CiphertextB64,
		"iv":         "aXYxMjM0NTY3ODkw",
	})
	unwrapReq := httptest.NewRequest(http.MethodPost, "/hyok/generic/v1/keys/key-1/unwrap?tenant_id=tenant-a", bytes.NewReader(unwrapBody))
	unwrapReq.Header.Set("X-Client-CN", "tenant-a:cloud")
	unwrapRR := httptest.NewRecorder()
	h.ServeHTTP(unwrapRR, unwrapReq)
	if unwrapRR.Code != http.StatusOK {
		t.Fatalf("unwrap status=%d body=%s", unwrapRR.Code, unwrapRR.Body.String())
	}
	if !strings.Contains(unwrapRR.Body.String(), "\"plaintext\":\"aGVsbG8=\"") {
		t.Fatalf("unexpected unwrap response body=%s", unwrapRR.Body.String())
	}

	dkeReq := httptest.NewRequest(http.MethodGet, "/hyok/dke/v1/keys/key-1/publickey?tenant_id=tenant-a", nil)
	dkeReq.Header.Set("X-Client-CN", "tenant-a:cloud")
	dkeRR := httptest.NewRecorder()
	h.ServeHTTP(dkeRR, dkeReq)
	if dkeRR.Code != http.StatusOK {
		t.Fatalf("dke public key status=%d body=%s", dkeRR.Code, dkeRR.Body.String())
	}
	if !strings.Contains(dkeRR.Body.String(), "BEGIN PUBLIC KEY") {
		t.Fatalf("unexpected dke public key body=%s", dkeRR.Body.String())
	}
}

func TestHandlerGovernancePendingApproval(t *testing.T) {
	h, _, keycore, _, _, _ := newHYOKHandler(t)
	keycore.Seed("tenant-b", "key-2", "AES-256")

	configReq := httptest.NewRequest(http.MethodPut, "/hyok/v1/endpoints/generic?tenant_id=tenant-b", bytes.NewReader([]byte(`{
		"tenant_id":"tenant-b",
		"enabled":true,
		"auth_mode":"mtls_or_jwt",
		"governance_required":true
	}`)))
	configRR := httptest.NewRecorder()
	h.ServeHTTP(configRR, configReq)
	if configRR.Code != http.StatusOK {
		t.Fatalf("configure endpoint status=%d body=%s", configRR.Code, configRR.Body.String())
	}

	wrapReq := httptest.NewRequest(http.MethodPost, "/hyok/generic/v1/keys/key-2/wrap?tenant_id=tenant-b", bytes.NewReader([]byte(`{
		"plaintext":"aGVsbG8="
	}`)))
	wrapReq.Header.Set("X-Client-CN", "tenant-b:cloud")
	wrapRR := httptest.NewRecorder()
	h.ServeHTTP(wrapRR, wrapReq)
	if wrapRR.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for governance pending, got %d body=%s", wrapRR.Code, wrapRR.Body.String())
	}
	if !strings.Contains(wrapRR.Body.String(), "\"pending_approval\"") {
		t.Fatalf("expected pending approval body=%s", wrapRR.Body.String())
	}
}

func TestHandlerUnauthorized(t *testing.T) {
	h, _, keycore, _, _, _ := newHYOKHandler(t)
	keycore.Seed("tenant-c", "key-3", "AES-256")
	req := httptest.NewRequest(http.MethodPost, "/hyok/generic/v1/keys/key-3/wrap?tenant_id=tenant-c", bytes.NewReader([]byte(`{"plaintext":"aGVsbG8="}`)))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlerMicrosoftDKEAdapterFlow(t *testing.T) {
	h, _, keycore, _, _, _ := newHYOKHandler(t)
	keycore.Seed("tenant-ms", "rsa-1", "RSA-2048")

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/keys/rsa-1?tenant_id=tenant-ms", nil)
	getReq.Header.Set("X-Client-CN", "tenant-ms:cloud")
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("get key status=%d body=%s", getRR.Code, getRR.Body.String())
	}
	if !strings.Contains(getRR.Body.String(), "\"kty\":\"RSA\"") || !strings.Contains(getRR.Body.String(), "\"n\"") {
		t.Fatalf("unexpected key response body=%s", getRR.Body.String())
	}

	ciphertextRaw := []byte("wrap:aGVsbG8=")
	decryptBody, _ := json.Marshal(map[string]string{
		"alg":   "RSA-OAEP-256",
		"kid":   "rsa-1",
		"value": base64.RawURLEncoding.EncodeToString(ciphertextRaw),
	})
	decReq := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rsa-1/decrypt?tenant_id=tenant-ms", bytes.NewReader(decryptBody))
	decReq.Header.Set("X-Client-CN", "tenant-ms:cloud")
	decRR := httptest.NewRecorder()
	h.ServeHTTP(decRR, decReq)
	if decRR.Code != http.StatusOK {
		t.Fatalf("decrypt status=%d body=%s", decRR.Code, decRR.Body.String())
	}
	if !strings.Contains(decRR.Body.String(), "\"value\":\"aGVsbG8\"") {
		t.Fatalf("unexpected decrypt response body=%s", decRR.Body.String())
	}
}
