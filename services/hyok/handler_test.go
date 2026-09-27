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
	wrapReq.Header.Set("Authorization", "Bearer jwt:tenant-a:operator")
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
	unwrapReq.Header.Set("Authorization", "Bearer jwt:tenant-a:operator")
	unwrapRR := httptest.NewRecorder()
	h.ServeHTTP(unwrapRR, unwrapReq)
	if unwrapRR.Code != http.StatusOK {
		t.Fatalf("unwrap status=%d body=%s", unwrapRR.Code, unwrapRR.Body.String())
	}
	if !strings.Contains(unwrapRR.Body.String(), "\"plaintext\":\"aGVsbG8=\"") {
		t.Fatalf("unexpected unwrap response body=%s", unwrapRR.Body.String())
	}

	dkeReq := httptest.NewRequest(http.MethodGet, "/hyok/dke/v1/keys/key-1/publickey?tenant_id=tenant-a", nil)
	dkeReq.Header.Set("Authorization", "Bearer jwt:tenant-a:operator")
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
		"auth_mode":"jwt",
		"governance_required":true
	}`)))
	configReq.Header.Set("Authorization", "Bearer jwt:tenant-b:admin")
	configRR := httptest.NewRecorder()
	h.ServeHTTP(configRR, configReq)
	if configRR.Code != http.StatusOK {
		t.Fatalf("configure endpoint status=%d body=%s", configRR.Code, configRR.Body.String())
	}

	wrapReq := httptest.NewRequest(http.MethodPost, "/hyok/generic/v1/keys/key-2/wrap?tenant_id=tenant-b", bytes.NewReader([]byte(`{
		"plaintext":"aGVsbG8="
	}`)))
	wrapReq.Header.Set("Authorization", "Bearer jwt:tenant-b:operator")
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
	getReq.Header.Set("Authorization", "Bearer jwt:tenant-ms:operator")
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("get key status=%d body=%s", getRR.Code, getRR.Body.String())
	}
	var keyDoc struct {
		Key   struct{ Kty, N, Kid string }
		Cache struct{ Exp string }
	}
	if err := json.Unmarshal(getRR.Body.Bytes(), &keyDoc); err != nil || keyDoc.Key.Kty != "RSA" || keyDoc.Key.N == "" || keyDoc.Cache.Exp == "" {
		t.Fatalf("unexpected key response body=%s", getRR.Body.String())
	}
	// Office posts to kid + "/decrypt"; Envoy's /svc/hyok prefix is kept in
	// the kid so the call comes back through the edge.
	envoyReq := httptest.NewRequest(http.MethodGet, "/api/v1/keys/rsa-1?tenant_id=tenant-ms", nil)
	envoyReq.Host = "kms.test"
	envoyReq.Header.Set("X-Envoy-Original-Path", "/svc/hyok/api/v1/keys/rsa-1?tenant_id=tenant-ms")
	if got := dkeKeyURL(envoyReq); got != "https://kms.test/svc/hyok/api/v1/keys/rsa-1" {
		t.Fatalf("key URL %q", got)
	}
	if !strings.HasSuffix(keyDoc.Key.Kid, "/api/v1/keys/rsa-1/1") {
		t.Fatalf("kid %q is not the key URL plus version", keyDoc.Key.Kid)
	}

	ciphertextRaw := []byte("wrap:aGVsbG8=")
	decryptBody, _ := json.Marshal(map[string]string{
		"alg":   "RSA-OAEP-256",
		"value": base64.StdEncoding.EncodeToString(ciphertextRaw),
	})
	decReq := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rsa-1/1/decrypt?tenant_id=tenant-ms", bytes.NewReader(decryptBody))
	decReq.Header.Set("Authorization", "Bearer jwt:tenant-ms:operator")
	decRR := httptest.NewRecorder()
	h.ServeHTTP(decRR, decReq)
	if decRR.Code != http.StatusOK {
		t.Fatalf("decrypt status=%d body=%s", decRR.Code, decRR.Body.String())
	}
	if !strings.Contains(decRR.Body.String(), "\"value\":\"aGVsbG8=\"") {
		t.Fatalf("unexpected decrypt response body=%s", decRR.Body.String())
	}
}
