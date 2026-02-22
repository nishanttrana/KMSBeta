package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerTokenAndFPEFlows(t *testing.T) {
	h, _, _ := newDataProtectHandler(t)
	tenantID := "tenant-h1"

	createVaultReq := httptest.NewRequest(http.MethodPost, "/token-vaults", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"name":"card-vault",
		"token_type":"credit_card",
		"format":"deterministic",
		"key_id":"key-1"
	}`))
	createVaultReq.Header.Set("Content-Type", "application/json")
	createVaultRR := httptest.NewRecorder()
	h.ServeHTTP(createVaultRR, createVaultReq)
	if createVaultRR.Code != http.StatusCreated {
		t.Fatalf("create vault status=%d body=%s", createVaultRR.Code, createVaultRR.Body.String())
	}
	var createVaultPayload map[string]interface{}
	_ = json.Unmarshal(createVaultRR.Body.Bytes(), &createVaultPayload)
	vaultID, _ := createVaultPayload["vault"].(map[string]interface{})["id"].(string)
	if vaultID == "" {
		t.Fatalf("missing vault id")
	}

	tokenizeReq := httptest.NewRequest(http.MethodPost, "/tokenize", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"vault_id":"`+vaultID+`",
		"values":["4111111111111111"]
	}`))
	tokenizeReq.Header.Set("Content-Type", "application/json")
	tokenizeRR := httptest.NewRecorder()
	h.ServeHTTP(tokenizeRR, tokenizeReq)
	if tokenizeRR.Code != http.StatusOK {
		t.Fatalf("tokenize status=%d body=%s", tokenizeRR.Code, tokenizeRR.Body.String())
	}
	var tokPayload map[string]interface{}
	_ = json.Unmarshal(tokenizeRR.Body.Bytes(), &tokPayload)
	items, _ := tokPayload["items"].([]interface{})
	if len(items) != 1 {
		t.Fatalf("unexpected tokenize items: %+v", tokPayload)
	}
	token, _ := items[0].(map[string]interface{})["token"].(string)
	if token == "" {
		t.Fatalf("missing token in tokenize response")
	}

	vaultlessReq := httptest.NewRequest(http.MethodPost, "/tokenize", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"mode":"vaultless",
		"key_id":"key-1",
		"token_type":"credit_card",
		"format":"deterministic",
		"values":["4111111111111111"]
	}`))
	vaultlessReq.Header.Set("Content-Type", "application/json")
	vaultlessRR := httptest.NewRecorder()
	h.ServeHTTP(vaultlessRR, vaultlessReq)
	if vaultlessRR.Code != http.StatusOK {
		t.Fatalf("vaultless tokenize status=%d body=%s", vaultlessRR.Code, vaultlessRR.Body.String())
	}

	badVaultReq := httptest.NewRequest(http.MethodPost, "/token-vaults", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"name":"bad-vault",
		"token_type":"credit_card",
		"format":"deterministic",
		"key_id":"key-rsa"
	}`))
	badVaultReq.Header.Set("Content-Type", "application/json")
	badVaultRR := httptest.NewRecorder()
	h.ServeHTTP(badVaultRR, badVaultReq)
	if badVaultRR.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for asymmetric vault key, status=%d body=%s", badVaultRR.Code, badVaultRR.Body.String())
	}

	detokReq := httptest.NewRequest(http.MethodPost, "/detokenize", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"tokens":["`+token+`"]
	}`))
	detokReq.Header.Set("Content-Type", "application/json")
	detokRR := httptest.NewRecorder()
	h.ServeHTTP(detokRR, detokReq)
	if detokRR.Code != http.StatusOK {
		t.Fatalf("detokenize status=%d body=%s", detokRR.Code, detokRR.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/token-vaults?tenant_id="+tenantID, nil)
	listRR := httptest.NewRecorder()
	h.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list vaults status=%d body=%s", listRR.Code, listRR.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/token-vaults/"+vaultID+"?tenant_id="+tenantID, nil)
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("get vault status=%d body=%s", getRR.Code, getRR.Body.String())
	}

	fpeEncReq := httptest.NewRequest(http.MethodPost, "/fpe/encrypt", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"key_id":"key-1",
		"algorithm":"FF1",
		"radix":10,
		"plaintext":"1234567890"
	}`))
	fpeEncReq.Header.Set("Content-Type", "application/json")
	fpeEncRR := httptest.NewRecorder()
	h.ServeHTTP(fpeEncRR, fpeEncReq)
	if fpeEncRR.Code != http.StatusOK {
		t.Fatalf("fpe encrypt status=%d body=%s", fpeEncRR.Code, fpeEncRR.Body.String())
	}
	var fpePayload map[string]interface{}
	_ = json.Unmarshal(fpeEncRR.Body.Bytes(), &fpePayload)
	ciphertext, _ := fpePayload["result"].(map[string]interface{})["ciphertext"].(string)
	if ciphertext == "" {
		t.Fatalf("missing fpe ciphertext")
	}

	fpeDecReq := httptest.NewRequest(http.MethodPost, "/fpe/decrypt", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"key_id":"key-1",
		"algorithm":"FF1",
		"radix":10,
		"ciphertext":"`+ciphertext+`"
	}`))
	fpeDecReq.Header.Set("Content-Type", "application/json")
	fpeDecRR := httptest.NewRecorder()
	h.ServeHTTP(fpeDecRR, fpeDecReq)
	if fpeDecRR.Code != http.StatusOK {
		t.Fatalf("fpe decrypt status=%d body=%s", fpeDecRR.Code, fpeDecRR.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/token-vaults/"+vaultID+"?tenant_id="+tenantID+"&governance_approved=true", nil)
	deleteRR := httptest.NewRecorder()
	h.ServeHTTP(deleteRR, deleteReq)
	if deleteRR.Code != http.StatusOK {
		t.Fatalf("delete vault status=%d body=%s", deleteRR.Code, deleteRR.Body.String())
	}
}

func TestHandlerMaskRedactAndAppFlows(t *testing.T) {
	h, _, _ := newDataProtectHandler(t)
	tenantID := "tenant-h2"

	createMaskReq := httptest.NewRequest(http.MethodPost, "/masking-policies", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"name":"ssn-mask",
		"target_type":"field",
		"field_path":"$.customer.ssn",
		"mask_pattern":"full",
		"roles_partial":["analyst"]
	}`))
	createMaskReq.Header.Set("Content-Type", "application/json")
	createMaskRR := httptest.NewRecorder()
	h.ServeHTTP(createMaskRR, createMaskReq)
	if createMaskRR.Code != http.StatusCreated {
		t.Fatalf("create masking policy status=%d body=%s", createMaskRR.Code, createMaskRR.Body.String())
	}
	var maskPayload map[string]interface{}
	_ = json.Unmarshal(createMaskRR.Body.Bytes(), &maskPayload)
	maskID, _ := maskPayload["item"].(map[string]interface{})["id"].(string)
	if maskID == "" {
		t.Fatalf("missing masking policy id")
	}

	maskReq := httptest.NewRequest(http.MethodPost, "/mask", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"policy_id":"`+maskID+`",
		"role":"analyst",
		"data":{
			"customer":"ignored"
		}
	}`))
	maskReq.Header.Set("Content-Type", "application/json")
	maskRR := httptest.NewRecorder()
	h.ServeHTTP(maskRR, maskReq)
	if maskRR.Code == http.StatusInternalServerError {
		t.Fatalf("mask request unexpectedly failed body=%s", maskRR.Body.String())
	}

	createRedReq := httptest.NewRequest(http.MethodPost, "/redaction-policies", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"name":"pii-redact",
		"action":"replace_placeholder",
		"placeholder":"[REDACTED]"
	}`))
	createRedReq.Header.Set("Content-Type", "application/json")
	createRedRR := httptest.NewRecorder()
	h.ServeHTTP(createRedRR, createRedReq)
	if createRedRR.Code != http.StatusCreated {
		t.Fatalf("create redaction policy status=%d body=%s", createRedRR.Code, createRedRR.Body.String())
	}

	redactReq := httptest.NewRequest(http.MethodPost, "/redact", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"content":"reach me at test@example.com"
	}`))
	redactReq.Header.Set("Content-Type", "application/json")
	redactRR := httptest.NewRecorder()
	h.ServeHTTP(redactRR, redactReq)
	if redactRR.Code != http.StatusOK {
		t.Fatalf("redact status=%d body=%s", redactRR.Code, redactRR.Body.String())
	}

	encFieldsReq := httptest.NewRequest(http.MethodPost, "/app/encrypt-fields", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"document_id":"doc-h2",
		"document":{"email":"bob@example.com"},
		"fields":["$.email"],
		"key_id":"key-1",
		"algorithm":"AES-GCM"
	}`))
	encFieldsReq.Header.Set("Content-Type", "application/json")
	encFieldsRR := httptest.NewRecorder()
	h.ServeHTTP(encFieldsRR, encFieldsReq)
	if encFieldsRR.Code != http.StatusOK {
		t.Fatalf("encrypt fields status=%d body=%s", encFieldsRR.Code, encFieldsRR.Body.String())
	}
	var encFieldsPayload map[string]interface{}
	_ = json.Unmarshal(encFieldsRR.Body.Bytes(), &encFieldsPayload)
	result, _ := encFieldsPayload["result"].(map[string]interface{})
	document, _ := result["document"].(map[string]interface{})

	decFieldsBody, _ := json.Marshal(map[string]interface{}{
		"tenant_id":   tenantID,
		"document_id": "doc-h2",
		"document":    document,
		"fields":      []string{"$.email"},
		"key_id":      "key-1",
	})
	decFieldsReq := httptest.NewRequest(http.MethodPost, "/app/decrypt-fields", strings.NewReader(string(decFieldsBody)))
	decFieldsReq.Header.Set("Content-Type", "application/json")
	decFieldsRR := httptest.NewRecorder()
	h.ServeHTTP(decFieldsRR, decFieldsReq)
	if decFieldsRR.Code != http.StatusOK {
		t.Fatalf("decrypt fields status=%d body=%s", decFieldsRR.Code, decFieldsRR.Body.String())
	}

	envEncReq := httptest.NewRequest(http.MethodPost, "/app/envelope-encrypt", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"key_id":"key-1",
		"algorithm":"AES-GCM",
		"plaintext":"hello"
	}`))
	envEncReq.Header.Set("Content-Type", "application/json")
	envEncRR := httptest.NewRecorder()
	h.ServeHTTP(envEncRR, envEncReq)
	if envEncRR.Code != http.StatusOK {
		t.Fatalf("envelope encrypt status=%d body=%s", envEncRR.Code, envEncRR.Body.String())
	}
	var envPayload map[string]interface{}
	_ = json.Unmarshal(envEncRR.Body.Bytes(), &envPayload)
	envResult, _ := envPayload["result"].(map[string]interface{})

	envDecReq := httptest.NewRequest(http.MethodPost, "/app/envelope-decrypt", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"key_id":"key-1",
		"algorithm":"AES-GCM",
		"ciphertext":"`+envResult["ciphertext"].(string)+`",
		"iv":"`+envResult["iv"].(string)+`",
		"wrapped_dek":"`+envResult["wrapped_dek"].(string)+`",
		"wrapped_dek_iv":"`+envResult["wrapped_dek_iv"].(string)+`"
	}`))
	envDecReq.Header.Set("Content-Type", "application/json")
	envDecRR := httptest.NewRecorder()
	h.ServeHTTP(envDecRR, envDecReq)
	if envDecRR.Code != http.StatusOK {
		t.Fatalf("envelope decrypt status=%d body=%s", envDecRR.Code, envDecRR.Body.String())
	}

	seReq := httptest.NewRequest(http.MethodPost, "/app/searchable-encrypt", strings.NewReader(`{"tenant_id":"`+tenantID+`","key_id":"key-2","plaintext":"bob@example.com"}`))
	seReq.Header.Set("Content-Type", "application/json")
	seRR := httptest.NewRecorder()
	h.ServeHTTP(seRR, seReq)
	if seRR.Code != http.StatusOK {
		t.Fatalf("searchable encrypt status=%d body=%s", seRR.Code, seRR.Body.String())
	}
	var sePayload map[string]interface{}
	_ = json.Unmarshal(seRR.Body.Bytes(), &sePayload)
	ciphertext, _ := sePayload["result"].(map[string]interface{})["ciphertext"].(string)

	sdReq := httptest.NewRequest(http.MethodPost, "/app/searchable-decrypt", strings.NewReader(`{"tenant_id":"`+tenantID+`","key_id":"key-2","ciphertext":"`+ciphertext+`"}`))
	sdReq.Header.Set("Content-Type", "application/json")
	sdRR := httptest.NewRecorder()
	h.ServeHTTP(sdRR, sdReq)
	if sdRR.Code != http.StatusOK {
		t.Fatalf("searchable decrypt status=%d body=%s", sdRR.Code, sdRR.Body.String())
	}
}
