package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerCloudFlow(t *testing.T) {
	h, _, keycore, _ := newCloudHandler(t)
	keycore.Seed("tenant-1", "key-1", "AES-256")

	accountReq := map[string]interface{}{
		"tenant_id":        "tenant-1",
		"provider":         ProviderAWS,
		"name":             "aws-primary",
		"default_region":   "us-east-1",
		"credentials_json": `{"access_key":"abc","secret":"xyz"}`,
	}
	accountBody, _ := json.Marshal(accountReq)
	createAccount := httptest.NewRequest(http.MethodPost, "/cloud/accounts", bytes.NewReader(accountBody))
	createAccount.Header.Set("X-Request-ID", "req-1")
	accountRR := httptest.NewRecorder()
	h.ServeHTTP(accountRR, createAccount)
	if accountRR.Code != http.StatusCreated {
		t.Fatalf("account create status=%d body=%s", accountRR.Code, accountRR.Body.String())
	}
	var accountResp struct {
		Account CloudAccount `json:"account"`
	}
	_ = json.Unmarshal(accountRR.Body.Bytes(), &accountResp)
	if accountResp.Account.ID == "" {
		t.Fatalf("missing account id in response: %s", accountRR.Body.String())
	}

	importReq := map[string]interface{}{
		"tenant_id":  "tenant-1",
		"key_id":     "key-1",
		"provider":   ProviderAWS,
		"account_id": accountResp.Account.ID,
	}
	importBody, _ := json.Marshal(importReq)
	importHTTP := httptest.NewRequest(http.MethodPost, "/cloud/import", bytes.NewReader(importBody))
	importRR := httptest.NewRecorder()
	h.ServeHTTP(importRR, importHTTP)
	if importRR.Code != http.StatusCreated {
		t.Fatalf("import status=%d body=%s", importRR.Code, importRR.Body.String())
	}
	var importResp struct {
		Binding CloudKeyBinding `json:"binding"`
	}
	_ = json.Unmarshal(importRR.Body.Bytes(), &importResp)
	if importResp.Binding.ID == "" {
		t.Fatalf("missing binding id in response: %s", importRR.Body.String())
	}

	rotateHTTP := httptest.NewRequest(http.MethodPost, "/cloud/bindings/"+importResp.Binding.ID+"/rotate?tenant_id=tenant-1", bytes.NewReader([]byte(`{"reason":"manual"}`)))
	rotateRR := httptest.NewRecorder()
	h.ServeHTTP(rotateRR, rotateHTTP)
	if rotateRR.Code != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", rotateRR.Code, rotateRR.Body.String())
	}

	listHTTP := httptest.NewRequest(http.MethodGet, "/cloud/bindings?tenant_id=tenant-1", nil)
	listRR := httptest.NewRecorder()
	h.ServeHTTP(listRR, listHTTP)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listRR.Code, listRR.Body.String())
	}

	getHTTP := httptest.NewRequest(http.MethodGet, "/cloud/bindings/"+importResp.Binding.ID+"?tenant_id=tenant-1", nil)
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, getHTTP)
	if getRR.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", getRR.Code, getRR.Body.String())
	}

	inventoryHTTP := httptest.NewRequest(http.MethodGet, "/cloud/inventory?tenant_id=tenant-1&provider=aws&account_id="+accountResp.Account.ID, nil)
	inventoryRR := httptest.NewRecorder()
	h.ServeHTTP(inventoryRR, inventoryHTTP)
	if inventoryRR.Code != http.StatusOK {
		t.Fatalf("inventory status=%d body=%s", inventoryRR.Code, inventoryRR.Body.String())
	}

	deleteHTTP := httptest.NewRequest(http.MethodDelete, "/cloud/accounts/"+accountResp.Account.ID+"?tenant_id=tenant-1", nil)
	deleteRR := httptest.NewRecorder()
	h.ServeHTTP(deleteRR, deleteHTTP)
	if deleteRR.Code != http.StatusOK {
		t.Fatalf("delete account status=%d body=%s", deleteRR.Code, deleteRR.Body.String())
	}
}

func TestHandlerTenantRequired(t *testing.T) {
	h, _, _, _ := newCloudHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/cloud/accounts", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 got %d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.Error.Code == "" {
		t.Fatalf("expected structured error body=%s", rr.Body.String())
	}
}
