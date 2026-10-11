package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerCloudFlow(t *testing.T) {
	h, svc, _, _ := newCloudHandler(t)

	accountReq := map[string]interface{}{
		"tenant_id":        "tenant-1",
		"provider":         ProviderAWS,
		"name":             "aws-primary",
		"default_region":   "us-east-1",
		"connection_id":  "cred-aws",
	}
	accountBody, _ := json.Marshal(accountReq)
	createAccount := httptest.NewRequest(http.MethodPost, "/cloud/accounts", bytes.NewReader(accountBody))
	createAccount = createAccount.WithContext(attachCtx("tenant-1"))
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

	// A key an earlier release created natively in the cloud (read-only).
	legacy := CloudKeyBinding{ID: "cbk_legacy", TenantID: "tenant-1", KeyID: "key-1", Provider: ProviderAWS, AccountID: accountResp.Account.ID,
		CloudKeyID: "1234abcd-legacy", Region: "us-east-1", SyncStatus: "synced", MetadataJSON: "{}"}
	if err := svc.store.CreateBinding(createAccount.Context(), legacy); err != nil {
		t.Fatal(err)
	}
	for _, retired := range []string{"/cloud/import", "/cloud/bindings/cbk_legacy/rotate"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, retired+"?tenant_id=tenant-1", bytes.NewReader([]byte(`{}`))))
		if rr.Code != http.StatusNotFound && rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s still answers: %d", retired, rr.Code)
		}
	}

	listHTTP := httptest.NewRequest(http.MethodGet, "/cloud/bindings?tenant_id=tenant-1", nil)
	listRR := httptest.NewRecorder()
	h.ServeHTTP(listRR, listHTTP)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", listRR.Code, listRR.Body.String())
	}

	getHTTP := httptest.NewRequest(http.MethodGet, "/cloud/bindings/"+legacy.ID+"?tenant_id=tenant-1", nil)
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
