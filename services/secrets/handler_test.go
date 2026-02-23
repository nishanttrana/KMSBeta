package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newSecretsHandler(t *testing.T) (*Handler, *Service, *SQLStore) {
	t.Helper()
	svc, store := newSecretsService(t)
	return NewHandler(svc), svc, store
}

func TestHandlerListNeverReturnsValue(t *testing.T) {
	h, svc, _ := newSecretsHandler(t)
	_, err := svc.CreateSecret(context.Background(), CreateSecretRequest{
		TenantID:   "t1",
		Name:       "token",
		SecretType: "token",
		Value:      "abc",
		CreatedBy:  "tester",
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/secrets?tenant_id=t1", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "\"value\"") {
		t.Fatalf("list response contains secret value: %s", rr.Body.String())
	}
}

func TestHandlerExpiredSecretValueReturns410(t *testing.T) {
	h, svc, store := newSecretsHandler(t)
	secret, err := svc.CreateSecret(context.Background(), CreateSecretRequest{
		TenantID:        "t2",
		Name:            "ttl-secret",
		SecretType:      "password",
		Value:           "secret",
		LeaseTTLSeconds: 10,
		CreatedBy:       "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.db.SQL().Exec(`UPDATE secrets SET expires_at = DATETIME('now', '-5 minute') WHERE tenant_id='t2' AND id=?`, secret.ID)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/secrets/"+secret.ID+"/value?tenant_id=t2", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusGone {
		t.Fatalf("expected 410 got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlerGenerateSSHKeyEndpoint(t *testing.T) {
	h, _, _ := newSecretsHandler(t)
	body := map[string]interface{}{
		"tenant_id":  "t3",
		"name":       "ssh-auto",
		"created_by": "tester",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/secrets/generate/ssh_key", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "ssh-ed25519") {
		t.Fatalf("expected generated public key in response body=%s", rr.Body.String())
	}
}

func TestHandlerGenerateKeyPairEndpoint(t *testing.T) {
	h, _, _ := newSecretsHandler(t)
	body := map[string]interface{}{
		"tenant_id":  "t4",
		"name":       "wg-auto",
		"key_type":   "wireguard-curve25519",
		"created_by": "tester",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/secrets/generate/keypair", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"key_type":"wireguard-curve25519"`) {
		t.Fatalf("expected key_type in response body=%s", rr.Body.String())
	}
}

func TestVaultCompatibleKV2WriteRead(t *testing.T) {
	h, _, _ := newSecretsHandler(t)

	writeBody := `{"data":{"username":"alice","password":"s3cr3t"}}`
	writeReq := httptest.NewRequest(http.MethodPost, "/v1/secret/data/app/config", bytes.NewReader([]byte(writeBody)))
	writeReq.Header.Set("X-Vault-Namespace", "vault-tenant")
	writeRR := httptest.NewRecorder()
	h.ServeHTTP(writeRR, writeReq)
	if writeRR.Code != http.StatusOK {
		t.Fatalf("kv2 write status=%d body=%s", writeRR.Code, writeRR.Body.String())
	}

	readReq := httptest.NewRequest(http.MethodGet, "/v1/secret/data/app/config", nil)
	readReq.Header.Set("X-Vault-Namespace", "vault-tenant")
	readRR := httptest.NewRecorder()
	h.ServeHTTP(readRR, readReq)
	if readRR.Code != http.StatusOK {
		t.Fatalf("kv2 read status=%d body=%s", readRR.Code, readRR.Body.String())
	}
	body := readRR.Body.String()
	if !strings.Contains(body, `"username":"alice"`) || !strings.Contains(body, `"password":"s3cr3t"`) {
		t.Fatalf("unexpected kv2 read payload=%s", body)
	}
}

func TestVaultTokenLookupSelf(t *testing.T) {
	h, _, _ := newSecretsHandler(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token/lookup-self", nil)
	req.Header.Set("X-Vault-Token", "test-token")
	req.Header.Set("X-Vault-Namespace", "tenant-openbao")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("lookup-self status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "tenant-openbao") {
		t.Fatalf("lookup-self missing tenant metadata body=%s", rr.Body.String())
	}
}
