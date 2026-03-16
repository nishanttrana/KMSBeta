package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	pkgcache "vecta-kms/pkg/cache"
	"vecta-kms/pkg/metering"
	"vecta-kms/pkg/payment"
)

type nopPublisher struct{}

func (nopPublisher) Publish(_ context.Context, _ string, _ []byte) error { return nil }

type denyPolicyEvaluator struct{}

func (denyPolicyEvaluator) Evaluate(_ context.Context, _ PolicyEvaluateRequest) (PolicyEvaluateResponse, error) {
	return PolicyEvaluateResponse{Decision: "DENY", Reason: "blocked by test policy"}, nil
}

func newHandlerForTest(t *testing.T) (*Handler, *Service) {
	t.Helper()
	store := newStoreForTest(t)
	mek := []byte("0123456789ABCDEF0123456789ABCDEF")
	svc := NewService(store, NewKeyCache(pkgcache.NewMemory(5*time.Minute), 5*time.Minute), nopPublisher{}, metering.NewMeter(0, time.Hour), mek, nil, false)
	return NewHandler(svc), svc
}

func TestEncryptApprovalRequiredFailsClosedWithoutGovernanceClient(t *testing.T) {
	h, svc := newHandlerForTest(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "k1", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Owner: "ops", CreatedBy: "tester", ApprovalRequired: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"tenant_id": "t1",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/keys/"+key.ID+"/encrypt", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(strings.ToLower(rr.Body.String()), "governance approval is required but governance client is not configured") {
		t.Fatalf("expected governance fail-closed error, got body=%s", rr.Body.String())
	}
}

func TestEncryptOpsLimitReturns429(t *testing.T) {
	h, svc := newHandlerForTest(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "k2", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Owner: "ops", CreatedBy: "tester", OpsLimit: 1, OpsLimitWindow: "total",
	})
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"tenant_id": "t1",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
	}
	raw, _ := json.Marshal(body)

	req1 := httptest.NewRequest(http.MethodPost, "/keys/"+key.ID+"/encrypt", bytes.NewReader(raw))
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", rr1.Code, rr1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/keys/"+key.ID+"/encrypt", bytes.NewReader(raw))
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second status=%d body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestExternalIVValidation(t *testing.T) {
	h, svc := newHandlerForTest(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "k3", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Owner: "ops", CreatedBy: "tester", IVMode: "external",
	})
	if err != nil {
		t.Fatal(err)
	}
	noIV := map[string]any{
		"tenant_id": "t1",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
	}
	raw, _ := json.Marshal(noIV)
	req1 := httptest.NewRequest(http.MethodPost, "/keys/"+key.ID+"/encrypt", bytes.NewReader(raw))
	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 got %d body=%s", rr1.Code, rr1.Body.String())
	}

	withIV := map[string]any{
		"tenant_id": "t1",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
		"iv":        base64.StdEncoding.EncodeToString([]byte("123456789012")),
	}
	raw2, _ := json.Marshal(withIV)
	req2 := httptest.NewRequest(http.MethodPost, "/keys/"+key.ID+"/encrypt", bytes.NewReader(raw2))
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestCreateKeyPolicyDeniedReturns403(t *testing.T) {
	store := newStoreForTest(t)
	mek := []byte("0123456789ABCDEF0123456789ABCDEF")
	svc := NewService(store, NewKeyCache(pkgcache.NewMemory(5*time.Minute), 5*time.Minute), nopPublisher{}, metering.NewMeter(0, time.Hour), mek, denyPolicyEvaluator{}, true)
	h := NewHandler(svc)

	body := map[string]any{
		"tenant_id":  "t1",
		"name":       "k4",
		"algorithm":  "AES-256",
		"key_type":   "symmetric",
		"purpose":    "encrypt",
		"owner":      "ops",
		"created_by": "tester",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/keys", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestImportKeyRawMethod(t *testing.T) {
	h, _ := newHandlerForTest(t)
	body := map[string]any{
		"tenant_id":     "t1",
		"name":          "import-raw",
		"algorithm":     "AES-256",
		"key_type":      "symmetric",
		"purpose":       "encrypt-decrypt",
		"created_by":    "tester",
		"import_method": "raw",
		"material":      base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/keys/import", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if strings.TrimSpace(stringValue(out, "key_id")) == "" {
		t.Fatalf("missing key_id: %s", rr.Body.String())
	}
}

func TestImportKeyPEMAutodetect(t *testing.T) {
	h, svc := newHandlerForTest(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	body := map[string]any{
		"tenant_id":     "t1",
		"name":          "import-pem",
		"algorithm":     "Auto-detect from format",
		"created_by":    "tester",
		"import_method": "pem",
		"material":      string(pemBytes),
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/keys/import", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	keyID := strings.TrimSpace(stringValue(out, "key_id"))
	if keyID == "" {
		t.Fatalf("missing key_id: %s", rr.Body.String())
	}
	key, err := svc.GetKey(context.Background(), "t1", keyID)
	if err != nil {
		t.Fatalf("fetch imported key: %v", err)
	}
	if !strings.HasPrefix(strings.ToUpper(key.Algorithm), "RSA-") {
		t.Fatalf("expected RSA algorithm, got %q", key.Algorithm)
	}
	if !strings.Contains(strings.ToLower(key.KeyType), "asymmetric") {
		t.Fatalf("expected asymmetric key_type, got %q", key.KeyType)
	}
}

func TestImportKeyWrappedEnvelope(t *testing.T) {
	h, svc := newHandlerForTest(t)
	wrappingKey, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID:  "t1",
		Name:      "wrapping-kek",
		Algorithm: "AES-256",
		KeyType:   "symmetric",
		Purpose:   "wrap-unwrap",
		CreatedBy: "tester",
	})
	if err != nil {
		t.Fatalf("create wrapping key: %v", err)
	}
	version, err := svc.GetVersion(context.Background(), "t1", wrappingKey.ID, 0)
	if err != nil {
		t.Fatalf("get wrapping version: %v", err)
	}
	wrappingRaw, err := svc.decryptMaterial(version)
	if err != nil {
		t.Fatalf("decrypt wrapping key material: %v", err)
	}
	defer zeroizeBytes(wrappingRaw)
	targetMaterial := []byte("abcdef0123456789abcdef0123456789")
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("iv generation failed: %v", err)
	}
	wrapped, err := encryptAESGCM(wrappingRaw, iv, targetMaterial, nil)
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}
	artifact := map[string]any{
		"wrapped_material": base64.StdEncoding.EncodeToString(wrapped),
		"material_iv":      base64.StdEncoding.EncodeToString(iv),
		"wrapping_key_id":  wrappingKey.ID,
	}
	artifactJSON, _ := json.Marshal(artifact)
	body := map[string]any{
		"tenant_id":     "t1",
		"name":          "import-wrapped",
		"algorithm":     "AES-256",
		"purpose":       "encrypt-decrypt",
		"created_by":    "tester",
		"import_method": "raw",
		"material":      string(artifactJSON),
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/keys/import", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestImportKeyTR31Method(t *testing.T) {
	h, _ := newHandlerForTest(t)
	keyMaterial := []byte("0123456789abcdef0123456789abcdef")
	kcv, _, err := computeKCVStrict("AES-256", keyMaterial)
	if err != nil {
		t.Fatalf("compute kcv: %v", err)
	}
	tr31, err := payment.BuildTR31(payment.TR31Block{
		Version:   "D",
		Algorithm: "AES-256",
		Usage:     "B0",
		Key:       keyMaterial,
		KCV:       strings.ToUpper(hex.EncodeToString(kcv)),
	})
	if err != nil {
		t.Fatalf("build TR31: %v", err)
	}
	body := map[string]any{
		"tenant_id":     "t1",
		"name":          "import-tr31",
		"algorithm":     "Auto-detect from format",
		"created_by":    "tester",
		"import_method": "tr31",
		"material":      tr31,
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/keys/import", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func stringValue(m map[string]any, key string) string {
	value, _ := m[key]
	out, _ := value.(string)
	return out
}

func zeroizeBytes(raw []byte) {
	for i := range raw {
		raw[i] = 0
	}
}

func TestInterfaceTLSConfigAPIOverridesTLSInterfaceWrites(t *testing.T) {
	h, _ := newHandlerForTest(t)

	tlsConfigBody, _ := json.Marshal(map[string]any{
		"certificate_source": "pki_ca",
		"ca_id":              "ca_root_ops",
	})
	putReq := httptest.NewRequest(http.MethodPut, "/access/interface-tls-config?tenant_id=t1", bytes.NewReader(tlsConfigBody))
	putRR := httptest.NewRecorder()
	h.ServeHTTP(putRR, putReq)
	if putRR.Code != http.StatusOK {
		t.Fatalf("put tls config status=%d body=%s", putRR.Code, putRR.Body.String())
	}

	portBody, _ := json.Marshal(map[string]any{
		"interface_name":     "rest",
		"bind_address":       "0.0.0.0",
		"port":               8443,
		"protocol":           "https",
		"certificate_source": "uploaded_certificate",
		"certificate_id":     "crt_external",
		"enabled":            true,
		"description":        "REST API",
	})
	postReq := httptest.NewRequest(http.MethodPost, "/access/interface-ports?tenant_id=t1", bytes.NewReader(portBody))
	postRR := httptest.NewRecorder()
	h.ServeHTTP(postRR, postReq)
	if postRR.Code != http.StatusOK {
		t.Fatalf("upsert interface port status=%d body=%s", postRR.Code, postRR.Body.String())
	}

	var postOut map[string]any
	if err := json.Unmarshal(postRR.Body.Bytes(), &postOut); err != nil {
		t.Fatalf("decode upsert response: %v", err)
	}
	item, _ := postOut["item"].(map[string]any)
	if got := stringValue(item, "certificate_source"); got != "pki_ca" {
		t.Fatalf("expected pki_ca override, got %q body=%s", got, postRR.Body.String())
	}
	if got := stringValue(item, "ca_id"); got != "ca_root_ops" {
		t.Fatalf("expected ca_root_ops override, got %q body=%s", got, postRR.Body.String())
	}
	if got := stringValue(item, "certificate_id"); got != "" {
		t.Fatalf("expected certificate_id cleared, got %q body=%s", got, postRR.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/access/interface-tls-config?tenant_id=t1", nil)
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("get tls config status=%d body=%s", getRR.Code, getRR.Body.String())
	}

	var getOut map[string]any
	if err := json.Unmarshal(getRR.Body.Bytes(), &getOut); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	cfg, _ := getOut["config"].(map[string]any)
	if got := stringValue(cfg, "certificate_source"); got != "pki_ca" {
		t.Fatalf("expected pki_ca config, got %q body=%s", got, getRR.Body.String())
	}
	if got := stringValue(cfg, "ca_id"); got != "ca_root_ops" {
		t.Fatalf("expected ca_root_ops config, got %q body=%s", got, getRR.Body.String())
	}
}
