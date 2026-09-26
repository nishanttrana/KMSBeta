package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"vecta-kms/pkg/fips/fipstest"
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

func TestCompromiseEventAutoSuspendsKey(t *testing.T) {
	_, svc := newHandlerForTest(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "compromise-target", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	event, err := svc.ReportCompromiseEvent(context.Background(), CompromiseEvent{
		TenantID:        "t1",
		KeyID:           key.ID,
		CVEID:           "CVE-2026-0001",
		ThreatType:      "cve",
		Severity:        "critical",
		DetectionSource: "unit_test",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if event.Status != "pending" {
		t.Fatalf("unexpected event status: %+v", event)
	}
	got, err := svc.GetKey(context.Background(), "t1", key.ID)
	if err != nil {
		t.Fatal(err)
	}
	if normalizeLifecycleStatus(got.Status) != StateSuspended {
		t.Fatalf("expected key to be suspended, got %s", got.Status)
	}
	events, err := svc.store.ListCompromiseEvents(context.Background(), "t1", "", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].KeyID != key.ID {
		t.Fatalf("unexpected compromise events: %+v", events)
	}
}

func TestEnterpriseKDFAndShamir(t *testing.T) {
	_, svc := newHandlerForTest(t)
	secret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	salt := base64.StdEncoding.EncodeToString([]byte("salt-salt-salt-123"))
	kdf, err := svc.DeriveEnterpriseKDF(context.Background(), KDFDeriveRequest{
		TenantID: "t1", Algorithm: "hkdf-sha256", SecretBase64: secret, SaltBase64: salt, Length: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if kdf.Length != 32 || strings.TrimSpace(kdf.DerivedKeyBase64) == "" || !kdf.SecretNotPersisted {
		t.Fatalf("unexpected kdf response: %+v", kdf)
	}

	split, err := svc.SplitShamirSecret(context.Background(), ShamirSplitRequest{
		TenantID: "t1", SecretBase64: secret, Threshold: 3, Shares: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(split.Shares) != 5 || split.Threshold != 3 {
		t.Fatalf("unexpected split: %+v", split)
	}
	verify, err := svc.VerifyShamirSecret(context.Background(), ShamirVerifyRequest{
		TenantID: "t1", SplitID: split.SplitID, Shares: split.Shares[:3],
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verify.Valid || verify.SecretSHA256 != split.SecretSHA256 {
		t.Fatalf("unexpected verify response: %+v split=%+v", verify, split)
	}
}

func TestEnterpriseAnomalyFeedsDSPM(t *testing.T) {
	_, svc := newHandlerForTest(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "weak-key", Algorithm: "RSA-2048", KeyType: "symmetric", Purpose: "encrypt",
		Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.store.UpsertKeyHealthScore(context.Background(), KeyHealthScore{
		KeyID: key.ID, TenantID: "t1", HealthScore: 30, EntropyScore: 40, AgeScore: 40,
		UsageScore: 50, AlgorithmScore: 75, BackupStatus: "missing", RotationOverdue: true, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	findings, err := svc.RunEnterpriseAnomalyDetection(context.Background(), "t1", 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected anomaly findings")
	}
	stored, err := svc.store.ListDSPMFindings(context.Background(), "t1", DSPMFindingQuery{Status: "open", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) == 0 {
		t.Fatalf("expected stored DSPM findings")
	}
}

func TestExternalIVValidation(t *testing.T) {
	fipstest.SkipIfStrict(t, "caller-supplied AES-GCM IV (iv_mode=external)")
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
	fipstest.SkipIfStrict(t, "caller-supplied AES-GCM IV (iv_mode=external)")
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

func TestStrictModeRefusesExternalIV(t *testing.T) {
	fipstest.StrictOnly(t)
	h, svc := newHandlerForTest(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "k-strict", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Owner: "ops", CreatedBy: "tester", IVMode: "external",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{
		"tenant_id": "t1",
		"plaintext": base64.StdEncoding.EncodeToString([]byte("hello")),
		"iv":        base64.StdEncoding.EncodeToString([]byte("123456789012")),
	})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/keys/"+key.ID+"/encrypt", bytes.NewReader(raw)))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "strict mode") {
		t.Fatalf("strict mode must refuse a caller-supplied IV cleanly, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestInternalIVEncryptWorksInEveryMode(t *testing.T) {
	h, svc := newHandlerForTest(t)
	key, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "k-internal", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Owner: "ops", CreatedBy: "tester",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"tenant_id": "t1", "plaintext": base64.StdEncoding.EncodeToString([]byte("hello"))})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/keys/"+key.ID+"/encrypt", bytes.NewReader(raw)))
	if rr.Code != http.StatusOK {
		t.Fatalf("internal-IV encrypt must work in every FIPS mode, got %d %s", rr.Code, rr.Body.String())
	}
}

// ML-DSA/SLH-DSA come from cloudflare/circl, outside the validated module, so
// strict mode refuses them even though the algorithms are FIPS-approved.
func TestStrictModeRefusesNonModulePQC(t *testing.T) {
	fipstest.StrictOnly(t)
	_, svc := newHandlerForTest(t)
	_, err := svc.CreateKey(context.Background(), CreateKeyRequest{
		TenantID: "t1", Name: "pq-sign", Algorithm: "ML-DSA-65", KeyType: "asymmetric", Purpose: "sign",
		Owner: "ops", CreatedBy: "tester",
	})
	if err == nil || !strings.Contains(err.Error(), "FIPS mode") {
		t.Fatalf("strict mode must refuse ML-DSA from a non-validated implementation, got %v", err)
	}
}

// DER is binary: an encoding that ends in a whitespace byte must import intact
// (it was trimmed and refused, which made TestImportKeyPEMAutodetect flaky).
func TestImportDERWithWhitespaceBoundaryBytes(t *testing.T) {
	for i := 0; ; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if last := der[len(der)-1]; last != ' ' && last != '\t' && last != '\n' && last != '\v' && last != '\f' && last != '\r' {
			if i > 5000 {
				t.Fatal("no key with a whitespace final byte generated")
			}
			continue
		}
		for name, in := range map[string][]byte{
			"der": der,
			"pem": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
		} {
			material, _, keyType, err := parsePEMImportMaterial(in, "")
			if err != nil || keyType != "asymmetric-private" || !bytes.Equal(material, der) {
				t.Fatalf("%s: key ending in %#x must import intact: %v", name, der[len(der)-1], err)
			}
		}
		return
	}
}
