package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ocsp"
)

func newCertsHandler(t *testing.T) (*Handler, *Service) {
	t.Helper()
	svc, _ := newCertsService(t)
	return NewHandler(svc), svc
}

func TestHandlerCreateCAAndIssue(t *testing.T) {
	h, _ := newCertsHandler(t)
	caReq := map[string]interface{}{
		"tenant_id":   "t1",
		"name":        "root",
		"ca_level":    "root",
		"algorithm":   "ECDSA-P384",
		"key_backend": "software",
		"subject":     "CN=Root",
	}
	raw, _ := json.Marshal(caReq)
	req := httptest.NewRequest(http.MethodPost, "/certs/ca", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create ca status=%d body=%s", rr.Code, rr.Body.String())
	}
	var caResp struct {
		CA CA `json:"ca"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &caResp)
	if caResp.CA.ID == "" {
		t.Fatalf("missing ca id in response: %s", rr.Body.String())
	}

	issueReq := map[string]interface{}{
		"tenant_id":     "t1",
		"ca_id":         caResp.CA.ID,
		"subject_cn":    "svc.vecta.local",
		"sans":          []string{"svc.vecta.local"},
		"cert_type":     "tls-server",
		"algorithm":     "ECDSA-P256",
		"server_keygen": true,
	}
	issueRaw, _ := json.Marshal(issueReq)
	issueHTTP := httptest.NewRequest(http.MethodPost, "/certs", bytes.NewReader(issueRaw))
	issueRR := httptest.NewRecorder()
	h.ServeHTTP(issueRR, issueHTTP)
	if issueRR.Code != http.StatusCreated {
		t.Fatalf("issue status=%d body=%s", issueRR.Code, issueRR.Body.String())
	}
	if !strings.Contains(issueRR.Body.String(), "BEGIN CERTIFICATE") {
		t.Fatalf("missing certificate pem in response")
	}
}

func TestHandlerPQCReadinessAndOCSP(t *testing.T) {
	h, svc := newCertsHandler(t)
	ctx := context.Background()
	ca, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "t2",
		Name:       "root",
		CALevel:    "root",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=Root",
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := svc.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:  "t2",
		CAID:      ca.ID,
		SubjectCN: "pqc-service",
		CertType:  "tls-server",
		Algorithm: "ML-DSA-65",
		CertClass: "pqc",
	})
	if err != nil {
		t.Fatal(err)
	}

	readinessReq := httptest.NewRequest(http.MethodGet, "/certs/pqc-readiness?tenant_id=t2", nil)
	readinessRR := httptest.NewRecorder()
	h.ServeHTTP(readinessRR, readinessReq)
	if readinessRR.Code != http.StatusOK {
		t.Fatalf("readiness status=%d body=%s", readinessRR.Code, readinessRR.Body.String())
	}
	if !strings.Contains(readinessRR.Body.String(), "\"pqc\":1") {
		t.Fatalf("expected pqc count in response body=%s", readinessRR.Body.String())
	}

	ocspReq := httptest.NewRequest(http.MethodGet, "/certs/ocsp?tenant_id=t2&cert_id="+cert.ID, nil)
	ocspRR := httptest.NewRecorder()
	h.ServeHTTP(ocspRR, ocspReq)
	if ocspRR.Code != http.StatusOK {
		t.Fatalf("ocsp status=%d body=%s", ocspRR.Code, ocspRR.Body.String())
	}
	if !strings.Contains(ocspRR.Body.String(), "\"status\":\"good\"") {
		t.Fatalf("unexpected ocsp response=%s", ocspRR.Body.String())
	}
}

func TestHandlerACMEFlow(t *testing.T) {
	h, svc := newCertsHandler(t)
	ctx := context.Background()
	ca, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "t3",
		Name:       "acme-root",
		CALevel:    "root",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=ACME Root",
	})
	if err != nil {
		t.Fatal(err)
	}
	acctReq := map[string]interface{}{"tenant_id": "t3", "email": "ops@example.com"}
	acctRaw, _ := json.Marshal(acctReq)
	acctHTTP := httptest.NewRequest(http.MethodPost, "/acme/new-account", bytes.NewReader(acctRaw))
	acctRR := httptest.NewRecorder()
	h.ServeHTTP(acctRR, acctHTTP)
	if acctRR.Code != http.StatusCreated {
		t.Fatalf("acme account status=%d body=%s", acctRR.Code, acctRR.Body.String())
	}
	var acctResp map[string]interface{}
	_ = json.Unmarshal(acctRR.Body.Bytes(), &acctResp)
	orderReq := map[string]interface{}{
		"tenant_id":  "t3",
		"ca_id":      ca.ID,
		"account_id": acctResp["account_id"],
		"subject_cn": "acme.t3.local",
		"sans":       []string{"acme.t3.local"},
	}
	orderRaw, _ := json.Marshal(orderReq)
	orderHTTP := httptest.NewRequest(http.MethodPost, "/acme/new-order", bytes.NewReader(orderRaw))
	orderRR := httptest.NewRecorder()
	h.ServeHTTP(orderRR, orderHTTP)
	if orderRR.Code != http.StatusCreated {
		t.Fatalf("acme order status=%d body=%s", orderRR.Code, orderRR.Body.String())
	}
}

func TestHandlerProtocolConfigAndUpload(t *testing.T) {
	h, svc := newCertsHandler(t)
	ctx := context.Background()

	cfgReq := map[string]interface{}{
		"enabled":     true,
		"config_json": `{"rfc":"8555","challenge_types":["http-01"]}`,
		"updated_by":  "tester",
	}
	cfgRaw, _ := json.Marshal(cfgReq)
	cfgHTTP := httptest.NewRequest(http.MethodPut, "/certs/protocols/acme?tenant_id=t9", bytes.NewReader(cfgRaw))
	cfgRR := httptest.NewRecorder()
	h.ServeHTTP(cfgRR, cfgHTTP)
	if cfgRR.Code != http.StatusOK {
		t.Fatalf("protocol config status=%d body=%s", cfgRR.Code, cfgRR.Body.String())
	}

	ca, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "t9",
		Name:       "upload-root",
		CALevel:    "root",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=Upload Root",
	})
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	issued, keyPEM, err := svc.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:     "t9",
		CAID:         ca.ID,
		SubjectCN:    "upload.t9.local",
		SANs:         []string{"upload.t9.local"},
		CertType:     "tls-server",
		Algorithm:    "ECDSA-P256",
		ServerKeygen: true,
	})
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	uploadReq := map[string]interface{}{
		"tenant_id":            "t9",
		"purpose":              "KMS Web Interface (HTTPS:443)",
		"certificate_pem":      issued.CertPEM,
		"private_key_pem":      keyPEM,
		"set_active":           true,
		"enable_ocsp_stapling": true,
	}
	uploadRaw, _ := json.Marshal(uploadReq)
	uploadHTTP := httptest.NewRequest(http.MethodPost, "/certs/upload-3p", bytes.NewReader(uploadRaw))
	uploadRR := httptest.NewRecorder()
	h.ServeHTTP(uploadRR, uploadHTTP)
	if uploadRR.Code != http.StatusCreated {
		t.Fatalf("upload status=%d body=%s", uploadRR.Code, uploadRR.Body.String())
	}
	if !strings.Contains(uploadRR.Body.String(), "\"protocol\":\"upload-3p\"") {
		t.Fatalf("expected upload protocol marker in body=%s", uploadRR.Body.String())
	}
}

func TestHandlerProtocolSchemas(t *testing.T) {
	h, _ := newCertsHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/certs/protocols/schema", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("schema status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, protocol := range []string{"\"protocol\":\"acme\"", "\"protocol\":\"est\"", "\"protocol\":\"scep\"", "\"protocol\":\"cmpv2\""} {
		if !strings.Contains(body, protocol) {
			t.Fatalf("expected %s in schema response body=%s", protocol, body)
		}
	}
	if !strings.Contains(body, "\"implementation\"") {
		t.Fatalf("expected implementation section in schema response body=%s", body)
	}
}

func TestHandlerDeleteCertificate(t *testing.T) {
	h, svc := newCertsHandler(t)
	ctx := context.Background()
	ca, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "t-del",
		Name:       "root",
		CALevel:    "root",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=Root",
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, _, err := svc.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:  "t-del",
		CAID:      ca.ID,
		SubjectCN: "svc.delete.local",
		CertType:  "tls-server",
		Algorithm: "ECDSA-P256",
	})
	if err != nil {
		t.Fatal(err)
	}
	delReq := httptest.NewRequest(http.MethodDelete, "/certs/"+issued.ID+"?tenant_id=t-del", nil)
	delRR := httptest.NewRecorder()
	h.ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", delRR.Code, delRR.Body.String())
	}
	getReq := httptest.NewRequest(http.MethodGet, "/certs/"+issued.ID+"?tenant_id=t-del", nil)
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("expected certificate metadata after delete status=%d body=%s", getRR.Code, getRR.Body.String())
	}
	if !strings.Contains(strings.ToLower(getRR.Body.String()), "\"status\":\"deleted\"") {
		t.Fatalf("expected deleted status after delete body=%s", getRR.Body.String())
	}
}

func TestHandlerProtocolWireCompatESTSCEPCMP(t *testing.T) {
	h, svc := newCertsHandler(t)
	ctx := context.Background()
	ca, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "t-wire",
		Name:       "wire-root",
		CALevel:    "root",
		Algorithm:  "ECDSA-P384",
		KeyBackend: "software",
		Subject:    "CN=Wire Root",
	})
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := mustCSRPEM(t, "wire-client.local")

	estReq := httptest.NewRequest(
		http.MethodPost,
		"/est/.well-known/est/simpleenroll?tenant_id=t-wire&ca_id="+ca.ID,
		bytes.NewReader([]byte(csrPEM)),
	)
	estReq.Header.Set("Content-Type", "application/pkcs10")
	estRR := httptest.NewRecorder()
	h.ServeHTTP(estRR, estReq)
	if estRR.Code != http.StatusOK {
		t.Fatalf("est wire status=%d body=%s", estRR.Code, estRR.Body.String())
	}
	if ct := strings.ToLower(estRR.Header().Get("Content-Type")); !strings.Contains(ct, "application/pkix-cert") {
		t.Fatalf("unexpected est content-type=%s", ct)
	}
	if _, err := x509.ParseCertificate(estRR.Body.Bytes()); err != nil {
		t.Fatalf("est wire response not x509 der: %v", err)
	}

	scepReq := httptest.NewRequest(
		http.MethodPost,
		"/scep/pkiclient.exe?operation=pkioperation&tenant_id=t-wire&ca_id="+ca.ID+"&message_type=pkcsreq&transaction_id=txn-1",
		bytes.NewReader([]byte(csrPEM)),
	)
	scepReq.Header.Set("Content-Type", "application/x-pki-message")
	scepRR := httptest.NewRecorder()
	h.ServeHTTP(scepRR, scepReq)
	if scepRR.Code != http.StatusOK {
		t.Fatalf("scep wire status=%d body=%s", scepRR.Code, scepRR.Body.String())
	}
	if ct := strings.ToLower(scepRR.Header().Get("Content-Type")); !strings.Contains(ct, "application/x-pki-message") {
		t.Fatalf("unexpected scep content-type=%s", ct)
	}
	if _, err := x509.ParseCertificate(scepRR.Body.Bytes()); err != nil {
		t.Fatalf("scep wire response not certificate der: %v", err)
	}

	cmpReq := httptest.NewRequest(
		http.MethodPost,
		"/cmpv2?tenant_id=t-wire&ca_id="+ca.ID+"&message_type=ir&transaction_id=cmp-1&protected=true",
		bytes.NewReader([]byte(csrPEM)),
	)
	cmpReq.Header.Set("Content-Type", "application/pkixcmp")
	cmpRR := httptest.NewRecorder()
	h.ServeHTTP(cmpRR, cmpReq)
	if cmpRR.Code != http.StatusOK {
		t.Fatalf("cmp wire status=%d body=%s", cmpRR.Code, cmpRR.Body.String())
	}
	if ct := strings.ToLower(cmpRR.Header().Get("Content-Type")); !strings.Contains(ct, "application/pkix-cert") {
		t.Fatalf("unexpected cmp content-type=%s", ct)
	}
	if _, err := x509.ParseCertificate(cmpRR.Body.Bytes()); err != nil {
		t.Fatalf("cmp wire response not certificate der: %v", err)
	}
}

func TestHandlerOCSPWireResponse(t *testing.T) {
	h, svc := newCertsHandler(t)
	ctx := context.Background()
	ca, err := svc.CreateCA(ctx, CreateCARequest{
		TenantID:   "t-ocsp",
		Name:       "ocsp-root",
		CALevel:    "root",
		Algorithm:  "RSA-4096",
		KeyBackend: "software",
		Subject:    "CN=OCSP Root",
	})
	if err != nil {
		t.Fatal(err)
	}
	issued, _, err := svc.IssueCertificate(ctx, IssueCertificateRequest{
		TenantID:  "t-ocsp",
		CAID:      ca.ID,
		SubjectCN: "svc.ocsp.local",
		CertType:  "tls-server",
		Algorithm: "RSA-2048",
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := parseCertificatePEM(issued.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := parseCertificatePEM(ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	reqDER, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/certs/ocsp?tenant_id=t-ocsp", bytes.NewReader(reqDER))
	req.Header.Set("Content-Type", "application/ocsp-request")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("ocsp wire status=%d body=%s", rr.Code, rr.Body.String())
	}
	if ct := strings.ToLower(rr.Header().Get("Content-Type")); !strings.Contains(ct, "application/ocsp-response") {
		t.Fatalf("unexpected ocsp wire content-type=%s", ct)
	}
	resp, err := ocsp.ParseResponseForCert(rr.Body.Bytes(), leaf, issuer)
	if err != nil {
		t.Fatalf("invalid ocsp response: %v", err)
	}
	if resp.Status != ocsp.Good {
		t.Fatalf("unexpected ocsp status=%d", resp.Status)
	}
}

func mustCSRPEM(t *testing.T, commonName string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	req := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: []string{commonName},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
