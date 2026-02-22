package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerSBOMEndpoints(t *testing.T) {
	h, _, _, _, _, _ := newSBOMHandler(t)

	genReq := httptest.NewRequest(http.MethodPost, "/sbom/generate", strings.NewReader(`{"trigger":"test"}`))
	genReq.Header.Set("Content-Type", "application/json")
	genRR := httptest.NewRecorder()
	h.ServeHTTP(genRR, genReq)
	if genRR.Code != http.StatusAccepted {
		t.Fatalf("generate sbom status=%d body=%s", genRR.Code, genRR.Body.String())
	}

	var gen map[string]interface{}
	if err := json.Unmarshal(genRR.Body.Bytes(), &gen); err != nil {
		t.Fatalf("decode generate response: %v", err)
	}
	snapshotMap, _ := gen["snapshot"].(map[string]interface{})
	snapshotID, _ := snapshotMap["id"].(string)
	if snapshotID == "" {
		t.Fatalf("expected snapshot id in response: %s", genRR.Body.String())
	}

	latestReq := httptest.NewRequest(http.MethodGet, "/sbom/latest", nil)
	latestRR := httptest.NewRecorder()
	h.ServeHTTP(latestRR, latestReq)
	if latestRR.Code != http.StatusOK {
		t.Fatalf("latest sbom status=%d body=%s", latestRR.Code, latestRR.Body.String())
	}

	vulnReq := httptest.NewRequest(http.MethodGet, "/sbom/vulnerabilities", nil)
	vulnRR := httptest.NewRecorder()
	h.ServeHTTP(vulnRR, vulnReq)
	if vulnRR.Code != http.StatusOK {
		t.Fatalf("vulns sbom status=%d body=%s", vulnRR.Code, vulnRR.Body.String())
	}

	expReq := httptest.NewRequest(http.MethodGet, "/sbom/"+snapshotID+"/export?format=spdx", nil)
	expRR := httptest.NewRecorder()
	h.ServeHTTP(expRR, expReq)
	if expRR.Code != http.StatusOK {
		t.Fatalf("export sbom status=%d body=%s", expRR.Code, expRR.Body.String())
	}

	pdfReq := httptest.NewRequest(http.MethodGet, "/sbom/"+snapshotID+"/export?format=pdf", nil)
	pdfRR := httptest.NewRecorder()
	h.ServeHTTP(pdfRR, pdfReq)
	if pdfRR.Code != http.StatusOK {
		t.Fatalf("export sbom pdf status=%d body=%s", pdfRR.Code, pdfRR.Body.String())
	}
	var pdfPayload map[string]interface{}
	if err := json.Unmarshal(pdfRR.Body.Bytes(), &pdfPayload); err != nil {
		t.Fatalf("decode sbom pdf payload: %v", err)
	}
	exportMap, _ := pdfPayload["export"].(map[string]interface{})
	content, _ := exportMap["content"].(string)
	raw, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		t.Fatalf("decode sbom pdf base64: %v", err)
	}
	if !strings.HasPrefix(string(raw), "%PDF-") {
		t.Fatalf("expected valid pdf header, got: %q", string(raw[:min(10, len(raw))]))
	}
	if len(raw) < 500 {
		t.Fatalf("expected non-trivial pdf content, got %d bytes", len(raw))
	}

	diffReq := httptest.NewRequest(http.MethodGet, "/sbom/diff?from="+snapshotID+"&to="+snapshotID, nil)
	diffRR := httptest.NewRecorder()
	h.ServeHTTP(diffRR, diffReq)
	if diffRR.Code != http.StatusOK {
		t.Fatalf("diff sbom status=%d body=%s", diffRR.Code, diffRR.Body.String())
	}
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestHandlerCBOMEndpoints(t *testing.T) {
	h, _, keycore, certs, _, _ := newSBOMHandler(t)
	tenantID := "tenant-h"
	keycore.keys[tenantID] = []map[string]interface{}{
		{"id": "k1", "name": "data", "algorithm": "AES-256", "status": "active"},
	}
	certs.items[tenantID] = []map[string]interface{}{
		{"id": "c1", "subject_cn": "svc.example", "algorithm": "ML-DSA-65", "cert_class": "pqc", "status": "active"},
	}

	genReq := httptest.NewRequest(http.MethodPost, "/cbom/generate", strings.NewReader(`{"tenant_id":"`+tenantID+`","trigger":"test"}`))
	genReq.Header.Set("Content-Type", "application/json")
	genRR := httptest.NewRecorder()
	h.ServeHTTP(genRR, genReq)
	if genRR.Code != http.StatusAccepted {
		t.Fatalf("generate cbom status=%d body=%s", genRR.Code, genRR.Body.String())
	}

	var gen map[string]interface{}
	if err := json.Unmarshal(genRR.Body.Bytes(), &gen); err != nil {
		t.Fatalf("decode generate cbom response: %v", err)
	}
	snapshotMap, _ := gen["snapshot"].(map[string]interface{})
	snapshotID, _ := snapshotMap["id"].(string)
	if snapshotID == "" {
		t.Fatalf("expected cbom snapshot id in response: %s", genRR.Body.String())
	}

	reqs := []string{
		"/cbom/latest?tenant_id=" + tenantID,
		"/cbom/history?tenant_id=" + tenantID,
		"/cbom/summary?tenant_id=" + tenantID,
		"/cbom/pqc-readiness?tenant_id=" + tenantID,
		"/cbom/" + snapshotID + "?tenant_id=" + tenantID,
		"/cbom/" + snapshotID + "/export?tenant_id=" + tenantID + "&format=cyclonedx",
		"/cbom/diff?tenant_id=" + tenantID + "&from=" + snapshotID + "&to=" + snapshotID,
	}
	for _, path := range reqs {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("path %s status=%d body=%s", path, rr.Code, rr.Body.String())
		}
	}
}
