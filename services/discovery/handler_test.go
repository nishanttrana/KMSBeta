package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerDiscoveryFlow(t *testing.T) {
	h, _, _ := newDiscoveryHandler(t)
	tenantID := "tenant-h1"

	scanReq := httptest.NewRequest(http.MethodPost, "/discovery/scan", strings.NewReader(`{"tenant_id":"`+tenantID+`","scan_types":["network","cloud"],"trigger":"test"}`))
	scanReq.Header.Set("Content-Type", "application/json")
	scanRR := httptest.NewRecorder()
	h.ServeHTTP(scanRR, scanReq)
	if scanRR.Code != http.StatusAccepted {
		t.Fatalf("scan status=%d body=%s", scanRR.Code, scanRR.Body.String())
	}
	var scanPayload map[string]interface{}
	_ = json.Unmarshal(scanRR.Body.Bytes(), &scanPayload)
	scanID, _ := scanPayload["scan"].(map[string]interface{})["id"].(string)
	if scanID == "" {
		t.Fatalf("missing scan id")
	}

	listScansReq := httptest.NewRequest(http.MethodGet, "/discovery/scans?tenant_id="+tenantID, nil)
	listScansRR := httptest.NewRecorder()
	h.ServeHTTP(listScansRR, listScansReq)
	if listScansRR.Code != http.StatusOK {
		t.Fatalf("list scans status=%d body=%s", listScansRR.Code, listScansRR.Body.String())
	}

	getScanReq := httptest.NewRequest(http.MethodGet, "/discovery/scans/"+scanID+"?tenant_id="+tenantID, nil)
	getScanRR := httptest.NewRecorder()
	h.ServeHTTP(getScanRR, getScanReq)
	if getScanRR.Code != http.StatusOK {
		t.Fatalf("get scan status=%d body=%s", getScanRR.Code, getScanRR.Body.String())
	}

	assetsReq := httptest.NewRequest(http.MethodGet, "/discovery/assets?tenant_id="+tenantID, nil)
	assetsRR := httptest.NewRecorder()
	h.ServeHTTP(assetsRR, assetsReq)
	if assetsRR.Code != http.StatusOK {
		t.Fatalf("assets status=%d body=%s", assetsRR.Code, assetsRR.Body.String())
	}
	var assetsPayload map[string]interface{}
	_ = json.Unmarshal(assetsRR.Body.Bytes(), &assetsPayload)
	items, _ := assetsPayload["items"].([]interface{})
	if len(items) == 0 {
		t.Fatalf("expected assets")
	}
	assetID, _ := items[0].(map[string]interface{})["id"].(string)
	if assetID == "" {
		t.Fatalf("missing asset id")
	}

	aliasReq := httptest.NewRequest(http.MethodGet, "/discovery/crypto/assets?tenant_id="+tenantID, nil)
	aliasRR := httptest.NewRecorder()
	h.ServeHTTP(aliasRR, aliasReq)
	if aliasRR.Code != http.StatusOK {
		t.Fatalf("crypto assets alias status=%d body=%s", aliasRR.Code, aliasRR.Body.String())
	}

	classReq := httptest.NewRequest(http.MethodPut, "/discovery/assets/"+assetID+"/classify", strings.NewReader(`{"tenant_id":"`+tenantID+`","classification":"strong","status":"reviewed"}`))
	classReq.Header.Set("Content-Type", "application/json")
	classRR := httptest.NewRecorder()
	h.ServeHTTP(classRR, classReq)
	if classRR.Code != http.StatusOK {
		t.Fatalf("classify status=%d body=%s", classRR.Code, classRR.Body.String())
	}

	summaryReq := httptest.NewRequest(http.MethodGet, "/discovery/summary?tenant_id="+tenantID, nil)
	summaryRR := httptest.NewRecorder()
	h.ServeHTTP(summaryRR, summaryReq)
	if summaryRR.Code != http.StatusOK {
		t.Fatalf("summary status=%d body=%s", summaryRR.Code, summaryRR.Body.String())
	}

	postureReq := httptest.NewRequest(http.MethodGet, "/discovery/posture?tenant_id="+tenantID, nil)
	postureRR := httptest.NewRecorder()
	h.ServeHTTP(postureRR, postureReq)
	if postureRR.Code != http.StatusOK {
		t.Fatalf("posture status=%d body=%s", postureRR.Code, postureRR.Body.String())
	}
}
