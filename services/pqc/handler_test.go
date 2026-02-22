package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPQCHandlerFlow(t *testing.T) {
	h, _, _ := newPQCHandler(t)
	tenantID := "tenant-h1"

	scanReq := httptest.NewRequest(http.MethodPost, "/pqc/scan", strings.NewReader(`{"tenant_id":"`+tenantID+`","trigger":"test"}`))
	scanReq.Header.Set("Content-Type", "application/json")
	scanRR := httptest.NewRecorder()
	h.ServeHTTP(scanRR, scanReq)
	if scanRR.Code != http.StatusAccepted {
		t.Fatalf("scan status=%d body=%s", scanRR.Code, scanRR.Body.String())
	}

	readinessReq := httptest.NewRequest(http.MethodGet, "/pqc/readiness?tenant_id="+tenantID, nil)
	readinessRR := httptest.NewRecorder()
	h.ServeHTTP(readinessRR, readinessReq)
	if readinessRR.Code != http.StatusOK {
		t.Fatalf("readiness status=%d body=%s", readinessRR.Code, readinessRR.Body.String())
	}

	planReq := httptest.NewRequest(http.MethodPost, "/pqc/migration/plans", strings.NewReader(`{"tenant_id":"`+tenantID+`","name":"plan-a","created_by":"tester"}`))
	planReq.Header.Set("Content-Type", "application/json")
	planRR := httptest.NewRecorder()
	h.ServeHTTP(planRR, planReq)
	if planRR.Code != http.StatusCreated {
		t.Fatalf("create plan status=%d body=%s", planRR.Code, planRR.Body.String())
	}
	var planPayload map[string]interface{}
	_ = json.Unmarshal(planRR.Body.Bytes(), &planPayload)
	planID, _ := planPayload["plan"].(map[string]interface{})["id"].(string)
	if planID == "" {
		t.Fatalf("missing plan id")
	}

	listPlansReq := httptest.NewRequest(http.MethodGet, "/pqc/migration/plans?tenant_id="+tenantID, nil)
	listPlansRR := httptest.NewRecorder()
	h.ServeHTTP(listPlansRR, listPlansReq)
	if listPlansRR.Code != http.StatusOK {
		t.Fatalf("list plans status=%d body=%s", listPlansRR.Code, listPlansRR.Body.String())
	}

	getPlanReq := httptest.NewRequest(http.MethodGet, "/pqc/migration/plans/"+planID+"?tenant_id="+tenantID, nil)
	getPlanRR := httptest.NewRecorder()
	h.ServeHTTP(getPlanRR, getPlanReq)
	if getPlanRR.Code != http.StatusOK {
		t.Fatalf("get plan status=%d body=%s", getPlanRR.Code, getPlanRR.Body.String())
	}

	execReq := httptest.NewRequest(http.MethodPost, "/pqc/migration/plans/"+planID+"/execute", strings.NewReader(`{"tenant_id":"`+tenantID+`","dry_run":true,"actor":"tester"}`))
	execReq.Header.Set("Content-Type", "application/json")
	execRR := httptest.NewRecorder()
	h.ServeHTTP(execRR, execReq)
	if execRR.Code != http.StatusOK {
		t.Fatalf("execute status=%d body=%s", execRR.Code, execRR.Body.String())
	}

	runsReq := httptest.NewRequest(http.MethodGet, "/pqc/migration/plans/"+planID+"/runs?tenant_id="+tenantID, nil)
	runsRR := httptest.NewRecorder()
	h.ServeHTTP(runsRR, runsReq)
	if runsRR.Code != http.StatusOK {
		t.Fatalf("runs status=%d body=%s", runsRR.Code, runsRR.Body.String())
	}

	rollbackReq := httptest.NewRequest(http.MethodPost, "/pqc/migration/plans/"+planID+"/rollback", strings.NewReader(`{"tenant_id":"`+tenantID+`","actor":"tester"}`))
	rollbackReq.Header.Set("Content-Type", "application/json")
	rollbackRR := httptest.NewRecorder()
	h.ServeHTTP(rollbackRR, rollbackReq)
	if rollbackRR.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollbackRR.Code, rollbackRR.Body.String())
	}

	timelineReq := httptest.NewRequest(http.MethodGet, "/pqc/timeline?tenant_id="+tenantID, nil)
	timelineRR := httptest.NewRecorder()
	h.ServeHTTP(timelineRR, timelineReq)
	if timelineRR.Code != http.StatusOK {
		t.Fatalf("timeline status=%d body=%s", timelineRR.Code, timelineRR.Body.String())
	}

	cbomReq := httptest.NewRequest(http.MethodGet, "/pqc/cbom/export?tenant_id="+tenantID, nil)
	cbomRR := httptest.NewRecorder()
	h.ServeHTTP(cbomRR, cbomReq)
	if cbomRR.Code != http.StatusOK {
		t.Fatalf("cbom status=%d body=%s", cbomRR.Code, cbomRR.Body.String())
	}
}
