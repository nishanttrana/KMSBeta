package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandlerPostureAndFrameworkEndpoints(t *testing.T) {
	h, _, keycore, policy, audit, _, _ := newComplianceHandler(t)
	keycore.keys["t1"] = []map[string]interface{}{
		{"id": "k1", "algorithm": "AES-256", "status": "active", "current_version": 2, "ops_total": 10},
		{"id": "k2", "algorithm": "3DES", "status": "active", "current_version": 1, "ops_total": 0},
	}
	policy.policies["t1"] = []map[string]interface{}{
		{"id": "p1", "status": "active"},
	}
	audit.events["t1"] = []map[string]interface{}{
		{"action": "auth.login_failed", "correlation_id": "c1", "timestamp": time.Now().UTC().Format(time.RFC3339)},
	}
	audit.stats["t1"] = map[string]interface{}{"critical": 0, "high": 1}

	postureReq := httptest.NewRequest(http.MethodGet, "/compliance/posture?tenant_id=t1&refresh=true", nil)
	postureRR := httptest.NewRecorder()
	h.ServeHTTP(postureRR, postureReq)
	if postureRR.Code != http.StatusOK {
		t.Fatalf("posture status=%d body=%s", postureRR.Code, postureRR.Body.String())
	}
	if !strings.Contains(postureRR.Body.String(), "\"overall_score\"") {
		t.Fatalf("unexpected posture body=%s", postureRR.Body.String())
	}

	ctrlReq := httptest.NewRequest(http.MethodGet, "/compliance/frameworks/pci-dss-4.0/controls?tenant_id=t1", nil)
	ctrlRR := httptest.NewRecorder()
	h.ServeHTTP(ctrlRR, ctrlReq)
	if ctrlRR.Code != http.StatusOK {
		t.Fatalf("controls status=%d body=%s", ctrlRR.Code, ctrlRR.Body.String())
	}

	gapsReq := httptest.NewRequest(http.MethodGet, "/compliance/frameworks/pci-dss-4.0/gaps?tenant_id=t1", nil)
	gapsRR := httptest.NewRecorder()
	h.ServeHTTP(gapsRR, gapsReq)
	if gapsRR.Code != http.StatusOK {
		t.Fatalf("gaps status=%d body=%s", gapsRR.Code, gapsRR.Body.String())
	}
}

func TestHandlerKeyHygieneAndAuditEndpoints(t *testing.T) {
	h, _, keycore, _, audit, _, _ := newComplianceHandler(t)
	keycore.keys["t2"] = []map[string]interface{}{
		{"id": "k1", "algorithm": "AES-256", "status": "active", "current_version": 2, "ops_total": 11},
		{"id": "k2", "algorithm": "RSA-2048", "status": "deactivated", "current_version": 1, "ops_total": 0},
	}
	audit.events["t2"] = []map[string]interface{}{
		{"action": "auth.login_failed", "result": "failure", "correlation_id": "c1", "timestamp": time.Now().UTC().Format(time.RFC3339)},
		{"action": "auth.login_failed", "result": "failure", "correlation_id": "c1", "timestamp": time.Now().UTC().Format(time.RFC3339)},
		{"action": "auth.login_failed", "result": "failure", "correlation_id": "c1", "timestamp": time.Now().UTC().Format(time.RFC3339)},
	}

	req := httptest.NewRequest(http.MethodGet, "/compliance/keys/hygiene?tenant_id=t2", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("hygiene status=%d body=%s", rr.Code, rr.Body.String())
	}

	corrReq := httptest.NewRequest(http.MethodGet, "/compliance/audit/correlations?tenant_id=t2", nil)
	corrRR := httptest.NewRecorder()
	h.ServeHTTP(corrRR, corrReq)
	if corrRR.Code != http.StatusOK {
		t.Fatalf("correlations status=%d body=%s", corrRR.Code, corrRR.Body.String())
	}

	anomReq := httptest.NewRequest(http.MethodGet, "/compliance/audit/anomalies?tenant_id=t2", nil)
	anomRR := httptest.NewRecorder()
	h.ServeHTTP(anomRR, anomReq)
	if anomRR.Code != http.StatusOK || !strings.Contains(anomRR.Body.String(), "failed_auth_spike") {
		t.Fatalf("anomalies status=%d body=%s", anomRR.Code, anomRR.Body.String())
	}
}

func TestHandlerSBOMAndCBOMEndpoints(t *testing.T) {
	h, _, keycore, _, _, _, _ := newComplianceHandler(t)
	keycore.keys["t3"] = []map[string]interface{}{
		{"id": "k1", "algorithm": "AES-256", "status": "active"},
		{"id": "k2", "algorithm": "ML-KEM-768", "status": "active"},
	}

	sbomReq := httptest.NewRequest(http.MethodGet, "/compliance/sbom?format=spdx", nil)
	sbomRR := httptest.NewRecorder()
	h.ServeHTTP(sbomRR, sbomReq)
	if sbomRR.Code != http.StatusOK {
		t.Fatalf("sbom status=%d body=%s", sbomRR.Code, sbomRR.Body.String())
	}

	cbomReq := httptest.NewRequest(http.MethodGet, "/compliance/cbom?tenant_id=t3", nil)
	cbomRR := httptest.NewRecorder()
	h.ServeHTTP(cbomRR, cbomReq)
	if cbomRR.Code != http.StatusOK {
		t.Fatalf("cbom status=%d body=%s", cbomRR.Code, cbomRR.Body.String())
	}

	pqcReq := httptest.NewRequest(http.MethodGet, "/compliance/cbom/pqc-readiness?tenant_id=t3", nil)
	pqcRR := httptest.NewRecorder()
	h.ServeHTTP(pqcRR, pqcReq)
	if pqcRR.Code != http.StatusOK {
		t.Fatalf("pqc status=%d body=%s", pqcRR.Code, pqcRR.Body.String())
	}

	diffReq := httptest.NewRequest(http.MethodGet, "/compliance/cbom/diff?tenant_id=t3", nil)
	diffRR := httptest.NewRecorder()
	h.ServeHTTP(diffRR, diffReq)
	if diffRR.Code != http.StatusOK {
		t.Fatalf("diff status=%d body=%s", diffRR.Code, diffRR.Body.String())
	}

	_ = bytes.NewBuffer(nil)
	_ = json.RawMessage{}
}

func TestHandlerAssessmentRunAndSchedule(t *testing.T) {
	h, _, keycore, _, _, certs, _ := newComplianceHandler(t)
	keycore.keys["t4"] = []map[string]interface{}{
		{"id": "k1", "algorithm": "RSA-1024", "status": "active", "current_version": 1, "ops_total": 10, "created_at": time.Now().UTC().Add(-400 * 24 * time.Hour).Format(time.RFC3339)},
	}
	certs.certs["t4"] = []map[string]interface{}{
		{"id": "c1", "algorithm": "RSA-1024-SHA1", "status": "active", "not_after": time.Now().UTC().Add(5 * 24 * time.Hour).Format(time.RFC3339)},
	}

	getBeforeRunReq := httptest.NewRequest(http.MethodGet, "/compliance/assessment?tenant_id=t4", nil)
	getBeforeRunRR := httptest.NewRecorder()
	h.ServeHTTP(getBeforeRunRR, getBeforeRunReq)
	if getBeforeRunRR.Code != http.StatusNotFound || !strings.Contains(getBeforeRunRR.Body.String(), "has not been run yet") {
		t.Fatalf("get assessment before run status=%d body=%s", getBeforeRunRR.Code, getBeforeRunRR.Body.String())
	}

	runReq := httptest.NewRequest(http.MethodPost, "/compliance/assessment/run?tenant_id=t4", nil)
	runRR := httptest.NewRecorder()
	h.ServeHTTP(runRR, runReq)
	if runRR.Code != http.StatusOK || !strings.Contains(runRR.Body.String(), "\"assessment\"") {
		t.Fatalf("run assessment status=%d body=%s", runRR.Code, runRR.Body.String())
	}

	keycore.keys["t4"] = append(keycore.keys["t4"], map[string]interface{}{
		"id": "k2", "algorithm": "3DES", "status": "active", "current_version": 1, "ops_total": 0,
	})
	runAgainReq := httptest.NewRequest(http.MethodPost, "/compliance/assessment/run?tenant_id=t4", nil)
	runAgainRR := httptest.NewRecorder()
	h.ServeHTTP(runAgainRR, runAgainReq)
	if runAgainRR.Code != http.StatusOK {
		t.Fatalf("second assessment status=%d body=%s", runAgainRR.Code, runAgainRR.Body.String())
	}

	deltaReq := httptest.NewRequest(http.MethodGet, "/compliance/assessment/delta?tenant_id=t4", nil)
	deltaRR := httptest.NewRecorder()
	h.ServeHTTP(deltaRR, deltaReq)
	if deltaRR.Code != http.StatusOK || !strings.Contains(deltaRR.Body.String(), "\"delta\"") {
		t.Fatalf("delta status=%d body=%s", deltaRR.Code, deltaRR.Body.String())
	}

	putScheduleReq := httptest.NewRequest(http.MethodPut, "/compliance/assessment/schedule",
		strings.NewReader(`{"tenant_id":"t4","enabled":true,"frequency":"daily"}`))
	putScheduleReq.Header.Set("Content-Type", "application/json")
	putScheduleRR := httptest.NewRecorder()
	h.ServeHTTP(putScheduleRR, putScheduleReq)
	if putScheduleRR.Code != http.StatusOK {
		t.Fatalf("put schedule status=%d body=%s", putScheduleRR.Code, putScheduleRR.Body.String())
	}

	getScheduleReq := httptest.NewRequest(http.MethodGet, "/compliance/assessment/schedule?tenant_id=t4", nil)
	getScheduleRR := httptest.NewRecorder()
	h.ServeHTTP(getScheduleRR, getScheduleReq)
	if getScheduleRR.Code != http.StatusOK || !strings.Contains(getScheduleRR.Body.String(), "\"enabled\":true") {
		t.Fatalf("get schedule status=%d body=%s", getScheduleRR.Code, getScheduleRR.Body.String())
	}
}

func TestHandlerComplianceTemplateEndpoints(t *testing.T) {
	h, _, keycore, _, _, _, _ := newComplianceHandler(t)
	keycore.keys["t6"] = []map[string]interface{}{
		{"id": "k1", "algorithm": "AES-256", "status": "active", "current_version": 2, "ops_total": 11},
	}

	createReq := httptest.NewRequest(http.MethodPost, "/compliance/templates",
		strings.NewReader(`{"tenant_id":"t6","name":"My Template","enabled":true}`))
	createReq.Header.Set("Content-Type", "application/json")
	createRR := httptest.NewRecorder()
	h.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusOK || !strings.Contains(createRR.Body.String(), "\"template\"") {
		t.Fatalf("create template status=%d body=%s", createRR.Code, createRR.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/compliance/templates?tenant_id=t6", nil)
	listRR := httptest.NewRecorder()
	h.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK || !strings.Contains(listRR.Body.String(), "My Template") {
		t.Fatalf("list templates status=%d body=%s", listRR.Code, listRR.Body.String())
	}

	runReq := httptest.NewRequest(http.MethodPost, "/compliance/assessment/run?tenant_id=t6", nil)
	runRR := httptest.NewRecorder()
	h.ServeHTTP(runRR, runReq)
	if runRR.Code != http.StatusOK || !strings.Contains(runRR.Body.String(), "\"assessment\"") {
		t.Fatalf("run assessment status=%d body=%s", runRR.Code, runRR.Body.String())
	}
}
