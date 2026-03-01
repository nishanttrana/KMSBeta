package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandlerAlertsIncidentsAndStats(t *testing.T) {
	h, _, audit, _, _ := newReportingHandler(t)
	tenantID := "tenant-h1"
	audit.events[tenantID] = []map[string]interface{}{
		{"id": "e1", "action": "key.created", "service": "keycore", "target_id": "k1", "timestamp": time.Now().UTC().Format(time.RFC3339)},
	}

	alertsReq := httptest.NewRequest(http.MethodGet, "/alerts?tenant_id="+tenantID, nil)
	alertsRR := httptest.NewRecorder()
	h.ServeHTTP(alertsRR, alertsReq)
	if alertsRR.Code != http.StatusOK {
		t.Fatalf("alerts status=%d body=%s", alertsRR.Code, alertsRR.Body.String())
	}

	var alertsPayload map[string]interface{}
	if err := json.Unmarshal(alertsRR.Body.Bytes(), &alertsPayload); err != nil {
		t.Fatalf("decode alerts payload: %v", err)
	}
	rawItems, _ := alertsPayload["items"].([]interface{})
	if len(rawItems) == 0 {
		t.Fatalf("expected at least one alert")
	}
	firstAlert := rawItems[0].(map[string]interface{})
	alertID, _ := firstAlert["id"].(string)
	if alertID == "" {
		t.Fatalf("expected alert id in payload")
	}

	unreadReq := httptest.NewRequest(http.MethodGet, "/alerts/unread?tenant_id="+tenantID, nil)
	unreadRR := httptest.NewRecorder()
	h.ServeHTTP(unreadRR, unreadReq)
	if unreadRR.Code != http.StatusOK {
		t.Fatalf("unread status=%d body=%s", unreadRR.Code, unreadRR.Body.String())
	}

	ackReq := httptest.NewRequest(http.MethodPut, "/alerts/"+alertID+"/acknowledge?tenant_id="+tenantID, strings.NewReader(`{"actor":"analyst"}`))
	ackReq.Header.Set("Content-Type", "application/json")
	ackRR := httptest.NewRecorder()
	h.ServeHTTP(ackRR, ackReq)
	if ackRR.Code != http.StatusOK {
		t.Fatalf("ack status=%d body=%s", ackRR.Code, ackRR.Body.String())
	}

	statsReq := httptest.NewRequest(http.MethodGet, "/alerts/stats?tenant_id="+tenantID, nil)
	statsRR := httptest.NewRecorder()
	h.ServeHTTP(statsRR, statsReq)
	if statsRR.Code != http.StatusOK {
		t.Fatalf("stats status=%d body=%s", statsRR.Code, statsRR.Body.String())
	}

	mttrReq := httptest.NewRequest(http.MethodGet, "/alerts/stats/mttr?tenant_id="+tenantID, nil)
	mttrRR := httptest.NewRecorder()
	h.ServeHTTP(mttrRR, mttrReq)
	if mttrRR.Code != http.StatusOK {
		t.Fatalf("mttr status=%d body=%s", mttrRR.Code, mttrRR.Body.String())
	}

	topReq := httptest.NewRequest(http.MethodGet, "/alerts/stats/top-sources?tenant_id="+tenantID, nil)
	topRR := httptest.NewRecorder()
	h.ServeHTTP(topRR, topReq)
	if topRR.Code != http.StatusOK {
		t.Fatalf("top sources status=%d body=%s", topRR.Code, topRR.Body.String())
	}
}

func TestHandlerRulesChannelsAndReports(t *testing.T) {
	h, _, _, compliance, _ := newReportingHandler(t)
	tenantID := "tenant-h2"
	compliance.posture[tenantID] = map[string]interface{}{"overall_score": "77"}

	ruleReq := httptest.NewRequest(http.MethodPost, "/alerts/rules?tenant_id="+tenantID, strings.NewReader(`{
		"name":"brute_force",
		"condition":"count(auth.login_failed)>=3",
		"severity":"critical",
		"event_pattern":"auth.login_failed",
		"threshold":3,
		"window_seconds":300,
		"channels":["screen","email"]
	}`))
	ruleReq.Header.Set("Content-Type", "application/json")
	ruleRR := httptest.NewRecorder()
	h.ServeHTTP(ruleRR, ruleReq)
	if ruleRR.Code != http.StatusCreated {
		t.Fatalf("create rule status=%d body=%s", ruleRR.Code, ruleRR.Body.String())
	}

	listRulesReq := httptest.NewRequest(http.MethodGet, "/alerts/rules?tenant_id="+tenantID, nil)
	listRulesRR := httptest.NewRecorder()
	h.ServeHTTP(listRulesRR, listRulesReq)
	if listRulesRR.Code != http.StatusOK {
		t.Fatalf("list rules status=%d body=%s", listRulesRR.Code, listRulesRR.Body.String())
	}

	sevUpdateReq := httptest.NewRequest(http.MethodPut, "/alerts/severity-config?tenant_id="+tenantID, strings.NewReader(`{"key.created":"warning"}`))
	sevUpdateReq.Header.Set("Content-Type", "application/json")
	sevUpdateRR := httptest.NewRecorder()
	h.ServeHTTP(sevUpdateRR, sevUpdateReq)
	if sevUpdateRR.Code != http.StatusOK {
		t.Fatalf("update severity config status=%d body=%s", sevUpdateRR.Code, sevUpdateRR.Body.String())
	}

	chReq := httptest.NewRequest(http.MethodGet, "/alerts/channels?tenant_id="+tenantID, nil)
	chRR := httptest.NewRecorder()
	h.ServeHTTP(chRR, chReq)
	if chRR.Code != http.StatusOK {
		t.Fatalf("channels status=%d body=%s", chRR.Code, chRR.Body.String())
	}

	templatesReq := httptest.NewRequest(http.MethodGet, "/reports/templates", nil)
	templatesRR := httptest.NewRecorder()
	h.ServeHTTP(templatesRR, templatesReq)
	if templatesRR.Code != http.StatusOK {
		t.Fatalf("templates status=%d body=%s", templatesRR.Code, templatesRR.Body.String())
	}

	genReq := httptest.NewRequest(http.MethodPost, "/reports/generate", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"template_id":"alert_summary",
		"format":"json",
		"requested_by":"tester"
	}`))
	genReq.Header.Set("Content-Type", "application/json")
	genRR := httptest.NewRecorder()
	h.ServeHTTP(genRR, genReq)
	if genRR.Code != http.StatusAccepted {
		t.Fatalf("generate report status=%d body=%s", genRR.Code, genRR.Body.String())
	}
	var genPayload map[string]interface{}
	if err := json.Unmarshal(genRR.Body.Bytes(), &genPayload); err != nil {
		t.Fatalf("decode report generate payload: %v", err)
	}
	jobMap, _ := genPayload["job"].(map[string]interface{})
	jobID, _ := jobMap["id"].(string)
	if jobID == "" {
		t.Fatalf("expected report job id")
	}

	var jobStatus string
	for i := 0; i < 50; i++ {
		jobReq := httptest.NewRequest(http.MethodGet, "/reports/jobs/"+jobID+"?tenant_id="+tenantID, nil)
		jobRR := httptest.NewRecorder()
		h.ServeHTTP(jobRR, jobReq)
		if jobRR.Code != http.StatusOK {
			t.Fatalf("report job status code=%d body=%s", jobRR.Code, jobRR.Body.String())
		}
		var payload map[string]interface{}
		_ = json.Unmarshal(jobRR.Body.Bytes(), &payload)
		j, _ := payload["job"].(map[string]interface{})
		jobStatus, _ = j["status"].(string)
		if jobStatus == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if jobStatus != "completed" {
		t.Fatalf("expected completed report job got %s", jobStatus)
	}

	downloadReq := httptest.NewRequest(http.MethodGet, "/reports/jobs/"+jobID+"/download?tenant_id="+tenantID, nil)
	downloadRR := httptest.NewRecorder()
	h.ServeHTTP(downloadRR, downloadReq)
	if downloadRR.Code != http.StatusOK {
		t.Fatalf("download report status=%d body=%s", downloadRR.Code, downloadRR.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/reports/jobs/"+jobID+"?tenant_id="+tenantID+"&actor=tester", nil)
	deleteRR := httptest.NewRecorder()
	h.ServeHTTP(deleteRR, deleteReq)
	if deleteRR.Code != http.StatusOK {
		t.Fatalf("delete report status=%d body=%s", deleteRR.Code, deleteRR.Body.String())
	}

	jobAfterDeleteReq := httptest.NewRequest(http.MethodGet, "/reports/jobs/"+jobID+"?tenant_id="+tenantID, nil)
	jobAfterDeleteRR := httptest.NewRecorder()
	h.ServeHTTP(jobAfterDeleteRR, jobAfterDeleteReq)
	if jobAfterDeleteRR.Code != http.StatusNotFound {
		t.Fatalf("expected report job not found after delete status=%d body=%s", jobAfterDeleteRR.Code, jobAfterDeleteRR.Body.String())
	}

	schedReq := httptest.NewRequest(http.MethodPost, "/reports/scheduled", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"name":"daily",
		"template_id":"alert_summary",
		"format":"pdf",
		"schedule":"daily",
		"recipients":["soc@example.com"]
	}`))
	schedReq.Header.Set("Content-Type", "application/json")
	schedRR := httptest.NewRecorder()
	h.ServeHTTP(schedRR, schedReq)
	if schedRR.Code != http.StatusCreated {
		t.Fatalf("schedule report status=%d body=%s", schedRR.Code, schedRR.Body.String())
	}

	listSchedReq := httptest.NewRequest(http.MethodGet, "/reports/scheduled?tenant_id="+tenantID, nil)
	listSchedRR := httptest.NewRecorder()
	h.ServeHTTP(listSchedRR, listSchedReq)
	if listSchedRR.Code != http.StatusOK {
		t.Fatalf("list schedules status=%d body=%s", listSchedRR.Code, listSchedRR.Body.String())
	}
}

func TestHandlerTelemetryEndpoints(t *testing.T) {
	h, _, _, _, _ := newReportingHandler(t)
	tenantID := "tenant-telemetry-handler"
	createReq := httptest.NewRequest(http.MethodPost, "/telemetry/errors", strings.NewReader(`{
		"tenant_id":"`+tenantID+`",
		"source":"frontend",
		"service":"dashboard",
		"component":"window.onerror",
		"level":"error",
		"message":"globalFipsEnabled is not defined",
		"stack_trace":"Error: globalFipsEnabled is not defined",
		"context":{"tab":"dashboard"},
		"fingerprint":"fp_123",
		"request_id":"req_abc",
		"release_tag":"dashboard",
		"build_version":"v1"
	}`))
	createReq.Header.Set("Content-Type", "application/json")
	createRR := httptest.NewRecorder()
	h.ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusAccepted {
		t.Fatalf("create telemetry status=%d body=%s", createRR.Code, createRR.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/telemetry/errors?tenant_id="+tenantID+"&service=dashboard", nil)
	listRR := httptest.NewRecorder()
	h.ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list telemetry status=%d body=%s", listRR.Code, listRR.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(listRR.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode telemetry list payload: %v", err)
	}
	items, _ := payload["items"].([]interface{})
	if len(items) != 1 {
		t.Fatalf("expected one telemetry item got %d", len(items))
	}
}
