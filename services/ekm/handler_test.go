package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerEKMFlow(t *testing.T) {
	h, _, _, _ := newEKMHandler(t)

	registerAgentBody := []byte(`{
		"tenant_id":"tenant-h1",
		"agent_id":"agent-h1",
		"name":"sql-agent-h1",
		"db_engine":"mssql",
		"host":"sql-host-1"
	}`)
	registerReq := httptest.NewRequest(http.MethodPost, "/ekm/agents/register", bytes.NewReader(registerAgentBody))
	registerReq.Header.Set("X-Request-ID", "req-ekm-1")
	registerRR := httptest.NewRecorder()
	h.ServeHTTP(registerRR, registerReq)
	if registerRR.Code != http.StatusCreated {
		t.Fatalf("register agent status=%d body=%s", registerRR.Code, registerRR.Body.String())
	}
	var registerResp struct {
		Agent Agent `json:"agent"`
	}
	_ = json.Unmarshal(registerRR.Body.Bytes(), &registerResp)
	if registerResp.Agent.ID == "" {
		t.Fatalf("missing agent id: %s", registerRR.Body.String())
	}
	if registerResp.Agent.AssignedKeyID == "" {
		t.Fatalf("expected auto-provisioned key in agent response: %s", registerRR.Body.String())
	}

	heartbeatReq := httptest.NewRequest(http.MethodPost, "/ekm/agents/agent-h1/heartbeat", bytes.NewReader([]byte(`{
		"tenant_id":"tenant-h1",
		"status":"connected",
		"tde_state":"enabled",
		"active_key_id":"`+registerResp.Agent.AssignedKeyID+`",
		"active_key_version":"v1",
		"config_version_ack":1
	}`)))
	heartbeatRR := httptest.NewRecorder()
	h.ServeHTTP(heartbeatRR, heartbeatReq)
	if heartbeatRR.Code != http.StatusOK {
		t.Fatalf("heartbeat status=%d body=%s", heartbeatRR.Code, heartbeatRR.Body.String())
	}

	dbReq := httptest.NewRequest(http.MethodPost, "/ekm/databases", bytes.NewReader([]byte(`{
		"tenant_id":"tenant-h1",
		"database_id":"db-h1",
		"agent_id":"agent-h1",
		"name":"FinanceDB",
		"engine":"mssql",
		"tde_enabled":true,
		"database_name":"FinanceDB"
	}`)))
	dbRR := httptest.NewRecorder()
	h.ServeHTTP(dbRR, dbReq)
	if dbRR.Code != http.StatusCreated {
		t.Fatalf("register database status=%d body=%s", dbRR.Code, dbRR.Body.String())
	}
	var dbResp struct {
		Database DatabaseInstance `json:"database"`
	}
	_ = json.Unmarshal(dbRR.Body.Bytes(), &dbResp)
	if dbResp.Database.ID == "" {
		t.Fatalf("expected database id in response: %s", dbRR.Body.String())
	}

	keyReq := httptest.NewRequest(http.MethodPost, "/ekm/tde/keys", bytes.NewReader([]byte(`{
		"tenant_id":"tenant-h1",
		"name":"manual-key"
	}`)))
	keyRR := httptest.NewRecorder()
	h.ServeHTTP(keyRR, keyReq)
	if keyRR.Code != http.StatusCreated {
		t.Fatalf("create key status=%d body=%s", keyRR.Code, keyRR.Body.String())
	}
	var keyResp struct {
		Key TDEKeyRecord `json:"key"`
	}
	_ = json.Unmarshal(keyRR.Body.Bytes(), &keyResp)
	if keyResp.Key.ID == "" {
		t.Fatalf("missing key id: %s", keyRR.Body.String())
	}

	plainB64 := base64.StdEncoding.EncodeToString([]byte("0123456789ABCDEF0123456789ABCDEF"))
	wrapPayload := map[string]interface{}{
		"tenant_id":   "tenant-h1",
		"plaintext":   plainB64,
		"database_id": dbResp.Database.ID,
		"agent_id":    "agent-h1",
	}
	wrapRaw, _ := json.Marshal(wrapPayload)
	wrapReq := httptest.NewRequest(http.MethodPost, "/ekm/tde/keys/"+keyResp.Key.ID+"/wrap", bytes.NewReader(wrapRaw))
	wrapRR := httptest.NewRecorder()
	h.ServeHTTP(wrapRR, wrapReq)
	if wrapRR.Code != http.StatusOK {
		t.Fatalf("wrap status=%d body=%s", wrapRR.Code, wrapRR.Body.String())
	}
	var wrapResp struct {
		Result WrapDEKResponse `json:"result"`
	}
	_ = json.Unmarshal(wrapRR.Body.Bytes(), &wrapResp)
	if wrapResp.Result.CiphertextB64 == "" {
		t.Fatalf("expected wrapped ciphertext: %s", wrapRR.Body.String())
	}

	unwrapReq := httptest.NewRequest(http.MethodPost, "/ekm/tde/keys/"+keyResp.Key.ID+"/unwrap", bytes.NewReader([]byte(`{
		"tenant_id":"tenant-h1",
		"ciphertext":"`+wrapResp.Result.CiphertextB64+`",
		"iv":"`+wrapResp.Result.IVB64+`",
		"database_id":"`+dbResp.Database.ID+`",
		"agent_id":"agent-h1"
	}`)))
	unwrapRR := httptest.NewRecorder()
	h.ServeHTTP(unwrapRR, unwrapReq)
	if unwrapRR.Code != http.StatusOK {
		t.Fatalf("unwrap status=%d body=%s", unwrapRR.Code, unwrapRR.Body.String())
	}

	publicReq := httptest.NewRequest(http.MethodGet, "/ekm/tde/keys/"+keyResp.Key.ID+"/public?tenant_id=tenant-h1", nil)
	publicRR := httptest.NewRecorder()
	h.ServeHTTP(publicRR, publicReq)
	if publicRR.Code != http.StatusOK {
		t.Fatalf("public status=%d body=%s", publicRR.Code, publicRR.Body.String())
	}

	rotateReq := httptest.NewRequest(http.MethodPost, "/ekm/tde/keys/"+keyResp.Key.ID+"/rotate", bytes.NewReader([]byte(`{
		"tenant_id":"tenant-h1",
		"reason":"scheduled"
	}`)))
	rotateRR := httptest.NewRecorder()
	h.ServeHTTP(rotateRR, rotateReq)
	if rotateRR.Code != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", rotateRR.Code, rotateRR.Body.String())
	}

	listAgentsReq := httptest.NewRequest(http.MethodGet, "/ekm/agents?tenant_id=tenant-h1", nil)
	listAgentsRR := httptest.NewRecorder()
	h.ServeHTTP(listAgentsRR, listAgentsReq)
	if listAgentsRR.Code != http.StatusOK {
		t.Fatalf("list agents status=%d body=%s", listAgentsRR.Code, listAgentsRR.Body.String())
	}

	agentStatusReq := httptest.NewRequest(http.MethodGet, "/ekm/agents/agent-h1/status?tenant_id=tenant-h1", nil)
	agentStatusRR := httptest.NewRecorder()
	h.ServeHTTP(agentStatusRR, agentStatusReq)
	if agentStatusRR.Code != http.StatusOK {
		t.Fatalf("agent status status=%d body=%s", agentStatusRR.Code, agentStatusRR.Body.String())
	}

	agentHealthReq := httptest.NewRequest(http.MethodGet, "/ekm/agents/agent-h1/health?tenant_id=tenant-h1", nil)
	agentHealthRR := httptest.NewRecorder()
	h.ServeHTTP(agentHealthRR, agentHealthReq)
	if agentHealthRR.Code != http.StatusOK {
		t.Fatalf("agent health status=%d body=%s", agentHealthRR.Code, agentHealthRR.Body.String())
	}

	agentLogsReq := httptest.NewRequest(http.MethodGet, "/ekm/agents/agent-h1/logs?tenant_id=tenant-h1&limit=10", nil)
	agentLogsRR := httptest.NewRecorder()
	h.ServeHTTP(agentLogsRR, agentLogsReq)
	if agentLogsRR.Code != http.StatusOK {
		t.Fatalf("agent logs status=%d body=%s", agentLogsRR.Code, agentLogsRR.Body.String())
	}

	sdkOverviewReq := httptest.NewRequest(http.MethodGet, "/ekm/sdk/overview?tenant_id=tenant-h1", nil)
	sdkOverviewRR := httptest.NewRecorder()
	h.ServeHTTP(sdkOverviewRR, sdkOverviewReq)
	if sdkOverviewRR.Code != http.StatusOK {
		t.Fatalf("sdk overview status=%d body=%s", sdkOverviewRR.Code, sdkOverviewRR.Body.String())
	}

	sdkDownloadReq := httptest.NewRequest(http.MethodGet, "/ekm/sdk/download?tenant_id=tenant-h1&provider=pkcs11&os=linux", nil)
	sdkDownloadRR := httptest.NewRecorder()
	h.ServeHTTP(sdkDownloadRR, sdkDownloadReq)
	if sdkDownloadRR.Code != http.StatusOK {
		t.Fatalf("sdk download status=%d body=%s", sdkDownloadRR.Code, sdkDownloadRR.Body.String())
	}

	agentRotateReq := httptest.NewRequest(http.MethodPost, "/ekm/agents/agent-h1/rotate", bytes.NewReader([]byte(`{
		"tenant_id":"tenant-h1",
		"reason":"manual"
	}`)))
	agentRotateRR := httptest.NewRecorder()
	h.ServeHTTP(agentRotateRR, agentRotateReq)
	if agentRotateRR.Code != http.StatusOK {
		t.Fatalf("agent rotate status=%d body=%s", agentRotateRR.Code, agentRotateRR.Body.String())
	}

	deployPkgReq := httptest.NewRequest(http.MethodGet, "/ekm/agents/agent-h1/deploy?tenant_id=tenant-h1&os=linux", nil)
	deployPkgRR := httptest.NewRecorder()
	h.ServeHTTP(deployPkgRR, deployPkgReq)
	if deployPkgRR.Code != http.StatusOK {
		t.Fatalf("deploy package status=%d body=%s", deployPkgRR.Code, deployPkgRR.Body.String())
	}

	listDBReq := httptest.NewRequest(http.MethodGet, "/ekm/databases?tenant_id=tenant-h1", nil)
	listDBRR := httptest.NewRecorder()
	h.ServeHTTP(listDBRR, listDBReq)
	if listDBRR.Code != http.StatusOK {
		t.Fatalf("list db status=%d body=%s", listDBRR.Code, listDBRR.Body.String())
	}

	getDBReq := httptest.NewRequest(http.MethodGet, "/ekm/databases/"+dbResp.Database.ID+"?tenant_id=tenant-h1", nil)
	getDBRR := httptest.NewRecorder()
	h.ServeHTTP(getDBRR, getDBReq)
	if getDBRR.Code != http.StatusOK {
		t.Fatalf("get db status=%d body=%s", getDBRR.Code, getDBRR.Body.String())
	}

	deleteAgentReq := httptest.NewRequest(http.MethodDelete, "/ekm/agents/agent-h1", bytes.NewReader([]byte(`{
		"tenant_id":"tenant-h1",
		"reason":"cleanup"
	}`)))
	deleteAgentRR := httptest.NewRecorder()
	h.ServeHTTP(deleteAgentRR, deleteAgentReq)
	if deleteAgentRR.Code != http.StatusOK {
		t.Fatalf("delete agent status=%d body=%s", deleteAgentRR.Code, deleteAgentRR.Body.String())
	}

	listAgentsAfterDeleteReq := httptest.NewRequest(http.MethodGet, "/ekm/agents?tenant_id=tenant-h1", nil)
	listAgentsAfterDeleteRR := httptest.NewRecorder()
	h.ServeHTTP(listAgentsAfterDeleteRR, listAgentsAfterDeleteReq)
	if listAgentsAfterDeleteRR.Code != http.StatusOK {
		t.Fatalf("list agents after delete status=%d body=%s", listAgentsAfterDeleteRR.Code, listAgentsAfterDeleteRR.Body.String())
	}
	var listAfterDelete struct {
		Items []Agent `json:"items"`
	}
	_ = json.Unmarshal(listAgentsAfterDeleteRR.Body.Bytes(), &listAfterDelete)
	if len(listAfterDelete.Items) != 0 {
		t.Fatalf("expected no agents after delete, got=%d body=%s", len(listAfterDelete.Items), listAgentsAfterDeleteRR.Body.String())
	}
}

func TestHandlerEKMTenantRequired(t *testing.T) {
	h, _, _, _ := newEKMHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/ekm/agents", nil)
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

func TestHandlerBitLockerRegisterAndDeployWithDashboardJWT(t *testing.T) {
	h, _, _, _ := newEKMHandler(t)

	registerReq := httptest.NewRequest(http.MethodPost, "/ekm/bitlocker/clients/register", bytes.NewReader([]byte(`{
		"tenant_id":"tenant-h1",
		"name":"bitlocker-host-01",
		"host":"10.0.0.25",
		"os_version":"Windows 11",
		"mount_point":"C:"
	}`)))
	registerReq.Header.Set("Authorization", "Bearer dashboard-session-token")
	registerReq.Header.Set("X-Tenant-ID", "tenant-h1")
	registerRR := httptest.NewRecorder()
	h.ServeHTTP(registerRR, registerReq)
	if registerRR.Code != http.StatusCreated {
		t.Fatalf("register bitlocker client status=%d body=%s", registerRR.Code, registerRR.Body.String())
	}
	var registerResp struct {
		Client BitLockerClient `json:"client"`
	}
	_ = json.Unmarshal(registerRR.Body.Bytes(), &registerResp)
	if registerResp.Client.ID == "" {
		t.Fatalf("missing bitlocker client id: %s", registerRR.Body.String())
	}

	dupReq := httptest.NewRequest(http.MethodPost, "/ekm/bitlocker/clients/register", bytes.NewReader([]byte(`{
		"tenant_id":"tenant-h1",
		"name":"bitlocker-host-01",
		"host":"10.0.0.25",
		"os_version":"Windows 11",
		"mount_point":"C:"
	}`)))
	dupReq.Header.Set("Authorization", "Bearer dashboard-session-token")
	dupReq.Header.Set("X-Tenant-ID", "tenant-h1")
	dupRR := httptest.NewRecorder()
	h.ServeHTTP(dupRR, dupReq)
	if dupRR.Code != http.StatusConflict {
		t.Fatalf("duplicate bitlocker registration status=%d body=%s", dupRR.Code, dupRR.Body.String())
	}

	deployReq := httptest.NewRequest(
		http.MethodGet,
		"/ekm/bitlocker/clients/"+registerResp.Client.ID+"/deploy?tenant_id=tenant-h1&os=windows",
		nil,
	)
	deployReq.Header.Set("Authorization", "Bearer dashboard-session-token")
	deployReq.Header.Set("X-Tenant-ID", "tenant-h1")
	deployRR := httptest.NewRecorder()
	h.ServeHTTP(deployRR, deployReq)
	if deployRR.Code != http.StatusOK {
		t.Fatalf("bitlocker deploy package status=%d body=%s", deployRR.Code, deployRR.Body.String())
	}
}
