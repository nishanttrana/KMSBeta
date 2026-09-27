package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"vecta-kms/pkg/agentauth"
)

// jobResultRequest mirrors services/ekm BitLockerJobResultRequest: the agent
// must send exactly what the service decodes.
type jobResultRequest struct {
	TenantID         string                 `json:"tenant_id"`
	Status           string                 `json:"status"`
	ProtectionStatus string                 `json:"protection_status"`
	Result           map[string]interface{} `json:"result"`
	ErrorMessage     string                 `json:"error_message"`
	RecoveryKey      string                 `json:"recovery_key"`
	ProtectorID      string                 `json:"protector_id"`
	VolumeMountPoint string                 `json:"volume_mount_point"`
}

// The agent polls with POST, reads the job from {"job": ...} including its
// params_json, and reports a result the service accepts.
func TestBitLockerJobRoundTripMatchesServiceContract(t *testing.T) {
	var got *jobResultRequest
	mux := http.NewServeMux()
	mux.HandleFunc("/ekm/bitlocker/clients/a1/jobs/next", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("poll used %s; the service route is POST", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"job": map[string]string{"id": "j1", "operation": "tpm_status", "params_json": `{"mount_point":"D:"}`}})
	})
	mux.HandleFunc("/ekm/bitlocker/clients/a1/jobs/j1/result", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var req jobResultRequest
		if err := dec.Decode(&req); err != nil {
			t.Errorf("result body is not the service's shape: %v (%s)", err, raw)
		}
		got = &req
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	auth, err := agentauth.New(agentauth.Config{AuthToken: "test-token", TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	r := &AgentRunner{
		cfg: AgentConfig{TenantID: "t1", AgentID: "a1", APIBaseURL: srv.URL,
			JobsNextPath: "/ekm/bitlocker/clients/{agent_id}/jobs/next", JobResultPath: "/ekm/bitlocker/clients/{agent_id}/jobs/{job_id}/result"},
		httpClient: srv.Client(),
		logger:     log.New(io.Discard, "", 0),
		auth:       auth,
	}
	r.PollAndExecuteJob(context.Background())
	if got == nil {
		t.Fatal("no result was reported")
	}
	if got.Status != "succeeded" && got.Status != "failed" {
		t.Fatalf("status %q is not succeeded|failed", got.Status)
	}
	if got.TenantID != "t1" || got.VolumeMountPoint != "D:" {
		t.Fatalf("tenant or params_json mount point lost: %+v", got)
	}
	if runtime.GOOS != "windows" && (got.Status != "failed" || got.ErrorMessage == "") {
		t.Fatalf("an operation that cannot run here must report failed with a reason: %+v", got)
	}
}
