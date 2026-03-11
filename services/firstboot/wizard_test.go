package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHandleFeaturesApplyConfigOnly(t *testing.T) {
	deployPath := writeDeploymentFixture(t)
	t.Setenv("FIRSTBOOT_DEPLOYMENT_PATH", deployPath)
	t.Setenv("FIRSTBOOT_RUNTIME_APPLY_ENABLED", "false")

	server := NewServer(log.New(io.Discard, "", 0))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/firstboot/features/apply", strings.NewReader(`{
		"metadata": {},
		"spec": {
			"features": {
				"secrets": true,
				"ai_llm": true
			}
		}
	}`))
	req.Header.Set("Content-Type", "application/json")

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Status       string             `json:"status"`
		RuntimeApply RuntimeApplyStatus `json:"runtime_apply"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Status != "applied" {
		t.Fatalf("unexpected status: %s", payload.Status)
	}
	if payload.RuntimeApply.Executed {
		t.Fatal("runtime apply should not have executed when disabled")
	}

	body, err := os.ReadFile(deployPath)
	if err != nil {
		t.Fatalf("read deployment file: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "ai_llm: true") {
		t.Fatalf("deployment file missing updated feature toggle: %s", text)
	}
}

func TestHandleFeaturesApplyRunsRuntimeCommands(t *testing.T) {
	deployPath := writeDeploymentFixture(t)
	t.Setenv("FIRSTBOOT_DEPLOYMENT_PATH", deployPath)
	t.Setenv("FIRSTBOOT_RUNTIME_APPLY_ENABLED", "true")
	t.Setenv("FIRSTBOOT_STACK_APPLY_COMMAND", successCommand("stack-started"))
	t.Setenv("FIRSTBOOT_HEALTHCHECK_COMMAND", successCommand("healthy: auth"))

	server := NewServer(log.New(io.Discard, "", 0))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/firstboot/features/apply", strings.NewReader(`{
		"metadata": {},
		"spec": {
			"features": {
				"secrets": true,
				"certs": true
			}
		}
	}`))
	req.Header.Set("Content-Type", "application/json")

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		RuntimeApply RuntimeApplyStatus `json:"runtime_apply"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !payload.RuntimeApply.Executed || !payload.RuntimeApply.StartOK || !payload.RuntimeApply.Healthy {
		t.Fatalf("unexpected runtime apply result: %+v", payload.RuntimeApply)
	}
	if len(payload.RuntimeApply.StartLogs) == 0 || len(payload.RuntimeApply.HealthLogs) == 0 {
		t.Fatalf("expected runtime logs, got: %+v", payload.RuntimeApply)
	}
}

func TestHandleFeaturesApplyReturnsBadGatewayOnRuntimeFailure(t *testing.T) {
	deployPath := writeDeploymentFixture(t)
	t.Setenv("FIRSTBOOT_DEPLOYMENT_PATH", deployPath)
	t.Setenv("FIRSTBOOT_RUNTIME_APPLY_ENABLED", "true")
	t.Setenv("FIRSTBOOT_STACK_APPLY_COMMAND", failureCommand("stack-failed"))

	server := NewServer(log.New(io.Discard, "", 0))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/firstboot/features/apply", strings.NewReader(`{
		"metadata": {},
		"spec": {
			"features": {
				"secrets": true
			}
		}
	}`))
	req.Header.Set("Content-Type", "application/json")

	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		RuntimeStatus string             `json:"runtime_status"`
		RuntimeApply  RuntimeApplyStatus `json:"runtime_apply"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.RuntimeStatus != "applied_with_runtime_error" {
		t.Fatalf("unexpected runtime status: %s", payload.RuntimeStatus)
	}
	if !payload.RuntimeApply.Executed || payload.RuntimeApply.StartOK {
		t.Fatalf("unexpected runtime apply result: %+v", payload.RuntimeApply)
	}
}

func writeDeploymentFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "deployment.yaml")
	content := `apiVersion: kms.vecta.io/v1
kind: DeploymentConfig
metadata:
  appliance_id: kms-test
spec:
  hsm_mode: software
  features:
    secrets: false
    certs: false
    governance: false
    cloud_byok: false
    hyok_proxy: false
    kmip_server: false
    qkd_interface: false
    qrng_generator: false
    ekm_database: false
    payment_crypto: false
    compliance_dashboard: false
    sbom_cbom: false
    reporting_alerting: false
    posture_management: false
    ai_llm: false
    pqc_migration: false
    crypto_discovery: false
    mpc_engine: false
    data_protection: false
    clustering: false
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write deployment fixture: %v", err)
	}
	return path
}

func successCommand(message string) string {
	if runtime.GOOS == "windows" {
		return "echo " + message
	}
	return "printf '" + message + "\\n'"
}

func failureCommand(message string) string {
	if runtime.GOOS == "windows" {
		return "echo " + message + " && exit /b 1"
	}
	return "printf '" + message + "\\n'; exit 1"
}
