package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type Server struct {
	logger           *log.Logger
	mux              *http.ServeMux
	cleanupMu        sync.Mutex
	cleanupScheduled bool
	applyMu          sync.Mutex
	applyRunning     bool
	applyStatusMu    sync.RWMutex
	applyStatus      ApplyJobStatus
}

type ApplyJobStatus struct {
	Status     string         `json:"status"`
	Stage      string         `json:"stage,omitempty"`
	StartedAt  string         `json:"started_at,omitempty"`
	FinishedAt string         `json:"finished_at,omitempty"`
	StatusURL  string         `json:"status_url,omitempty"`
	Result     map[string]any `json:"result,omitempty"`
}

func NewServer(logger *log.Logger) *Server {
	s := &Server{
		logger:      logger,
		applyStatus: ApplyJobStatus{Status: "idle", StatusURL: "/api/v1/firstboot/apply/status"},
	}
	s.mux = s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /wizard", s.handleWizardPage)
	mux.HandleFunc("GET /api/v1/firstboot/apply/status", s.handleApplyStatus)
	mux.HandleFunc("POST /api/v1/firstboot/preview", s.handlePreview)
	mux.HandleFunc("POST /api/v1/firstboot/apply", s.handleApply)
	mux.HandleFunc("POST /api/v1/firstboot/features/apply", s.handleFeaturesApply)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"service":   "firstboot",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleWizardPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(wizardHTML))
}

func (s *Server) handleApplyStatus(w http.ResponseWriter, r *http.Request) {
	status := s.snapshotApplyStatus()
	readyStatus := s.withRuntimeReadiness(status, requestHost(r))
	if readyStatus.Status == "succeeded" && !resultLoginReady(readyStatus.Result) {
		readyStatus.Stage = "verifying"
	}
	writeJSON(w, http.StatusOK, readyStatus)
}

func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request) {
	var req WizardRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	gen, err := generateConfigs(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":    gen.GeneratedAt.Format(time.RFC3339),
		"warnings":        gen.Warnings,
		"paths":           gen.Paths,
		"recovery_shares": gen.RecoveryShares,
		"deployment_yaml": string(gen.DeploymentYAML),
		"network_yaml":    string(gen.NetworkYAML),
		"fips_yaml":       string(gen.FIPSYAML),
		"fde_yaml":        string(gen.FDEYAML),
		"auth_yaml":       string(gen.AuthYAML),
	})
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	release, ok := s.beginApply(w)
	if !ok {
		return
	}

	var req WizardRequest
	if err := decodeJSON(r, &req); err != nil {
		release()
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	gen, err := generateConfigs(req)
	if err != nil {
		release()
		writeErr(w, http.StatusBadRequest, "validation_failed", err.Error())
		return
	}
	if err := writeConfigFiles(gen); err != nil {
		release()
		writeErr(w, http.StatusInternalServerError, "write_failed", err.Error())
		return
	}
	s.logger.Printf("Firstboot apply started for appliance %s", req.Metadata.ApplianceID)
	host := requestHost(r)
	baseResult := map[string]any{
		"status":          "applied",
		"generated_at":    gen.GeneratedAt.Format(time.RFC3339),
		"warnings":        gen.Warnings,
		"paths":           gen.Paths,
		"recovery_shares": gen.RecoveryShares,
		"next_steps": []string{
			"Generated deployment files were written to the configured output paths.",
			"Selected KMS services are being started from the generated deployment profile.",
			"Firstboot will remove itself after the KMS handoff completes successfully.",
			"Keep this page open to follow deployment progress until the dashboard redirect is ready.",
		},
	}
	s.setApplyStatus(ApplyJobStatus{
		Status:    "running",
		Stage:     "deploying",
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		StatusURL: "/api/v1/firstboot/apply/status",
		Result:    cloneAnyMap(baseResult),
	})

	go func(gen GeneratedConfigs, host string, release func()) {
		defer release()

		runtimeApply, runtimeErr := applyRuntimeChanges(gen.Paths["deployment"])
		statusText := "applied"
		if runtimeErr != nil {
			statusText = "applied_with_runtime_error"
		}

		redirectURL := ""
		edgeURL := ""
		warnings := append([]string(nil), gen.Warnings...)
		if runtimeErr == nil && runtimeApply.StartOK {
			redirectURL = fmt.Sprintf("http://%s:5173/", host)
			edgeURL = fmt.Sprintf("https://%s/", host)
			if err := s.scheduleCleanup(&runtimeApply); err != nil {
				runtimeApply.Message = strings.TrimSpace(runtimeApply.Message + "; firstboot cleanup must be done manually")
				runtimeApply.CleanupLogs = append(runtimeApply.CleanupLogs, err.Error())
				warnings = append(warnings, "firstboot cleanup could not be scheduled automatically")
			}
		}

		result := map[string]any{
			"status":                 "applied",
			"runtime_status":         statusText,
			"generated_at":           gen.GeneratedAt.Format(time.RFC3339),
			"warnings":               warnings,
			"paths":                  gen.Paths,
			"recovery_shares":        gen.RecoveryShares,
			"runtime_apply":          runtimeApply,
			"redirect_url":           redirectURL,
			"edge_url":               edgeURL,
			"redirect_delay_seconds": envInt("FIRSTBOOT_REDIRECT_DELAY_SECONDS", 6),
			"next_steps": []string{
				"Generated deployment files were written to the configured output paths.",
				"Selected KMS services were started from the generated deployment profile.",
				"Firstboot will remove itself after the KMS handoff completes successfully.",
				"Open the dashboard on the redirect URL if the browser does not switch automatically.",
			},
		}
		finishedAt := time.Now().UTC().Format(time.RFC3339)
		if runtimeErr != nil {
			s.setApplyStatus(ApplyJobStatus{
				Status:     "failed",
				Stage:      "complete",
				StartedAt:  s.snapshotApplyStatus().StartedAt,
				FinishedAt: finishedAt,
				StatusURL:  "/api/v1/firstboot/apply/status",
				Result:     result,
			})
			s.logger.Printf("Firstboot apply failed for appliance %s: %v", gen.Paths["deployment"], runtimeErr)
			return
		}

		s.setApplyStatus(ApplyJobStatus{
			Status:     "succeeded",
			Stage:      "complete",
			StartedAt:  s.snapshotApplyStatus().StartedAt,
			FinishedAt: finishedAt,
			StatusURL:  "/api/v1/firstboot/apply/status",
			Result:     result,
		})
		s.logger.Printf("Firstboot apply completed for deployment %s", gen.Paths["deployment"])
	}(gen, host, release)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":                 "accepted",
		"job_status":             "running",
		"generated_at":           gen.GeneratedAt.Format(time.RFC3339),
		"warnings":               gen.Warnings,
		"paths":                  gen.Paths,
		"recovery_shares":        gen.RecoveryShares,
		"status_url":             "/api/v1/firstboot/apply/status",
		"redirect_delay_seconds": envInt("FIRSTBOOT_REDIRECT_DELAY_SECONDS", 6),
		"next_steps": []string{
			"Deployment started in the background.",
			"Keep this page open to follow progress.",
			"Firstboot will remove itself after the KMS handoff completes successfully.",
		},
	})
}

// FeatureApplyRequest is a lightweight request for the onboarding wizard
// that only updates the features section of deployment.yaml.
type FeatureApplyRequest struct {
	Metadata map[string]any   `json:"metadata"`
	Spec     FeatureApplySpec `json:"spec"`
}

type FeatureApplySpec struct {
	Features map[string]bool `json:"features"`
}

func (s *Server) handleFeaturesApply(w http.ResponseWriter, r *http.Request) {
	release, ok := s.beginApply(w)
	if !ok {
		return
	}
	defer release()

	var req FeatureApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	defer r.Body.Close()

	deployPath := envOr("FIRSTBOOT_DEPLOYMENT_PATH", defaultDeploymentPath)

	// Read existing deployment.yaml
	existing, err := os.ReadFile(deployPath)
	if err != nil && !os.IsNotExist(err) {
		writeErr(w, http.StatusInternalServerError, "read_failed", err.Error())
		return
	}

	var doc map[string]any
	if len(existing) > 0 {
		if err := yaml.Unmarshal(existing, &doc); err != nil {
			writeErr(w, http.StatusInternalServerError, "parse_failed", err.Error())
			return
		}
	}
	if doc == nil {
		doc = map[string]any{
			"apiVersion": "kms.vecta.com/v1",
			"kind":       "DeploymentConfig",
		}
	}

	spec, _ := doc["spec"].(map[string]any)
	if spec == nil {
		spec = map[string]any{}
	}
	spec["features"] = req.Spec.Features
	doc["spec"] = spec

	out, err := yaml.Marshal(doc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "marshal_failed", err.Error())
		return
	}

	if err := os.MkdirAll(filepath.Dir(deployPath), 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "mkdir_failed", err.Error())
		return
	}
	if err := os.WriteFile(deployPath, out, 0o644); err != nil {
		writeErr(w, http.StatusInternalServerError, "write_failed", err.Error())
		return
	}

	s.logger.Printf("Features updated via onboarding wizard: %v", req.Spec.Features)

	runtimeApply, runtimeErr := applyRuntimeChanges(deployPath)
	statusCode := http.StatusOK
	statusText := "applied"
	if runtimeErr != nil {
		statusCode = http.StatusBadGateway
		statusText = "applied_with_runtime_error"
	}
	redirectURL := ""
	edgeURL := ""
	if runtimeErr == nil && runtimeApply.StartOK {
		redirectURL = dashboardURLForRequest(r)
		edgeURL = edgeURLForRequest(r)
		if err := s.scheduleCleanup(&runtimeApply); err != nil {
			runtimeApply.Message = strings.TrimSpace(runtimeApply.Message + "; firstboot cleanup must be done manually")
			runtimeApply.CleanupLogs = append(runtimeApply.CleanupLogs, err.Error())
		}
	}

	writeJSON(w, statusCode, map[string]any{
		"status":                 "applied",
		"runtime_status":         statusText,
		"applied_at":             time.Now().UTC().Format(time.RFC3339),
		"features":               req.Spec.Features,
		"runtime_apply":          runtimeApply,
		"redirect_url":           redirectURL,
		"edge_url":               edgeURL,
		"redirect_delay_seconds": envInt("FIRSTBOOT_REDIRECT_DELAY_SECONDS", 6),
	})
}

func (s *Server) scheduleCleanup(status *RuntimeApplyStatus) error {
	if status == nil || !status.Executed || !status.StartOK || (status.HealthChecked && !status.Healthy) {
		return nil
	}

	s.cleanupMu.Lock()
	if s.cleanupScheduled {
		s.cleanupMu.Unlock()
		status.CleanupScheduled = true
		return nil
	}
	s.cleanupMu.Unlock()

	if err := scheduleFirstbootCleanup(status); err != nil {
		return err
	}

	s.cleanupMu.Lock()
	s.cleanupScheduled = true
	s.cleanupMu.Unlock()
	return nil
}

func (s *Server) beginApply(w http.ResponseWriter) (func(), bool) {
	s.applyMu.Lock()
	if s.applyRunning {
		s.applyMu.Unlock()
		writeErr(w, http.StatusConflict, "apply_in_progress", "a deployment is already in progress; wait for it to finish before applying again")
		return nil, false
	}
	s.applyRunning = true
	s.applyMu.Unlock()

	released := false
	return func() {
		if released {
			return
		}
		s.applyMu.Lock()
		s.applyRunning = false
		s.applyMu.Unlock()
		released = true
	}, true
}

func dashboardURLForRequest(r *http.Request) string {
	host := requestHost(r)
	return fmt.Sprintf("http://%s:5173/", host)
}

func edgeURLForRequest(r *http.Request) string {
	host := requestHost(r)
	return fmt.Sprintf("https://%s/", host)
}

func requestHost(r *http.Request) string {
	raw := strings.TrimSpace(r.Host)
	if raw == "" {
		return "127.0.0.1"
	}
	host, _, err := net.SplitHostPort(raw)
	if err == nil && host != "" {
		return host
	}
	return raw
}

func (s *Server) setApplyStatus(status ApplyJobStatus) {
	if status.Status == "" {
		status.Status = "idle"
	}
	if status.StatusURL == "" {
		status.StatusURL = "/api/v1/firstboot/apply/status"
	}
	if status.Result != nil {
		status.Result = cloneAnyMap(status.Result)
	}

	s.applyStatusMu.Lock()
	s.applyStatus = status
	s.applyStatusMu.Unlock()
}

func (s *Server) snapshotApplyStatus() ApplyJobStatus {
	s.applyStatusMu.RLock()
	status := s.applyStatus
	s.applyStatusMu.RUnlock()
	if status.Result != nil {
		status.Result = cloneAnyMap(status.Result)
	}
	if status.Status == "" {
		status.Status = "idle"
	}
	if status.StatusURL == "" {
		status.StatusURL = "/api/v1/firstboot/apply/status"
	}
	return status
}

func cloneAnyMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func (s *Server) withRuntimeReadiness(status ApplyJobStatus, host string) ApplyJobStatus {
	readiness, ok := s.runtimeReadiness(host)
	if !ok {
		return status
	}

	if status.Result == nil {
		status.Result = map[string]any{}
	}
	for key, value := range readiness {
		status.Result[key] = value
	}
	status.Status = "ready"
	status.Stage = "login"
	if status.FinishedAt == "" {
		status.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	}

	cleanupStatus := &RuntimeApplyStatus{
		Executed:      true,
		StartOK:       true,
		HealthChecked: true,
		Healthy:       true,
	}
	if err := s.scheduleCleanup(cleanupStatus); err == nil {
		status.Result["cleanup_scheduled"] = cleanupStatus.CleanupScheduled
		if cleanupStatus.CleanupScheduled && len(cleanupStatus.CleanupLogs) > 0 {
			status.Result["cleanup_logs"] = cleanupStatus.CleanupLogs
		}
	}
	return status
}

func (s *Server) runtimeReadiness(host string) (map[string]any, bool) {
	composeFile := filepath.Join(runtimeProjectRoot(), "docker-compose.yml")
	if _, err := os.Stat(composeFile); err != nil {
		return nil, false
	}

	envMap, err := currentRuntimeComposeEnv()
	if err != nil {
		return nil, false
	}

	services := []string{
		"postgres",
		"nats",
		"consul",
		"valkey",
		"software-vault",
		"auth",
		"keycore",
		"audit",
		"policy",
		"certs",
		"dashboard",
		"envoy",
	}
	healthLogs, pending, err := inspectRuntimeServices(composeFile, envMap, services)
	if err != nil || len(pending) > 0 {
		return nil, false
	}
	if !probeHTTP("http://dashboard:5173/") {
		return nil, false
	}

	loginURL := fmt.Sprintf("http://%s:5173/", host)
	return map[string]any{
		"login_ready":     true,
		"login_url":       loginURL,
		"dashboard_url":   loginURL,
		"redirect_url":    loginURL,
		"edge_url":        fmt.Sprintf("https://%s/", host),
		"ready_message":   "KMS is ready to sign in.",
		"readiness_checks": healthLogs,
		"next_steps": []string{
			"KMS is ready to sign in.",
			"Open the dashboard URL to log in with the admin credentials from firstboot.",
			"Firstboot will remove itself after the redirect grace period.",
		},
	}, true
}

func probeHTTP(target string) bool {
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func resultLoginReady(result map[string]any) bool {
	if result == nil {
		return false
	}
	value, ok := result["login_ready"]
	if !ok {
		return false
	}
	ready, _ := value.(bool)
	return ready
}

func decodeJSON(r *http.Request, out any) error {
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}
