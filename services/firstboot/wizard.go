package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type Server struct {
	logger *log.Logger
	mux    *http.ServeMux
}

func NewServer(logger *log.Logger) *Server {
	s := &Server{logger: logger}
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
	if err := writeConfigFiles(gen); err != nil {
		writeErr(w, http.StatusInternalServerError, "write_failed", err.Error())
		return
	}
	runtimeApply, runtimeErr := applyRuntimeChanges(gen.Paths["deployment"])
	statusCode := http.StatusOK
	statusText := "applied"
	if runtimeErr != nil {
		statusCode = http.StatusBadGateway
		statusText = "applied_with_runtime_error"
	}
	writeJSON(w, statusCode, map[string]any{
		"status":          "applied",
		"runtime_status":  statusText,
		"generated_at":    gen.GeneratedAt.Format(time.RFC3339),
		"warnings":        gen.Warnings,
		"paths":           gen.Paths,
		"recovery_shares": gen.RecoveryShares,
		"runtime_apply":   runtimeApply,
		"next_steps": []string{
			"On appliance builds, vecta-deployment.path will auto-start vecta-stack.service.",
			"Local/dev mode: run /opt/vecta/infra/scripts/start-kms.sh /etc/vecta/deployment.yaml",
			"Verify health: /opt/vecta/infra/scripts/healthcheck-enabled-services.sh /etc/vecta/deployment.yaml",
			"Switch to main UI: https://<appliance-ip>/",
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

	writeJSON(w, statusCode, map[string]any{
		"status":         "applied",
		"runtime_status": statusText,
		"applied_at":     time.Now().UTC().Format(time.RFC3339),
		"features":       req.Spec.Features,
		"runtime_apply":  runtimeApply,
	})
}

func decodeJSON(r *http.Request, out any) error {
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
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
