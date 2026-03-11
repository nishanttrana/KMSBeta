package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type RuntimeApplyStatus struct {
	Enabled       bool     `json:"enabled"`
	Executed      bool     `json:"executed"`
	StartOK       bool     `json:"start_ok"`
	HealthChecked bool     `json:"health_checked"`
	Healthy       bool     `json:"healthy"`
	Profiles      []string `json:"profiles,omitempty"`
	Services      []string `json:"services,omitempty"`
	StartLogs     []string `json:"start_logs,omitempty"`
	HealthLogs    []string `json:"health_logs,omitempty"`
	Message       string   `json:"message,omitempty"`
	ManualSteps   []string `json:"manual_steps,omitempty"`
}

type runtimeDeploymentSpec struct {
	Spec struct {
		HSMMode  string          `yaml:"hsm_mode"`
		Features map[string]bool `yaml:"features"`
	} `yaml:"spec"`
}

var featureOrder = []string{
	"secrets",
	"certs",
	"governance",
	"cloud_byok",
	"hyok_proxy",
	"kmip_server",
	"qkd_interface",
	"qrng_generator",
	"ekm_database",
	"payment_crypto",
	"compliance_dashboard",
	"sbom_cbom",
	"reporting_alerting",
	"posture_management",
	"ai_llm",
	"pqc_migration",
	"crypto_discovery",
	"mpc_engine",
	"data_protection",
	"clustering",
}

var featureToServices = map[string][]string{
	"secrets":              {"secrets"},
	"certs":                {"certs"},
	"governance":           {"governance"},
	"cloud_byok":           {"cloud"},
	"hyok_proxy":           {"hyok"},
	"kmip_server":          {"kmip"},
	"qkd_interface":        {"qkd"},
	"qrng_generator":       {"qrng"},
	"ekm_database":         {"ekm"},
	"payment_crypto":       {"payment"},
	"compliance_dashboard": {"compliance"},
	"sbom_cbom":            {"sbom"},
	"reporting_alerting":   {"reporting"},
	"posture_management":   {"posture"},
	"ai_llm":               {"ai"},
	"pqc_migration":        {"pqc"},
	"crypto_discovery":     {"discovery"},
	"mpc_engine":           {"mpc"},
	"data_protection":      {"dataprotect"},
	"clustering":           {"cluster-manager", "etcd"},
	"hsm_hardware":         {"hsm-connector"},
	"hsm_software":         {"software-vault"},
}

func applyRuntimeChanges(deployPath string) (RuntimeApplyStatus, error) {
	spec, err := loadRuntimeDeploymentSpec(deployPath)
	if err != nil {
		return RuntimeApplyStatus{}, err
	}

	status := RuntimeApplyStatus{
		Enabled:     envBool("FIRSTBOOT_RUNTIME_APPLY_ENABLED", false),
		Profiles:    composeProfiles(spec),
		Services:    enabledServices(spec),
		ManualSteps: manualRuntimeSteps(deployPath),
	}

	if !status.Enabled {
		status.Message = "feature configuration saved; runtime apply is disabled"
		return status, nil
	}

	startLogs, err := runRuntimeStart(deployPath)
	status.Executed = true
	status.StartLogs = startLogs
	if err != nil {
		status.Message = "service startup failed"
		return status, err
	}
	status.StartOK = true

	healthLogs, healthChecked, err := runRuntimeHealthCheck(deployPath)
	status.HealthChecked = healthChecked
	status.HealthLogs = healthLogs
	if err != nil {
		status.Message = "services started but health checks failed"
		return status, err
	}

	if healthChecked {
		status.Healthy = true
		status.Message = "selected services started and are healthy"
	} else {
		status.Message = "selected services started; health checks were skipped"
	}
	return status, nil
}

func loadRuntimeDeploymentSpec(path string) (runtimeDeploymentSpec, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return runtimeDeploymentSpec{}, fmt.Errorf("read deployment config: %w", err)
	}
	var out runtimeDeploymentSpec
	if err := yaml.Unmarshal(body, &out); err != nil {
		return runtimeDeploymentSpec{}, fmt.Errorf("parse deployment config: %w", err)
	}
	return out, nil
}

func composeProfiles(spec runtimeDeploymentSpec) []string {
	features := spec.Spec.Features
	seen := map[string]struct{}{}
	out := make([]string, 0, len(featureOrder)+2)
	for _, feature := range featureOrder {
		if features[feature] {
			if _, ok := seen[feature]; !ok {
				seen[feature] = struct{}{}
				out = append(out, feature)
			}
		}
	}

	switch strings.ToLower(strings.TrimSpace(spec.Spec.HSMMode)) {
	case "hardware":
		out = appendUnique(out, "hsm_hardware")
	case "auto":
		out = appendUnique(out, "hsm_hardware")
		out = appendUnique(out, "hsm_software")
	default:
		out = appendUnique(out, "hsm_software")
	}
	return out
}

func enabledServices(spec runtimeDeploymentSpec) []string {
	seen := map[string]struct{}{}
	out := []string{"auth", "keycore", "audit", "policy"}
	for _, svc := range out {
		seen[svc] = struct{}{}
	}
	for _, profile := range composeProfiles(spec) {
		for _, svc := range featureToServices[profile] {
			if _, ok := seen[svc]; ok {
				continue
			}
			seen[svc] = struct{}{}
			out = append(out, svc)
		}
	}
	return out
}

func runRuntimeStart(deployPath string) ([]string, error) {
	if cmdText := strings.TrimSpace(os.Getenv("FIRSTBOOT_STACK_APPLY_COMMAND")); cmdText != "" {
		return runShellCommand(cmdText, map[string]string{
			"FIRSTBOOT_DEPLOYMENT_TARGET": deployPath,
		})
	}

	scriptPath := strings.TrimSpace(os.Getenv("FIRSTBOOT_START_SCRIPT_PATH"))
	if scriptPath == "" {
		projectRoot := runtimeProjectRoot()
		scriptPath = filepath.Join(projectRoot, "infra", "scripts", "start-kms.sh")
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("default runtime apply is only supported on linux; configure FIRSTBOOT_STACK_APPLY_COMMAND")
	}
	if _, err := os.Stat(scriptPath); err != nil {
		return nil, fmt.Errorf("start script not found: %s", scriptPath)
	}
	return runCommand([]string{"/bin/bash", scriptPath, deployPath, "--skip-health"}, map[string]string{
		"START_KMS_REMOVE_ORPHANS": "false",
	})
}

func runRuntimeHealthCheck(deployPath string) ([]string, bool, error) {
	if cmdText := strings.TrimSpace(os.Getenv("FIRSTBOOT_HEALTHCHECK_COMMAND")); cmdText != "" {
		logs, err := runShellCommand(cmdText, map[string]string{
			"FIRSTBOOT_DEPLOYMENT_TARGET": deployPath,
		})
		return logs, true, err
	}

	scriptPath := strings.TrimSpace(os.Getenv("FIRSTBOOT_HEALTHCHECK_SCRIPT_PATH"))
	if scriptPath == "" {
		projectRoot := runtimeProjectRoot()
		scriptPath = filepath.Join(projectRoot, "infra", "scripts", "healthcheck-enabled-services.sh")
	}
	if runtime.GOOS != "linux" {
		return nil, false, nil
	}
	if _, err := os.Stat(scriptPath); err != nil {
		return nil, false, nil
	}
	logs, err := runCommand([]string{"/bin/bash", scriptPath, deployPath}, nil)
	return logs, true, err
}

func runShellCommand(command string, extraEnv map[string]string) ([]string, error) {
	if runtime.GOOS == "windows" {
		return runCommand([]string{"cmd", "/C", command}, extraEnv)
	}
	return runCommand([]string{"/bin/sh", "-lc", command}, extraEnv)
}

func runCommand(argv []string, extraEnv map[string]string) ([]string, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = os.Environ()
	for key, value := range extraEnv {
		cmd.Env = append(cmd.Env, key+"="+value)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	lines := splitCommandLogs(stdout.String(), stderr.String())
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		if err == nil {
			err = ctx.Err()
		}
	}
	if err != nil {
		return lines, fmt.Errorf("%w: %s", err, strings.TrimSpace(strings.Join(lines, " | ")))
	}
	return lines, nil
}

func splitCommandLogs(parts ...string) []string {
	out := make([]string, 0)
	for _, part := range parts {
		for _, line := range strings.Split(part, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			out = append(out, line)
		}
	}
	return out
}

func manualRuntimeSteps(deployPath string) []string {
	projectRoot := runtimeProjectRoot()
	return []string{
		fmt.Sprintf("Run %s %s", filepath.Join(projectRoot, "infra", "scripts", "start-kms.sh"), deployPath),
		fmt.Sprintf("Run %s %s", filepath.Join(projectRoot, "infra", "scripts", "healthcheck-enabled-services.sh"), deployPath),
	}
}

func runtimeProjectRoot() string {
	if value := strings.TrimSpace(os.Getenv("FIRSTBOOT_PROJECT_ROOT")); value != "" {
		return value
	}
	return "/opt/vecta"
}

func envBool(key string, fallback bool) bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}
