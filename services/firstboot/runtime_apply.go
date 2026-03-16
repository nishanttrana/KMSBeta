package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type RuntimeApplyStatus struct {
	Enabled          bool     `json:"enabled"`
	Executed         bool     `json:"executed"`
	StartOK          bool     `json:"start_ok"`
	HealthChecked    bool     `json:"health_checked"`
	Healthy          bool     `json:"healthy"`
	CleanupScheduled bool     `json:"cleanup_scheduled"`
	Profiles         []string `json:"profiles,omitempty"`
	Services         []string `json:"services,omitempty"`
	StartLogs        []string `json:"start_logs,omitempty"`
	HealthLogs       []string `json:"health_logs,omitempty"`
	CleanupLogs      []string `json:"cleanup_logs,omitempty"`
	Message          string   `json:"message,omitempty"`
	ManualSteps      []string `json:"manual_steps,omitempty"`
}

type runtimeDeploymentSpec struct {
	Spec struct {
		HSMMode      string          `yaml:"hsm_mode"`
		Features     map[string]bool `yaml:"features"`
		CertSecurity struct {
			CertStorageMode    string `yaml:"cert_storage_mode"`
			RootKeyMode        string `yaml:"root_key_mode"`
			SealedKeyPath      string `yaml:"sealed_key_path"`
			PassphraseFilePath string `yaml:"passphrase_file_path"`
			UseTPMSeal         bool   `yaml:"use_tpm_seal"`
		} `yaml:"cert_security"`
	} `yaml:"spec"`
}

type commandOptions struct {
	Dir     string
	Timeout time.Duration
}

type dockerInspectResult struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

type imageAlias struct {
	Alias  string
	Source string
}

var (
	featureOrder = []string{
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
	runtimeBaseProfiles = []string{
		"certs",
		"event_streaming",
		"service_discovery",
		"distributed_cache",
	}
	featureToServices = map[string][]string{
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
		"event_streaming":      {"nats"},
		"service_discovery":    {"consul"},
		"distributed_cache":    {"valkey"},
	}
	baseRuntimeServices = []string{
		"postgres",
		"etcd",
		"auth",
		"keycore",
		"audit",
		"policy",
		"certs",
		"dashboard",
		"envoy",
	}
	healthcheckRuntimeErrors = regexp.MustCompile(`stat /bin/sh: no such file or directory|executable file not found in \$PATH|: not found`)
	localBuildBaseImages    = []imageAlias{
		{Alias: "vecta-local/golang:1.26-alpine", Source: "golang:1.26-alpine"},
		{Alias: "vecta-local/alpine:3.20", Source: "alpine:3.20"},
		{Alias: "vecta-local/alpine:3.21", Source: "alpine:3.21"},
		{Alias: "vecta-local/node:20-alpine", Source: "node:20-alpine"},
		{Alias: "vecta-local/nginx:1.27-alpine", Source: "nginx:1.27-alpine"},
		{Alias: "vecta-local/trivy:0.69.3", Source: "aquasec/trivy:0.69.3"},
	}
)

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

	startLogs, err := runRuntimeStart(deployPath, spec)
	status.Executed = true
	status.StartLogs = startLogs
	if err != nil {
		status.Message = "service startup failed"
		return status, err
	}
	status.StartOK = true

	healthLogs, healthChecked, err := runRuntimeHealthCheck(spec)
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
	if out.Spec.Features == nil {
		out.Spec.Features = map[string]bool{}
	}
	return out, nil
}

func composeProfiles(spec runtimeDeploymentSpec) []string {
	features := spec.Spec.Features
	seen := map[string]struct{}{}
	out := make([]string, 0, len(featureOrder)+4)
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

	for _, profile := range runtimeBaseProfiles {
		out = appendUnique(out, profile)
	}
	return out
}

func enabledServices(spec runtimeDeploymentSpec) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(baseRuntimeServices)+8)
	for _, svc := range baseRuntimeServices {
		seen[svc] = struct{}{}
		out = append(out, svc)
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

func runRuntimeStart(deployPath string, spec runtimeDeploymentSpec) ([]string, error) {
	if cmdText := strings.TrimSpace(os.Getenv("FIRSTBOOT_STACK_APPLY_COMMAND")); cmdText != "" {
		return runShellCommand(cmdText, map[string]string{
			"FIRSTBOOT_DEPLOYMENT_TARGET": deployPath,
		})
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("default runtime apply is only supported on linux; configure FIRSTBOOT_STACK_APPLY_COMMAND")
	}

	projectRoot := runtimeProjectRoot()
	composeFile := firstNonEmpty(
		strings.TrimSpace(os.Getenv("FIRSTBOOT_COMPOSE_FILE_PATH")),
		filepath.Join(projectRoot, "docker-compose.yml"),
	)
	if _, err := os.Stat(composeFile); err != nil {
		return nil, fmt.Errorf("compose file not found: %s", composeFile)
	}

	logs, err := ensureLocalBuildBaseImages()
	if err != nil {
		return logs, err
	}

	envMap, err := runtimeComposeEnv(spec)
	if err != nil {
		return logs, err
	}
	if err := prepareRuntimeVolumes(envMap); err != nil {
		return logs, err
	}

	argv := []string{"docker", "compose", "-f", composeFile, "up", "-d", "--build"}
	timeout := envDuration("FIRSTBOOT_STACK_APPLY_TIMEOUT", 30*time.Minute)
	composeLogs, err := runCommandWithOptions(argv, envMap, commandOptions{
		Dir:     filepath.Dir(composeFile),
		Timeout: timeout,
	})
	logs = append(logs, composeLogs...)
	return logs, err
}

func runRuntimeHealthCheck(spec runtimeDeploymentSpec) ([]string, bool, error) {
	if cmdText := strings.TrimSpace(os.Getenv("FIRSTBOOT_HEALTHCHECK_COMMAND")); cmdText != "" {
		logs, err := runShellCommand(cmdText, nil)
		return logs, true, err
	}

	if runtime.GOOS != "linux" {
		return nil, false, nil
	}

	projectRoot := runtimeProjectRoot()
	composeFile := firstNonEmpty(
		strings.TrimSpace(os.Getenv("FIRSTBOOT_COMPOSE_FILE_PATH")),
		filepath.Join(projectRoot, "docker-compose.yml"),
	)
	if _, err := os.Stat(composeFile); err != nil {
		return nil, false, nil
	}

	envMap, err := runtimeComposeEnv(spec)
	if err != nil {
		return nil, true, err
	}

	timeout := envDuration("FIRSTBOOT_HEALTHCHECK_TIMEOUT", 8*time.Minute)
	retryDelay := envDuration("FIRSTBOOT_HEALTHCHECK_RETRY_DELAY", 5*time.Second)
	deadline := time.Now().Add(timeout)
	services := enabledServices(spec)
	logs := make([]string, 0)

	for {
		attemptLogs, pending, err := inspectRuntimeServices(composeFile, envMap, services)
		logs = attemptLogs
		if err == nil {
			return logs, true, nil
		}
		if time.Now().After(deadline) {
			return logs, true, err
		}
		if len(pending) == 0 {
			return logs, true, err
		}
		time.Sleep(retryDelay)
	}
}

func runtimeComposeEnv(spec runtimeDeploymentSpec) (map[string]string, error) {
	envMap := map[string]string{
		"COMPOSE_PROFILES":       strings.Join(composeProfiles(spec), ","),
		"COMPOSE_IGNORE_ORPHANS": "true",
		"COMPOSE_PARALLEL_LIMIT": firstNonEmpty(strings.TrimSpace(os.Getenv("FIRSTBOOT_COMPOSE_PARALLEL_LIMIT")), "1"),
	}

	if value := strings.TrimSpace(os.Getenv("COMPOSE_PROJECT_NAME")); value != "" {
		envMap["COMPOSE_PROJECT_NAME"] = value
	}
	if value := strings.TrimSpace(os.Getenv("HSM_ENDPOINT")); value != "" {
		envMap["HSM_ENDPOINT"] = value
	} else {
		switch strings.ToLower(strings.TrimSpace(spec.Spec.HSMMode)) {
		case "hardware", "auto":
			envMap["HSM_ENDPOINT"] = "hsm-connector:18430"
		default:
			envMap["HSM_ENDPOINT"] = "software-vault:18440"
		}
	}
	if value := strings.TrimSpace(spec.Spec.HSMMode); value != "" {
		envMap["HSM_MODE"] = strings.ToLower(value)
	}

	certSecurity := spec.Spec.CertSecurity
	if value := strings.TrimSpace(certSecurity.CertStorageMode); value != "" {
		envMap["CERTS_STORAGE_MODE"] = value
	}
	if value := strings.TrimSpace(certSecurity.RootKeyMode); value != "" {
		envMap["CERTS_ROOT_KEY_MODE"] = value
	}
	if value := strings.TrimSpace(certSecurity.SealedKeyPath); value != "" {
		envMap["CERTS_CRWK_SEALED_PATH"] = value
	}
	if value := strings.TrimSpace(certSecurity.PassphraseFilePath); value != "" {
		envMap["CERTS_CRWK_PASSPHRASE_FILE"] = value
	}
	envMap["CERTS_CRWK_USE_TPM_SEAL"] = strconv.FormatBool(certSecurity.UseTPMSeal)

	bootstrapSecret, err := readRuntimeBootstrapSecret()
	if err != nil {
		return nil, err
	}
	if bootstrapSecret != "" {
		envMap["CERTS_CRWK_BOOTSTRAP_PASSPHRASE"] = bootstrapSecret
		envMap["CERTS_CRWK_PASSPHRASE_FILE"] = defaultVolumePassphrase
	}

	if value := strings.TrimSpace(os.Getenv("DOCKER_DEFAULT_PLATFORM")); value != "" {
		envMap["DOCKER_DEFAULT_PLATFORM"] = value
	} else if value := defaultDockerPlatform(); value != "" {
		envMap["DOCKER_DEFAULT_PLATFORM"] = value
	}
	return envMap, nil
}

func readRuntimeBootstrapSecret() (string, error) {
	path := strings.TrimSpace(envOr("FIRSTBOOT_CERT_BOOTSTRAP_PATH", defaultCertBootstrapPath))
	if path == "" {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read bootstrap secret: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func prepareRuntimeVolumes(envMap map[string]string) error {
	projectName := firstNonEmpty(
		strings.TrimSpace(envMap["COMPOSE_PROJECT_NAME"]),
		strings.TrimSpace(os.Getenv("COMPOSE_PROJECT_NAME")),
		"vecta-kms",
	)
	certsVolume := projectName + "_certs-key-data"
	runtimeVolume := projectName + "_runtime-certs"

	if _, err := runCommandWithOptions([]string{"docker", "volume", "create", certsVolume}, nil, commandOptions{Timeout: 30 * time.Second}); err != nil {
		return err
	}
	if _, err := runCommandWithOptions([]string{"docker", "volume", "create", runtimeVolume}, nil, commandOptions{Timeout: 30 * time.Second}); err != nil {
		return err
	}

	bootstrapSecret := strings.TrimSpace(envMap["CERTS_CRWK_BOOTSTRAP_PASSPHRASE"])
	helperScript := strings.Join([]string{
		"set -eu",
		"mkdir -p /data /runtime",
		"chown -R 100:101 /data /runtime",
		"chmod 700 /data /runtime",
		"if [ -n \"${BOOTSTRAP_SECRET:-}\" ] && [ ! -s /data/bootstrap.passphrase ]; then printf %s \"$BOOTSTRAP_SECRET\" > /data/bootstrap.passphrase; fi",
		"if [ -s /data/bootstrap.passphrase ]; then chown 100:101 /data/bootstrap.passphrase; chmod 600 /data/bootstrap.passphrase; fi",
	}, "; ")

	_, err := runCommandWithOptions([]string{
		"docker", "run", "--rm",
		"-v", certsVolume + ":/data",
		"-v", runtimeVolume + ":/runtime",
		"-e", "BOOTSTRAP_SECRET=" + bootstrapSecret,
		"alpine:3.20",
		"sh", "-lc", helperScript,
	}, nil, commandOptions{Timeout: 2 * time.Minute})
	if err != nil {
		return fmt.Errorf("prepare certificate volumes: %w", err)
	}
	return nil
}

func inspectRuntimeServices(composeFile string, envMap map[string]string, services []string) ([]string, []string, error) {
	logs := make([]string, 0, len(services))
	pending := make([]string, 0)

	for _, service := range services {
		containerID, err := composeServiceContainerID(composeFile, envMap, service)
		if err != nil {
			logs = append(logs, fmt.Sprintf("%s (lookup failed: %v)", service, err))
			pending = append(pending, service)
			continue
		}
		if containerID == "" {
			logs = append(logs, fmt.Sprintf("%s (missing)", service))
			pending = append(pending, service)
			continue
		}

		state, health, err := inspectContainerState(containerID)
		if err != nil {
			logs = append(logs, fmt.Sprintf("%s (inspect failed: %v)", service, err))
			pending = append(pending, service)
			continue
		}
		if state != "running" {
			logs = append(logs, fmt.Sprintf("%s (state=%s)", service, state))
			pending = append(pending, service)
			continue
		}
		if health != "" && health != "healthy" {
			missingRuntime, healthLog := healthcheckMissingRuntime(containerID)
			if missingRuntime {
				logs = append(logs, fmt.Sprintf("%s (running; health command unavailable)", service))
				if healthLog != "" {
					logs = append(logs, fmt.Sprintf("%s health log: %s", service, healthLog))
				}
				continue
			}
			logs = append(logs, fmt.Sprintf("%s (health=%s)", service, health))
			pending = append(pending, service)
			continue
		}

		logs = append(logs, fmt.Sprintf("%s (healthy)", service))
	}

	if len(pending) > 0 {
		return logs, pending, fmt.Errorf("health checks pending or failed: %s", strings.Join(pending, ", "))
	}
	return logs, nil, nil
}

func composeServiceContainerID(composeFile string, envMap map[string]string, service string) (string, error) {
	lines, err := runCommandWithOptions([]string{"docker", "compose", "-f", composeFile, "ps", "-q", service}, envMap, commandOptions{
		Dir:     filepath.Dir(composeFile),
		Timeout: 45 * time.Second,
	})
	if err != nil {
		return "", err
	}
	if len(lines) == 0 {
		return "", nil
	}
	return strings.TrimSpace(lines[len(lines)-1]), nil
}

func inspectContainerState(containerID string) (string, string, error) {
	lines, err := runCommandWithOptions([]string{
		"docker", "inspect",
		"--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}",
		containerID,
	}, nil, commandOptions{Timeout: 30 * time.Second})
	if err != nil {
		return "", "", err
	}
	if len(lines) == 0 {
		return "", "", errors.New("no inspect output")
	}
	parts := strings.SplitN(lines[len(lines)-1], "|", 2)
	state := strings.ToLower(strings.TrimSpace(parts[0]))
	health := ""
	if len(parts) > 1 {
		health = strings.ToLower(strings.TrimSpace(parts[1]))
	}
	return state, health, nil
}

func healthcheckMissingRuntime(containerID string) (bool, string) {
	lines, err := runCommandWithOptions([]string{
		"docker", "inspect",
		"--format", "{{if .State.Health}}{{range .State.Health.Log}}{{println .Output}}{{end}}{{end}}",
		containerID,
	}, nil, commandOptions{Timeout: 30 * time.Second})
	if err != nil {
		return false, ""
	}
	logText := strings.Join(lines, " ")
	return healthcheckRuntimeErrors.MatchString(logText), strings.TrimSpace(logText)
}

func scheduleFirstbootCleanup(status *RuntimeApplyStatus) error {
	if status == nil || !status.Executed || !status.StartOK || (status.HealthChecked && !status.Healthy) {
		return nil
	}

	self, err := inspectCurrentContainer()
	if err != nil {
		return err
	}

	envMap, err := currentRuntimeComposeEnv()
	if err != nil {
		return err
	}
	helperImage := firstNonEmpty(self.Config.Image, "vecta/firstboot:latest")
	helperPlatform := firstNonEmpty(
		strings.TrimSpace(os.Getenv("FIRSTBOOT_SELF_CLEANUP_PLATFORM")),
		strings.TrimSpace(envMap["DOCKER_DEFAULT_PLATFORM"]),
		dockerImagePlatform(helperImage),
	)
	delaySeconds := envInt("FIRSTBOOT_SELF_CLEANUP_DELAY_SECONDS", 20)
	if delaySeconds < 2 {
		delaySeconds = 2
	}

	command := fmt.Sprintf(
		"sleep %d; docker rm -f \"$FIRSTBOOT_SELF_CONTAINER\" >/dev/null 2>&1 || true",
		delaySeconds,
	)
	argv := []string{
		"docker", "run", "-d", "--rm",
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"-e", "FIRSTBOOT_SELF_CONTAINER=" + self.ID,
	}
	if helperPlatform != "" {
		argv = append(argv, "--platform", helperPlatform)
	}
	argv = append(argv, "--entrypoint", "/bin/sh", helperImage, "-lc", command)

	lines, err := runCommandWithOptions(argv, nil, commandOptions{Timeout: 45 * time.Second})
	if err != nil {
		return err
	}
	status.CleanupScheduled = true
	status.CleanupLogs = lines
	return nil
}

func inspectCurrentContainer() (dockerInspectResult, error) {
	containerID := strings.TrimSpace(os.Getenv("HOSTNAME"))
	if containerID == "" {
		return dockerInspectResult{}, errors.New("HOSTNAME is empty; cannot resolve running firstboot container")
	}

	lines, err := runCommandWithOptions([]string{"docker", "inspect", containerID}, nil, commandOptions{Timeout: 30 * time.Second})
	if err != nil {
		return dockerInspectResult{}, err
	}
	var payload []dockerInspectResult
	if err := json.Unmarshal([]byte(strings.Join(lines, "\n")), &payload); err != nil {
		return dockerInspectResult{}, fmt.Errorf("decode docker inspect output: %w", err)
	}
	if len(payload) == 0 {
		return dockerInspectResult{}, errors.New("docker inspect returned no containers")
	}
	return payload[0], nil
}

func currentRuntimeComposeEnv() (map[string]string, error) {
	deployPath := firstNonEmpty(
		strings.TrimSpace(os.Getenv("FIRSTBOOT_DEPLOYMENT_PATH")),
		defaultDeploymentPath,
	)
	spec, err := loadRuntimeDeploymentSpec(deployPath)
	if err != nil {
		return nil, err
	}
	return runtimeComposeEnv(spec)
}

func ensureLocalBuildBaseImages() ([]string, error) {
	logs := make([]string, 0, len(localBuildBaseImages))
	for _, image := range localBuildBaseImages {
		if dockerImageExists(image.Alias) {
			continue
		}
		if !dockerImageExists(image.Source) {
			return logs, fmt.Errorf("required local build base image %s is missing; load or pull it before applying firstboot", image.Source)
		}
		if _, err := runCommandWithOptions([]string{"docker", "tag", image.Source, image.Alias}, nil, commandOptions{Timeout: 30 * time.Second}); err != nil {
			return logs, fmt.Errorf("tag build base image %s as %s: %w", image.Source, image.Alias, err)
		}
		logs = append(logs, fmt.Sprintf("tagged %s as %s", image.Source, image.Alias))
	}
	return logs, nil
}

func dockerImageExists(image string) bool {
	lines, err := runCommandWithOptions([]string{
		"docker", "image", "inspect", "--format", "{{.Id}}", image,
	}, nil, commandOptions{Timeout: 30 * time.Second})
	return err == nil && len(lines) > 0
}

func dockerImagePlatform(image string) string {
	if image == "" {
		return ""
	}
	lines, err := runCommandWithOptions([]string{
		"docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image,
	}, nil, commandOptions{Timeout: 30 * time.Second})
	if err != nil || len(lines) == 0 {
		return ""
	}
	return normalizePlatform(lines[len(lines)-1])
}

func defaultDockerPlatform() string {
	lines, err := runCommandWithOptions([]string{
		"docker", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}",
	}, nil, commandOptions{Timeout: 30 * time.Second})
	if err != nil || len(lines) == 0 {
		return ""
	}
	host := normalizePlatform(lines[len(lines)-1])
	if strings.HasPrefix(host, "linux/arm64") {
		return "linux/amd64"
	}
	return host
}

func normalizePlatform(value string) string {
	raw := strings.ToLower(strings.TrimSpace(value))
	switch raw {
	case "", "/":
		return ""
	case "linux/arm64", "linux/aarch64":
		return "linux/arm64/v8"
	default:
		return raw
	}
}

func runShellCommand(command string, extraEnv map[string]string) ([]string, error) {
	if runtime.GOOS == "windows" {
		return runCommandWithOptions([]string{"cmd", "/C", command}, extraEnv, commandOptions{Timeout: 2 * time.Minute})
	}
	return runCommandWithOptions([]string{"/bin/sh", "-lc", command}, extraEnv, commandOptions{Timeout: 2 * time.Minute})
}

func runCommandWithOptions(argv []string, extraEnv map[string]string, options commandOptions) ([]string, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = os.Environ()
	for key, value := range extraEnv {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	if options.Dir != "" {
		cmd.Dir = options.Dir
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
		fmt.Sprintf("Run docker compose -f %s up -d --build", filepath.Join(projectRoot, "docker-compose.yml")),
		fmt.Sprintf("Run docker compose -f %s ps", filepath.Join(projectRoot, "docker-compose.yml")),
		fmt.Sprintf("Verify generated config at %s", deployPath),
	}
}

func runtimeProjectRoot() string {
	projectRoot := strings.TrimSpace(os.Getenv("FIRSTBOOT_PROJECT_ROOT"))
	if projectRoot == "" {
		projectRoot = "/opt/vecta"
	}
	self, err := inspectCurrentContainer()
	if err == nil {
		for _, mount := range self.Mounts {
			if mount.Destination == projectRoot && mount.Source != "" {
				if aliased := ensureHostPathAlias(mount.Source, projectRoot); aliased != "" {
					return aliased
				}
				return mount.Source
			}
		}
	}
	return projectRoot
}

func ensureHostPathAlias(hostPath string, containerPath string) string {
	hostPath = strings.TrimSpace(hostPath)
	containerPath = strings.TrimSpace(containerPath)
	if hostPath == "" || containerPath == "" || hostPath == containerPath {
		return hostPath
	}

	if _, err := os.Stat(filepath.Join(hostPath, "docker-compose.yml")); err == nil {
		return hostPath
	}

	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		return ""
	}

	if existing, err := os.Lstat(hostPath); err == nil {
		if existing.Mode()&os.ModeSymlink != 0 {
			if target, readErr := os.Readlink(hostPath); readErr == nil && target == containerPath {
				return hostPath
			}
		}
		return ""
	}

	if err := os.Symlink(containerPath, hostPath); err != nil {
		return ""
	}
	return hostPath
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

func envInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func envDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	if parsed, err := time.ParseDuration(raw); err == nil {
		return parsed
	}
	if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}
