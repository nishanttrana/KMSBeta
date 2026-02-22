package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kardianos/service"
)

type program struct {
	cfg    AgentConfig
	logger *log.Logger
	stopCh chan struct{}
	doneCh chan struct{}
}

func main() {
	var (
		configPath  string
		serviceCmd  string
		runOnce     bool
		showVersion bool
	)
	flag.StringVar(&configPath, "config", "", "Path to agent config JSON")
	flag.StringVar(&serviceCmd, "service", "", "Service command: install|uninstall|start|stop|restart")
	flag.BoolVar(&runOnce, "once", false, "Run register+heartbeat once and exit")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(agentVersion())
		return
	}

	if strings.TrimSpace(configPath) == "" {
		configPath = defaultConfigPath()
	}

	cfg, err := LoadAgentConfig(configPath)
	if err != nil {
		log.Fatalf("load config failed: %v", err)
	}

	logger := log.New(os.Stdout, "[ekm-agent] ", log.LstdFlags|log.LUTC)
	logger.Printf("starting with config=%s agent_id=%s db_engine=%s", configPath, cfg.AgentID, cfg.DBEngine)

	if runOnce {
		runner := NewAgentRunner(cfg, logger)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := runner.Register(ctx); err != nil {
			logger.Fatalf("register failed: %v", err)
		}
		if err := runner.SendHeartbeat(ctx); err != nil {
			logger.Fatalf("heartbeat failed: %v", err)
		}
		logger.Printf("run-once completed")
		return
	}

	svcCfg := &service.Config{
		Name:        "VectaEKMAgent",
		DisplayName: "Vecta EKM TDE Agent",
		Description: "Vecta KMS EKM agent for MSSQL/Oracle TDE with PKCS#11 integration",
		Arguments:   []string{"-config", configPath},
	}

	p := &program{
		cfg:    cfg,
		logger: logger,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}

	s, err := service.New(p, svcCfg)
	if err != nil {
		logger.Fatalf("service init failed: %v", err)
	}

	if strings.TrimSpace(serviceCmd) != "" {
		if err := service.Control(s, strings.ToLower(strings.TrimSpace(serviceCmd))); err != nil {
			logger.Fatalf("service command failed: %v", err)
		}
		return
	}

	if err := s.Run(); err != nil {
		logger.Fatalf("service run failed: %v", err)
	}
}

func (p *program) Start(_ service.Service) error {
	go p.runLoop()
	return nil
}

func (p *program) Stop(_ service.Service) error {
	select {
	case <-p.stopCh:
	default:
		close(p.stopCh)
	}
	select {
	case <-p.doneCh:
	case <-time.After(10 * time.Second):
	}
	return nil
}

func (p *program) runLoop() {
	defer close(p.doneCh)
	runner := NewAgentRunner(p.cfg, p.logger)

	ctx := context.Background()
	if err := runner.Register(ctx); err != nil {
		p.logger.Printf("register failed: %v", err)
	}

	interval := time.Duration(maxInt(p.cfg.HeartbeatIntervalSec, 5)) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Support foreground graceful shutdown when not running via SCM.
	sigCtx, sigCancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer sigCancel()

	for {
		select {
		case <-p.stopCh:
			p.logger.Printf("stop requested")
			return
		case <-sigCtx.Done():
			p.logger.Printf("signal received, stopping")
			return
		case <-ticker.C:
			hbCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			err := runner.SendHeartbeat(hbCtx)
			cancel()
			if err != nil {
				p.logger.Printf("heartbeat failed: %v", err)
			}
		}
	}
}

type AgentRunner struct {
	cfg        AgentConfig
	httpClient *http.Client
	logger     *log.Logger
	inspector  TDEInspector
}

func NewAgentRunner(cfg AgentConfig, logger *log.Logger) *AgentRunner {
	transport := &http.Transport{}
	if cfg.TLSSkipVerify {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}
	return &AgentRunner{
		cfg:        cfg,
		httpClient: client,
		logger:     logger,
		inspector:  NewTDEInspector(cfg),
	}
}

func (r *AgentRunner) Register(ctx context.Context) error {
	body := map[string]interface{}{
		"tenant_id":              r.cfg.TenantID,
		"agent_id":               r.cfg.AgentID,
		"name":                   r.cfg.AgentName,
		"role":                   r.cfg.Role,
		"db_engine":              r.cfg.DBEngine,
		"host":                   r.cfg.Host,
		"version":                r.cfg.Version,
		"heartbeat_interval_sec": r.cfg.HeartbeatIntervalSec,
		"auto_provision_tde":     r.cfg.AutoProvisionTDE,
		"metadata_json":          mustJSON(r.staticMetadata()),
	}
	url := joinURL(r.cfg.APIBaseURL, r.cfg.RegisterPath)
	return r.postJSON(ctx, url, body, nil)
}

func (r *AgentRunner) SendHeartbeat(ctx context.Context) error {
	tdeState, tdeDetails, stateErr := r.inspector.State(ctx)
	pkcs11 := CheckPKCS11Readiness(r.cfg.PKCS11ModulePath)
	osm := GatherOSMetrics(ctx)

	status := "connected"
	if stateErr != nil || !pkcs11.Ready {
		status = "degraded"
	}

	activeVersion := strings.TrimSpace(r.cfg.ActiveKeyVersion)
	if activeVersion == "" {
		activeVersion = "v1"
	}
	meta := map[string]interface{}{
		"hostname":            osm.Hostname,
		"os_name":             osm.OSName,
		"os_version":          osm.OSVersion,
		"kernel":              osm.Kernel,
		"arch":                osm.Arch,
		"cpu_usage_pct":       osm.CPUUsagePct,
		"memory_usage_pct":    osm.MemoryUsagePct,
		"disk_usage_pct":      osm.DiskUsagePct,
		"load_1":              osm.Load1,
		"uptime_sec":          osm.UptimeSec,
		"agent_runtime_sec":   osm.AgentRuntimeSec,
		"db_tde_state":        tdeState,
		"db_tde_details":      tdeDetails,
		"pkcs11_module_path":  r.cfg.PKCS11ModulePath,
		"pkcs11_ready":        pkcs11.Ready,
		"pkcs11_reason":       pkcs11.Reason,
		"rotation_cycle_days": r.cfg.RotationCycleDays,
		"target_os":           "windows",
	}
	if stateErr != nil {
		meta["db_error"] = stateErr.Error()
	}
	body := map[string]interface{}{
		"tenant_id":          r.cfg.TenantID,
		"status":             status,
		"tde_state":          tdeState,
		"active_key_id":      strings.TrimSpace(r.cfg.ActiveKeyID),
		"active_key_version": activeVersion,
		"config_version_ack": r.cfg.ConfigVersionAck,
		"metadata_json":      mustJSON(meta),
	}
	hbPath := replaceAgentIDPath(r.cfg.HeartbeatPath, r.cfg.AgentID)
	url := joinURL(r.cfg.APIBaseURL, hbPath)
	if err := r.postJSON(ctx, url, body, nil); err != nil {
		return err
	}
	r.logger.Printf("heartbeat sent status=%s tde_state=%s pkcs11_ready=%t", status, tdeState, pkcs11.Ready)
	return nil
}

func (r *AgentRunner) staticMetadata() map[string]interface{} {
	return map[string]interface{}{
		"target_os":           "windows",
		"rotation_cycle_days": r.cfg.RotationCycleDays,
		"pkcs11_profile":      strings.ToLower(strings.TrimSpace(r.cfg.DBEngine)) + "-tde-pkcs11",
		"db_type":             strings.ToLower(strings.TrimSpace(r.cfg.DBEngine)),
	}
}

func (r *AgentRunner) postJSON(ctx context.Context, url string, payload interface{}, out interface{}) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", r.cfg.TenantID)
	if strings.TrimSpace(r.cfg.AuthToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(r.cfg.AuthToken))
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("http %s failed: status=%d", url, resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func defaultConfigPath() string {
	if strings.EqualFold(os.Getenv("OS"), "Windows_NT") {
		base := strings.TrimSpace(os.Getenv("ProgramData"))
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "Vecta", "EKMAgent", "agent-config.json")
	}
	return "/etc/vecta-ekm/agent-config.json"
}

func agentVersion() string {
	return "vecta-ekm-agent/1.0.0"
}

func joinURL(baseURL string, path string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	p := strings.TrimSpace(path)
	if p == "" {
		return base
	}
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return base + p
}

func replaceAgentIDPath(path string, agentID string) string {
	out := strings.TrimSpace(path)
	replacements := []string{"{agent_id}", "{id}", ":agent_id", ":id"}
	for _, token := range replacements {
		out = strings.ReplaceAll(out, token, strings.TrimSpace(agentID))
	}
	return out
}

func mustJSON(v interface{}) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(raw)
}

func maxInt(v int, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func runWithSignal(ctx context.Context, fn func(context.Context) error) error {
	sigCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- fn(sigCtx)
	}()
	select {
	case <-sigCtx.Done():
		return sigCtx.Err()
	case err := <-errCh:
		return err
	}
}

func errWrap(msg string, err error) error {
	if err == nil {
		return errors.New(msg)
	}
	return fmt.Errorf("%s: %w", msg, err)
}
