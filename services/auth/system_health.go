package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	consulapi "github.com/hashicorp/consul/api"
)

type ServiceHealth struct {
	Name               string `json:"name"`
	Status             string `json:"status"`
	Source             string `json:"source"`
	Address            string `json:"address,omitempty"`
	Port               int    `json:"port,omitempty"`
	Instances          int    `json:"instances,omitempty"`
	Passing            int    `json:"passing,omitempty"`
	Warning            int    `json:"warning,omitempty"`
	Critical           int    `json:"critical,omitempty"`
	Output             string `json:"output,omitempty"`
	RestartAllowed     bool   `json:"restart_allowed"`
	RestartBlockReason string `json:"restart_block_reason,omitempty"`
}

type SystemHealthSummary struct {
	Total    int  `json:"total"`
	Running  int  `json:"running"`
	Degraded int  `json:"degraded"`
	Down     int  `json:"down"`
	Unknown  int  `json:"unknown"`
	AllOK    bool `json:"all_ok"`
}

type SystemHealthSnapshot struct {
	Services    []ServiceHealth     `json:"services"`
	Summary     SystemHealthSummary `json:"summary"`
	CollectedAt string              `json:"collected_at"`
}

type serviceTarget struct {
	name    string
	address string
}

type SystemHealthChecker struct {
	consul          *consulapi.Client
	logger          *log.Logger
	dialTimeout     time.Duration
	infra           []serviceTarget
	restartEnabled  bool
	dockerSockPath  string
	composeProject  string
	restartHTTP     *http.Client
	restartBlockMap map[string]string
}

var (
	errRestartNotAllowed  = errors.New("service restart not allowed")
	errRestartUnavailable = errors.New("service restart unavailable")
	errRestartFailed      = errors.New("service restart failed")
)

func NewSystemHealthChecker(consulAddr string, logger *log.Logger) *SystemHealthChecker {
	cfg := consulapi.DefaultConfig()
	cfg.Address = strings.TrimSpace(consulAddr)

	var client *consulapi.Client
	if c, err := consulapi.NewClient(cfg); err == nil {
		client = c
	} else if logger != nil {
		logger.Printf("system health: consul client init failed: %v", err)
	}

	restartEnabled := envFlag("SYSTEM_SERVICE_RESTART_ENABLED", true)
	dockerSock := firstNonEmpty(os.Getenv("DOCKER_SOCKET_PATH"), "/var/run/docker.sock")
	composeProject := firstNonEmpty(os.Getenv("COMPOSE_PROJECT_NAME"), "vecta-kms")

	var dockerHTTP *http.Client
	if strings.TrimSpace(dockerSock) != "" {
		dockerHTTP = dockerSocketHTTPClient(dockerSock)
	}

	return &SystemHealthChecker{
		consul:          client,
		logger:          logger,
		dialTimeout:     700 * time.Millisecond,
		infra:           defaultInfraTargets(consulAddr),
		restartEnabled:  restartEnabled,
		dockerSockPath:  dockerSock,
		composeProject:  composeProject,
		restartHTTP:     dockerHTTP,
		restartBlockMap: blockedRestartServices(),
	}
}

func envFlag(key string, defaultValue bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return defaultValue
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultValue
	}
}

func blockedRestartServices() map[string]string {
	return map[string]string{
		"audit":           "core audit service",
		"auth":            "core authentication service",
		"cluster-manager": "cluster control-plane service",
		"consul":          "service discovery backend",
		"dashboard":       "dashboard UI service",
		"envoy":           "edge proxy service",
		"etcd":            "distributed coordination backend",
		"hsm-connector":   "hardware HSM connector",
		"keycore":         "core key management service",
		"nats":            "messaging backend",
		"policy":          "core policy service",
		"postgres":        "database backend",
		"valkey":          "cache backend",
	}
}

func dockerSocketHTTPClient(socketPath string) *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &http.Client{
		Transport: transport,
		Timeout:   12 * time.Second,
	}
}

func defaultInfraTargets(consulAddr string) []serviceTarget {
	if raw := strings.TrimSpace(os.Getenv("SYSTEM_HEALTH_INFRA")); raw != "" {
		return parseTargetList(raw)
	}
	targets := []serviceTarget{
		{name: "PostgreSQL", address: postgresTarget()},
		{name: "Valkey", address: normalizeTargetAddress(firstNonEmpty(os.Getenv("REDIS_URL"), "valkey:6379"), "valkey:6379")},
		{name: "NATS JetStream", address: normalizeTargetAddress(firstNonEmpty(os.Getenv("NATS_URL"), "nats://nats:4222"), "nats:4222")},
		{name: "Consul", address: normalizeTargetAddress(firstNonEmpty(consulAddr, "consul:8500"), "consul:8500")},
		{name: "etcd", address: normalizeTargetAddress(firstNonEmpty(os.Getenv("ETCD_ENDPOINT"), "etcd:2379"), "etcd:2379")},
	}
	targets = append(targets, knownBackendTargets()...)
	return targets
}

func knownBackendTargets() []serviceTarget {
	return []serviceTarget{
		{name: "kms-auth", address: "auth:18001"},
		{name: "kms-keycore", address: "keycore:18010"},
		{name: "kms-secrets", address: "secrets:18020"},
		{name: "kms-certs", address: "certs:18030"},
		{name: "kms-policy", address: "policy:18040"},
		{name: "kms-governance", address: "governance:18050"},
		{name: "kms-pqc", address: "pqc:18060"},
		{name: "kms-audit", address: "audit:18070"},
		{name: "kms-cloud", address: "cloud:18080"},
		{name: "kms-ai", address: "ai:18090"},
		{name: "kms-discovery", address: "discovery:18100"},
		{name: "kms-compliance", address: "compliance:18110"},
		{name: "kms-hyok-proxy", address: "hyok:18120"},
		{name: "kms-ekm", address: "ekm:18130"},
		{name: "kms-reporting", address: "reporting:18140"},
		{name: "kms-qkd", address: "qkd:18150"},
		{name: "kms-payment", address: "payment:18170"},
		{name: "kms-sbom", address: "sbom:18180"},
		{name: "kms-mpc", address: "mpc:18190"},
		{name: "kms-dataprotect", address: "dataprotect:18200"},
		{name: "kms-cluster-manager", address: "cluster-manager:18210"},
		{name: "kms-hsm-connector", address: "hsm-connector:18430"},
		{name: "kms-kmip", address: "kmip:15696"},
		{name: "kms-software-vault", address: "software-vault:18440"},
	}
}

func parseTargetList(raw string) []serviceTarget {
	parts := strings.Split(raw, ",")
	targets := make([]serviceTarget, 0, len(parts))
	for _, p := range parts {
		entry := strings.TrimSpace(p)
		if entry == "" {
			continue
		}
		name := entry
		address := entry
		if idx := strings.Index(entry, "="); idx > 0 {
			name = strings.TrimSpace(entry[:idx])
			address = strings.TrimSpace(entry[idx+1:])
		}
		normalized := normalizeTargetAddress(address, "")
		if name == "" || normalized == "" {
			continue
		}
		targets = append(targets, serviceTarget{name: name, address: normalized})
	}
	return targets
}

func postgresTarget() string {
	raw := strings.TrimSpace(os.Getenv("POSTGRES_DSN"))
	if raw == "" {
		return "postgres:5432"
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return ensurePort(u.Host, "5432")
	}
	return normalizeTargetAddress(raw, "postgres:5432")
}

func normalizeTargetAddress(raw string, fallback string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fallback
	}
	if strings.Contains(trimmed, "://") {
		if u, err := url.Parse(trimmed); err == nil && u.Host != "" {
			return ensurePort(u.Host, fallbackPort(fallback))
		}
	}
	if strings.Contains(trimmed, "@") && strings.Contains(trimmed, ":") {
		if idx := strings.LastIndex(trimmed, "@"); idx >= 0 && idx+1 < len(trimmed) {
			trimmed = trimmed[idx+1:]
		}
	}
	return ensurePort(trimmed, fallbackPort(fallback))
}

func fallbackPort(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err == nil && port != "" {
		return port
	}
	if idx := strings.LastIndex(addr, ":"); idx >= 0 && idx+1 < len(addr) {
		return addr[idx+1:]
	}
	return ""
}

func ensurePort(hostPort string, fallbackPort string) string {
	if strings.TrimSpace(hostPort) == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(hostPort); err == nil {
		return hostPort
	}
	if strings.Count(hostPort, ":") > 1 && !strings.Contains(hostPort, "]") {
		hostPort = "[" + hostPort + "]"
	}
	if fallbackPort == "" {
		return hostPort
	}
	return net.JoinHostPort(hostOnly(hostPort), fallbackPort)
}

func hostOnly(hostPort string) string {
	if host, _, err := net.SplitHostPort(hostPort); err == nil {
		return host
	}
	return hostPort
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (c *SystemHealthChecker) Snapshot(ctx context.Context) (SystemHealthSnapshot, error) {
	services := make(map[string]ServiceHealth)
	pinnedDown := make(map[string]bool)
	var sourceErr error

	if c.restartHTTP != nil {
		items, err := c.collectComposeServiceHealth(ctx)
		if err != nil {
			sourceErr = mergeSourceErr(sourceErr, err)
			if c.logger != nil {
				c.logger.Printf("system health: compose query failed: %v", err)
			}
		}
		for _, item := range items {
			key := strings.ToLower(item.Name)
			services[key] = item
			if strings.ToLower(item.Status) != "running" {
				pinnedDown[key] = true
			}
		}
	}

	if c.consul != nil {
		items, err := c.collectConsulServices(ctx)
		if err != nil {
			sourceErr = mergeSourceErr(sourceErr, err)
			if c.logger != nil {
				c.logger.Printf("system health: consul query failed: %v", err)
			}
		}
		for _, item := range items {
			key := strings.ToLower(item.Name)
			if pinnedDown[key] {
				continue
			}
			services[key] = item
		}
	}

	for _, target := range c.infra {
		item, ok := c.collectTCPService(ctx, target)
		if !ok {
			continue
		}
		key := strings.ToLower(item.Name)
		if pinnedDown[key] {
			continue
		}
		if existing, exists := services[key]; exists && strings.ToLower(existing.Status) == "running" {
			continue
		}
		services[key] = item
	}

	list := make([]ServiceHealth, 0, len(services))
	for _, item := range services {
		allowed, reason := c.isRestartAllowed(item.Name)
		item.RestartAllowed = allowed
		if !allowed {
			item.RestartBlockReason = reason
		}
		list = append(list, item)
	}
	sort.Slice(list, func(i, j int) bool {
		return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
	})

	summary := summarizeServiceHealth(list)
	return SystemHealthSnapshot{
		Services:    list,
		Summary:     summary,
		CollectedAt: time.Now().UTC().Format(time.RFC3339),
	}, sourceErr
}

func summarizeServiceHealth(items []ServiceHealth) SystemHealthSummary {
	out := SystemHealthSummary{Total: len(items)}
	for _, item := range items {
		switch strings.ToLower(item.Status) {
		case "running":
			out.Running++
		case "degraded":
			out.Degraded++
		case "down":
			out.Down++
		default:
			out.Unknown++
		}
	}
	out.AllOK = out.Total > 0 && out.Running == out.Total
	return out
}

func (c *SystemHealthChecker) collectConsulServices(ctx context.Context) ([]ServiceHealth, error) {
	query := &consulapi.QueryOptions{
		AllowStale: true,
	}
	names, _, err := c.consul.Catalog().Services(query.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	items := make([]ServiceHealth, 0, len(names))
	for name := range names {
		item := ServiceHealth{
			Name:   name,
			Status: "unknown",
			Source: "consul",
		}
		entries, _, svcErr := c.consul.Health().Service(name, "", false, query.WithContext(ctx))
		if svcErr != nil {
			item.Output = svcErr.Error()
			items = append(items, item)
			continue
		}
		if len(entries) == 0 {
			item.Output = "no instances"
			items = append(items, item)
			continue
		}

		item.Instances = len(entries)
		if entries[0].Service != nil {
			item.Address = strings.TrimSpace(entries[0].Service.Address)
			if item.Address == "" && entries[0].Node != nil {
				item.Address = strings.TrimSpace(entries[0].Node.Address)
			}
			item.Port = entries[0].Service.Port
		}
		item.Status, item.Passing, item.Warning, item.Critical, item.Output = summarizeConsulChecks(entries)
		if item.Port > 0 && item.Status != "running" {
			if tcpHost := serviceDialHost(name, item.Address); tcpHost != "" {
				addr := net.JoinHostPort(tcpHost, strconv.Itoa(item.Port))
				tcpState, tcpOut := tcpStatus(ctx, addr, c.dialTimeout)
				if tcpState == "running" {
					item.Status = "running"
					item.Output = ""
					item.Address = tcpHost
					item.Source = "consul+tcp"
				} else if item.Output == "" {
					item.Output = tcpOut
				}
			}
		}
		items = append(items, item)
	}
	return items, nil
}

func serviceDialHost(serviceName string, registeredAddress string) string {
	addr := strings.TrimSpace(registeredAddress)
	if addr != "" && !strings.Contains(addr, "$") {
		return strings.Trim(addr, "[]")
	}
	name := strings.ToLower(strings.TrimSpace(serviceName))
	name = strings.TrimPrefix(name, "kms-")
	name = strings.TrimSuffix(name, "-proxy")
	return name
}

func summarizeConsulChecks(entries []*consulapi.ServiceEntry) (status string, passing int, warning int, critical int, output string) {
	status = "unknown"
	for _, entry := range entries {
		for _, check := range entry.Checks {
			switch strings.ToLower(strings.TrimSpace(check.Status)) {
			case consulapi.HealthPassing:
				passing++
			case consulapi.HealthWarning:
				warning++
				if output == "" {
					output = strings.TrimSpace(check.Output)
				}
			case consulapi.HealthCritical:
				critical++
				if output == "" {
					output = strings.TrimSpace(check.Output)
				}
			default:
				if output == "" {
					output = strings.TrimSpace(check.Output)
				}
			}
		}
	}

	switch {
	case critical > 0 && passing == 0 && warning == 0:
		status = "down"
	case critical > 0 || warning > 0:
		status = "degraded"
	case passing > 0:
		status = "running"
	default:
		status = "unknown"
	}
	return status, passing, warning, critical, output
}

func (c *SystemHealthChecker) collectTCPService(ctx context.Context, target serviceTarget) (ServiceHealth, bool) {
	addr := normalizeTargetAddress(target.address, "")
	if addr == "" {
		return ServiceHealth{}, false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ServiceHealth{}, false
	}
	status, output := tcpStatus(ctx, addr, c.dialTimeout)
	if status != "running" {
		return ServiceHealth{}, false
	}
	return ServiceHealth{
		Name:    target.name,
		Status:  status,
		Source:  "tcp",
		Address: host,
		Port:    parsePort(addr),
		Output:  output,
	}, true
}

func tcpStatus(ctx context.Context, addr string, timeout time.Duration) (string, string) {
	dialer := net.Dialer{Timeout: timeout}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dialer.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return "down", err.Error()
	}
	_ = conn.Close()
	return "running", ""
}

func parsePort(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n := 0
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return 0
		}
		n = n*10 + int(p[i]-'0')
	}
	return n
}

func mergeSourceErr(current error, next error) error {
	if current == nil {
		return next
	}
	if next == nil {
		return current
	}
	return fmt.Errorf("%v; %w", current, next)
}

type composeAggregate struct {
	Total      int
	Running    int
	Restarting int
	Paused     int
	Exited     int
	Created    int
	Dead       int
}

func (c *SystemHealthChecker) collectComposeServiceHealth(ctx context.Context) ([]ServiceHealth, error) {
	if c.restartHTTP == nil {
		return nil, fmt.Errorf("%w: docker client unavailable", errRestartUnavailable)
	}
	if _, statErr := os.Stat(c.dockerSockPath); statErr != nil {
		return nil, fmt.Errorf("%w: docker socket unavailable at %s", errRestartUnavailable, c.dockerSockPath)
	}

	filters := map[string][]string{
		"label": {
			"com.docker.compose.project=" + c.composeProject,
		},
	}
	rawFilters, err := json.Marshal(filters)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to encode docker filters", errRestartFailed)
	}

	path := "http://docker/containers/json?all=1&filters=" + url.QueryEscape(string(rawFilters))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to build docker query", errRestartFailed)
	}
	resp, err := c.restartHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to query docker containers", errRestartUnavailable)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: docker query failed (%d): %s", errRestartFailed, resp.StatusCode, bodySnippet(resp.Body))
	}

	var items []dockerContainerItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("%w: failed to decode docker response", errRestartFailed)
	}

	agg := make(map[string]*composeAggregate)
	for _, item := range items {
		serviceName := strings.TrimSpace(item.Label["com.docker.compose.service"])
		displayName, include := composeServiceToHealthName(serviceName)
		if !include {
			continue
		}
		if agg[displayName] == nil {
			agg[displayName] = &composeAggregate{}
		}
		state := strings.ToLower(strings.TrimSpace(item.State))
		current := agg[displayName]
		current.Total++
		switch state {
		case "running":
			current.Running++
		case "restarting":
			current.Restarting++
		case "paused":
			current.Paused++
		case "exited":
			current.Exited++
		case "dead":
			current.Dead++
		case "created":
			current.Created++
		default:
			current.Created++
		}
	}

	out := make([]ServiceHealth, 0, len(agg))
	for name, state := range agg {
		status, msg := composeAggregateStatus(*state)
		out = append(out, ServiceHealth{
			Name:      name,
			Status:    status,
			Source:    "docker",
			Instances: state.Total,
			Output:    msg,
		})
	}
	return out, nil
}

func composeServiceToHealthName(serviceName string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(serviceName)) {
	case "auth":
		return "kms-auth", true
	case "keycore":
		return "kms-keycore", true
	case "secrets":
		return "kms-secrets", true
	case "certs":
		return "kms-certs", true
	case "policy":
		return "kms-policy", true
	case "governance":
		return "kms-governance", true
	case "pqc":
		return "kms-pqc", true
	case "audit":
		return "kms-audit", true
	case "cloud":
		return "kms-cloud", true
	case "compliance":
		return "kms-compliance", true
	case "hyok":
		return "kms-hyok-proxy", true
	case "ekm":
		return "kms-ekm", true
	case "reporting":
		return "kms-reporting", true
	case "qkd":
		return "kms-qkd", true
	case "payment":
		return "kms-payment", true
	case "sbom":
		return "kms-sbom", true
	case "dataprotect":
		return "kms-dataprotect", true
	case "mpc":
		return "kms-mpc", true
	case "cluster-manager":
		return "kms-cluster-manager", true
	case "discovery":
		return "kms-discovery", true
	case "ai":
		return "kms-ai", true
	case "hsm-connector":
		return "kms-hsm-connector", true
	case "kmip":
		return "kms-kmip", true
	case "software-vault":
		return "kms-software-vault", true
	case "postgres":
		return "PostgreSQL", true
	case "nats":
		return "NATS JetStream", true
	case "valkey":
		return "Valkey", true
	case "consul":
		return "consul", true
	case "etcd":
		return "etcd", true
	default:
		return "", false
	}
}

func composeAggregateStatus(state composeAggregate) (string, string) {
	if state.Total == 0 {
		return "unknown", "no containers"
	}
	if state.Running == state.Total {
		return "running", ""
	}
	if state.Running > 0 {
		return "degraded", fmt.Sprintf("running=%d total=%d", state.Running, state.Total)
	}
	if state.Restarting > 0 || state.Paused > 0 {
		return "degraded", fmt.Sprintf("restarting=%d paused=%d", state.Restarting, state.Paused)
	}
	if state.Exited > 0 || state.Dead > 0 {
		return "down", fmt.Sprintf("exited=%d dead=%d", state.Exited, state.Dead)
	}
	return "unknown", fmt.Sprintf("created=%d total=%d", state.Created, state.Total)
}

func (c *SystemHealthChecker) RestartService(ctx context.Context, serviceName string) (string, error) {
	target, allowed, reason := c.restartTarget(strings.TrimSpace(serviceName))
	if !allowed {
		return "", fmt.Errorf("%w: %s", errRestartNotAllowed, reason)
	}
	if !c.restartEnabled {
		return "", fmt.Errorf("%w: restart endpoint is disabled", errRestartUnavailable)
	}
	if c.restartHTTP == nil {
		return "", fmt.Errorf("%w: docker restart client is not configured", errRestartUnavailable)
	}
	if _, statErr := os.Stat(c.dockerSockPath); statErr != nil {
		return "", fmt.Errorf("%w: docker socket unavailable at %s", errRestartUnavailable, c.dockerSockPath)
	}
	containerID, err := c.findComposeContainer(ctx, target)
	if err != nil {
		return "", err
	}
	if err := c.restartContainer(ctx, containerID); err != nil {
		return "", err
	}
	return target, nil
}

func (c *SystemHealthChecker) isRestartAllowed(serviceName string) (bool, string) {
	_, ok, reason := c.restartTarget(serviceName)
	return ok, reason
}

func (c *SystemHealthChecker) restartTarget(serviceName string) (string, bool, string) {
	name := strings.ToLower(strings.TrimSpace(serviceName))
	if name == "" {
		return "", false, "service name is required"
	}
	target := serviceNameToComposeService(name)
	if target == "" {
		return "", false, "service is not managed by compose restart controls"
	}
	if blockedReason, blocked := c.restartBlockMap[target]; blocked {
		return "", false, "restart blocked for " + blockedReason
	}
	return target, true, ""
}

func serviceNameToComposeService(name string) string {
	switch name {
	case "postgresql":
		return "postgres"
	case "nats jetstream":
		return "nats"
	case "valkey":
		return "valkey"
	case "consul":
		return "consul"
	case "etcd":
		return "etcd"
	case "dashboard":
		return "dashboard"
	case "envoy":
		return "envoy"
	}
	if strings.HasPrefix(name, "kms-") {
		raw := strings.TrimPrefix(name, "kms-")
		switch raw {
		case "hyok-proxy":
			return "hyok"
		default:
			return raw
		}
	}
	return ""
}

type dockerContainerItem struct {
	ID    string            `json:"Id"`
	State string            `json:"State"`
	Label map[string]string `json:"Labels"`
}

func (c *SystemHealthChecker) findComposeContainer(ctx context.Context, composeService string) (string, error) {
	filters := map[string][]string{
		"label": {
			"com.docker.compose.project=" + c.composeProject,
			"com.docker.compose.service=" + composeService,
		},
	}
	rawFilters, err := json.Marshal(filters)
	if err != nil {
		return "", fmt.Errorf("%w: failed to encode docker filters", errRestartFailed)
	}
	path := "http://docker/containers/json?all=1&filters=" + url.QueryEscape(string(rawFilters))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", fmt.Errorf("%w: failed to build docker query", errRestartFailed)
	}
	resp, err := c.restartHTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: failed to query docker containers", errRestartUnavailable)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: docker query failed (%d): %s", errRestartFailed, resp.StatusCode, bodySnippet(resp.Body))
	}

	var items []dockerContainerItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return "", fmt.Errorf("%w: failed to decode docker response", errRestartFailed)
	}
	if len(items) == 0 {
		return "", fmt.Errorf("%w: container for service %s not found", errRestartUnavailable, composeService)
	}

	for _, item := range items {
		if strings.EqualFold(item.State, "running") && strings.TrimSpace(item.ID) != "" {
			return strings.TrimSpace(item.ID), nil
		}
	}
	if strings.TrimSpace(items[0].ID) == "" {
		return "", fmt.Errorf("%w: container id is empty for service %s", errRestartFailed, composeService)
	}
	return strings.TrimSpace(items[0].ID), nil
}

func (c *SystemHealthChecker) restartContainer(ctx context.Context, containerID string) error {
	path := fmt.Sprintf("http://docker/containers/%s/restart?t=15", url.PathEscape(containerID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("%w: failed to build docker restart request", errRestartFailed)
	}
	resp, err := c.restartHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%w: failed to call docker restart API", errRestartUnavailable)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		return fmt.Errorf("%w: docker restart failed (%d): %s", errRestartFailed, resp.StatusCode, bodySnippet(resp.Body))
	}
	return nil
}

func bodySnippet(body io.Reader) string {
	if body == nil {
		return ""
	}
	raw, err := io.ReadAll(io.LimitReader(body, 256))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}
