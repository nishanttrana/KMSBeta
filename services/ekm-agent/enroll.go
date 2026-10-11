package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// clientKeyHeader carries the client key on every check-in.
const clientKeyHeader = "X-EKM-Client-Key"

// kmsTLSConfig is the TLS configuration for calls to the KMS: TLS 1.3, and
// the given PEM bundle as the roots when a KMS uses its internal CA.
func kmsTLSConfig(caPath string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if strings.TrimSpace(caPath) == "" {
		return cfg, nil
	}
	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("no certificate found in the CA bundle")
	}
	cfg.RootCAs = pool
	return cfg, nil
}

// registrationTenant reads the tenant a registration token was issued in
// ("vekm-reg.<tenant>.<client>.<secret>").
func registrationTenant(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "vekm-reg" {
		return "", errors.New("the token file does not hold a registration token")
	}
	tenant, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(tenant) == 0 {
		return "", errors.New("the token file does not hold a registration token")
	}
	return string(tenant), nil
}

// Enroll registers this host with the KMS. It presents the one-time
// registration token from tokenFile, and writes the client key the KMS
// answers with into the agent config (mode 0600), keeping any database
// settings already there. The token file is removed: the token is spent.
// It returns the client's name.
func Enroll(ctx context.Context, server, tokenFile, caPath, configPath string) (string, error) {
	server = strings.TrimRight(strings.TrimSpace(server), "/")
	if !strings.HasPrefix(server, "https://") {
		return "", errors.New("-server must be the KMS EKM endpoint, https://<host>/svc/ekm")
	}
	if strings.TrimSpace(tokenFile) == "" {
		return "", errors.New("-token-file is required")
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	tenant, err := registrationTenant(token)
	if err != nil {
		return "", err
	}
	tlsCfg, err := kmsTLSConfig(caPath)
	if err != nil {
		return "", err
	}
	hostname, _ := os.Hostname()
	body, _ := json.Marshal(map[string]string{"tenant_id": tenant, "token": token, "version": agentVersion(), "host": hostname})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, joinURL(server, "/ekm/clients/enroll"), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck
	var out struct {
		Client struct {
			ID                   string `json:"id"`
			Name                 string `json:"name"`
			DBEngine             string `json:"db_engine"`
			Host                 string `json:"host"`
			HeartbeatIntervalSec int    `json:"heartbeat_interval_sec"`
		} `json:"client"`
		TenantID    string `json:"tenant_id"`
		ClientKey   string `json:"client_key"`
		CheckInPath string `json:"check_in_path"`
		Error       struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the KMS refused the registration (%d %s): %s", resp.StatusCode, out.Error.Code, out.Error.Message)
	}
	if out.ClientKey == "" || out.Client.ID == "" || out.CheckInPath == "" {
		return "", errors.New("the KMS answered without a client key")
	}

	// Keep what an operator already configured (database DSN, intervals).
	var cfg AgentConfig
	if existing, err := os.ReadFile(configPath); err == nil {
		_ = json.Unmarshal(existing, &cfg)
	}
	cfg.TenantID, cfg.AgentID, cfg.AgentName = out.TenantID, out.Client.ID, out.Client.Name
	cfg.DBEngine, cfg.AgentMode = out.Client.DBEngine, ""
	cfg.Host = firstNonEmpty(out.Client.Host, hostname)
	cfg.APIBaseURL, cfg.HeartbeatPath = server, out.CheckInPath
	cfg.ClientKey, cfg.CAPath = out.ClientKey, strings.TrimSpace(caPath)
	cfg.HeartbeatIntervalSec = maxInt(out.Client.HeartbeatIntervalSec, 30)
	// The client key replaces any auth-service credential.
	cfg.AuthToken, cfg.APIKey, cfg.JWTEndpoint, cfg.RegisterPath = "", "", "", ""
	if err := writeConfig(configPath, cfg); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}
	if err := os.Remove(tokenFile); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not remove the used token file %s: %v\n", tokenFile, err)
	}
	return out.Client.Name, nil
}

// writeConfig writes the config so that it is never readable by others, and
// never half-written.
func writeConfig(path string, cfg AgentConfig) error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// CreateTemp creates the file with mode 0600.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agent-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close() //nolint:errcheck
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
