package clustersync

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type PublishRequest struct {
	TenantID     string                 `json:"tenant_id"`
	ProfileID    string                 `json:"profile_id,omitempty"`
	Component    string                 `json:"component"`
	EntityType   string                 `json:"entity_type"`
	EntityID     string                 `json:"entity_id"`
	Operation    string                 `json:"operation"`
	Payload      map[string]interface{} `json:"payload,omitempty"`
	SourceNodeID string                 `json:"source_node_id,omitempty"`
}

type Publisher interface {
	Publish(ctx context.Context, req PublishRequest) error
}

type noopPublisher struct{}

func (noopPublisher) Publish(_ context.Context, _ PublishRequest) error { return nil }

type HTTPPublisher struct {
	baseURL      string
	profileID    string
	sourceNodeID string
	sharedSecret []byte
	initErr      error
	client       *http.Client
}

func NewHTTPPublisher(baseURL string, profileID string, sourceNodeID string, sharedSecret string, timeout time.Duration) Publisher {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return noopPublisher{}
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	client, initErr := newPublisherHTTPClient(baseURL, timeout)
	return &HTTPPublisher{
		baseURL:      baseURL,
		profileID:    strings.TrimSpace(profileID),
		sourceNodeID: strings.TrimSpace(sourceNodeID),
		sharedSecret: []byte(strings.TrimSpace(sharedSecret)),
		initErr:      initErr,
		client:       client,
	}
}

func (p *HTTPPublisher) Publish(ctx context.Context, req PublishRequest) error {
	if p == nil || strings.TrimSpace(p.baseURL) == "" {
		return nil
	}
	if p.initErr != nil {
		return fmt.Errorf("cluster sync publisher transport init failed: %w", p.initErr)
	}
	tenantID := strings.TrimSpace(req.TenantID)
	component := strings.TrimSpace(req.Component)
	entityType := strings.TrimSpace(req.EntityType)
	entityID := strings.TrimSpace(req.EntityID)
	operation := strings.TrimSpace(req.Operation)
	if tenantID == "" || component == "" || entityType == "" || entityID == "" || operation == "" {
		return errors.New("cluster sync publish requires tenant_id, component, entity_type, entity_id and operation")
	}

	profileID := strings.TrimSpace(req.ProfileID)
	if profileID == "" {
		profileID = p.profileID
	}
	sourceNodeID := strings.TrimSpace(req.SourceNodeID)
	if sourceNodeID == "" {
		sourceNodeID = p.sourceNodeID
	}

	body := map[string]interface{}{
		"tenant_id":   tenantID,
		"component":   component,
		"entity_type": entityType,
		"entity_id":   entityID,
		"operation":   operation,
		"payload":     req.Payload,
	}
	if body["payload"] == nil {
		body["payload"] = map[string]interface{}{}
	}
	if profileID != "" {
		body["profile_id"] = profileID
	}
	if sourceNodeID != "" {
		body["source_node_id"] = sourceNodeID
	}

	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/cluster/sync/events", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Tenant-ID", tenantID)
	if sourceNodeID != "" {
		httpReq.Header.Set("X-Cluster-Source-Node", sourceNodeID)
	}
	if len(p.sharedSecret) > 0 {
		timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
		nonce := randomNonceHex(12)
		signature := BuildSignature(
			p.sharedSecret,
			httpReq.Method,
			httpReq.URL.Path,
			tenantID,
			sourceNodeID,
			timestamp,
			nonce,
			raw,
		)
		httpReq.Header.Set("X-Cluster-Timestamp", timestamp)
		httpReq.Header.Set("X-Cluster-Nonce", nonce)
		httpReq.Header.Set("X-Cluster-Signature", signature)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck

	out := map[string]interface{}{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode < http.StatusBadRequest {
		return nil
	}
	code, message := parseError(out)
	if shouldIgnoreFilteredError(resp.StatusCode, code) {
		return nil
	}
	if strings.TrimSpace(message) == "" {
		message = "request failed"
	}
	return fmt.Errorf("cluster sync publish failed: %s (status=%d code=%s)", message, resp.StatusCode, code)
}

func parseError(payload map[string]interface{}) (string, string) {
	errAny, ok := payload["error"]
	if !ok {
		return "", ""
	}
	errObj, ok := errAny.(map[string]interface{})
	if !ok {
		return "", ""
	}
	code, _ := errObj["code"].(string)
	message, _ := errObj["message"].(string)
	return strings.TrimSpace(code), strings.TrimSpace(message)
}

func shouldIgnoreFilteredError(status int, code string) bool {
	if status == http.StatusConflict && code == "component_not_allowed" {
		return true
	}
	if status == http.StatusConflict && code == "component_blocked" {
		return true
	}
	if status == http.StatusNotFound && code == "not_found" {
		return true
	}
	return false
}

func randomNonceHex(bytesLen int) string {
	if bytesLen <= 0 {
		bytesLen = 12
	}
	raw := make([]byte, bytesLen)
	_, _ = rand.Read(raw)
	return fmt.Sprintf("%x", raw)
}

func newPublisherHTTPClient(baseURL string, timeout time.Duration) (*http.Client, error) {
	client := &http.Client{Timeout: timeout}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(baseURL)), "https://") {
		return client, nil
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: strings.TrimSpace(os.Getenv("CLUSTER_SYNC_TLS_SERVER_NAME")),
	}
	if parseBoolEnv("CLUSTER_SYNC_TLS_INSECURE_SKIP_VERIFY", false) {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
	}
	if caPath := strings.TrimSpace(os.Getenv("CLUSTER_SYNC_TLS_CA_FILE")); caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CLUSTER_SYNC_TLS_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("parse CLUSTER_SYNC_TLS_CA_FILE: invalid PEM")
		}
		tlsCfg.RootCAs = pool
	}
	certFile := strings.TrimSpace(os.Getenv("CLUSTER_SYNC_TLS_CERT_FILE"))
	keyFile := strings.TrimSpace(os.Getenv("CLUSTER_SYNC_TLS_KEY_FILE"))
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, errors.New("both CLUSTER_SYNC_TLS_CERT_FILE and CLUSTER_SYNC_TLS_KEY_FILE are required for mTLS")
		}
		clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load CLUSTER_SYNC_TLS client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{clientCert}
	}
	client.Transport = &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   tlsCfg,
	}
	return client, nil
}

func parseBoolEnv(key string, def bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if raw == "" {
		return def
	}
	switch raw {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return def
	}
}
