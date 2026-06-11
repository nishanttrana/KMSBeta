package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RequestAuthorizer attaches credentials to an outbound request. It is
// satisfied by *agentauth.Provider, so customer-side agents reuse their
// existing mTLS/JWT/API-key auth for audit emission.
type RequestAuthorizer interface {
	ApplyAuth(req *http.Request) error
}

// HTTPEmitter emits canonical audit events over the audit service's
// authenticated HTTP ingest (POST /audit/publish). It is the sanctioned
// path for customer-side agents and external integrations that cannot
// reach NATS; in-cluster services use Client instead. Both produce the
// same Event wire schema, so downstream consumers see one event shape
// regardless of origin.
type HTTPEmitter struct {
	baseURL string
	service string
	agentID string
	client  *http.Client
	auth    RequestAuthorizer
}

// NewHTTPEmitter creates an emitter targeting the audit service at baseURL
// (e.g. "https://kms.example.com/svc/audit"). client may be nil for a
// default TLS client; auth may be nil when the transport itself carries
// credentials (pure mTLS).
func NewHTTPEmitter(baseURL string, service string, agentID string, client *http.Client, auth RequestAuthorizer) (*HTTPEmitter, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, errors.New("audit: base URL is required")
	}
	service = strings.ToLower(strings.TrimSpace(service))
	if service == "" {
		return nil, errors.New("audit: service name is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &HTTPEmitter{
		baseURL: baseURL,
		service: service,
		agentID: strings.TrimSpace(agentID),
		client:  client,
		auth:    auth,
	}, nil
}

// Emit publishes one audit event with Origin "agent". The subject is derived
// exactly as Client.Emit derives it, so agent events land in the same
// audit.<service>.<action> namespace.
func (e *HTTPEmitter) Emit(ctx context.Context, action string, evt Event) error {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		return errors.New("audit: action is required")
	}
	evt.Service = e.service
	evt.Action = fmt.Sprintf("audit.%s.%s", e.service, action)
	if evt.Result == "" {
		evt.Result = "success"
	}
	evt.Origin = "agent"
	if evt.AgentID == "" {
		evt.AgentID = e.agentID
	}
	if evt.ActorType == "" {
		evt.ActorType = "agent"
	}
	if evt.Timestamp == "" {
		evt.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	body, err := json.Marshal(map[string]interface{}{
		"subject": evt.Action,
		"event":   evt,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL+"/audit/publish", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if evt.TenantID != "" {
		req.Header.Set("X-Tenant-ID", evt.TenantID)
	}
	if e.auth != nil {
		if err := e.auth.ApplyAuth(req); err != nil {
			return fmt.Errorf("audit: apply auth: %w", err)
		}
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("audit: publish returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}
