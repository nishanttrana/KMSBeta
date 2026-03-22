package keyaccess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type EvaluateRequest struct {
	TenantID          string                 `json:"tenant_id"`
	Service           string                 `json:"service"`
	Connector         string                 `json:"connector,omitempty"`
	Operation         string                 `json:"operation"`
	KeyID             string                 `json:"key_id,omitempty"`
	ResourceID        string                 `json:"resource_id,omitempty"`
	TargetType        string                 `json:"target_type,omitempty"`
	RequestID         string                 `json:"request_id,omitempty"`
	RequesterID       string                 `json:"requester_id,omitempty"`
	RequesterEmail    string                 `json:"requester_email,omitempty"`
	RequesterIP       string                 `json:"requester_ip,omitempty"`
	JustificationCode string                 `json:"justification_code,omitempty"`
	JustificationText string                 `json:"justification_text,omitempty"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

type EvaluateResponse struct {
	DecisionID         string                 `json:"decision_id"`
	Enabled            bool                   `json:"enabled"`
	Mode               string                 `json:"mode"`
	Action             string                 `json:"action"`
	ApprovalRequired   bool                   `json:"approval_required"`
	ApprovalRequestID  string                 `json:"approval_request_id,omitempty"`
	MatchedRuleID      string                 `json:"matched_rule_id,omitempty"`
	MatchedCode        string                 `json:"matched_code,omitempty"`
	BypassDetected     bool                   `json:"bypass_detected"`
	Reason             string                 `json:"reason,omitempty"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
	Cryptographically  bool                   `json:"cryptographically_verified,omitempty"`
}

type Client interface {
	Evaluate(ctx context.Context, req EvaluateRequest) (EvaluateResponse, error)
}

type HTTPClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPClient(baseURL string, timeout time.Duration) *HTTPClient {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &HTTPClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPClient) Evaluate(ctx context.Context, req EvaluateRequest) (EvaluateResponse, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return EvaluateResponse{}, errors.New("key access base url is empty")
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return EvaluateResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/key-access/evaluate", bytes.NewReader(raw))
	if err != nil {
		return EvaluateResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return EvaluateResponse{}, err
	}
	defer resp.Body.Close() //nolint:errcheck

	var payload struct {
		Result EvaluateResponse `json:"result"`
		Error  struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return EvaluateResponse{}, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		msg := strings.TrimSpace(payload.Error.Message)
		if msg == "" {
			msg = "key access evaluation failed"
		}
		return EvaluateResponse{}, errors.New(msg)
	}
	return payload.Result, nil
}
