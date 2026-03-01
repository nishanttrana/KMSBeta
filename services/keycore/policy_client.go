package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type PolicyEvaluator interface {
	Evaluate(ctx context.Context, req PolicyEvaluateRequest) (PolicyEvaluateResponse, error)
}

type PolicyEvaluateRequest struct {
	TenantID          string         `json:"tenant_id"`
	Operation         string         `json:"operation"`
	KeyID             string         `json:"key_id,omitempty"`
	Algorithm         string         `json:"algorithm,omitempty"`
	Purpose           string         `json:"purpose,omitempty"`
	IVMode            string         `json:"iv_mode,omitempty"`
	OpsTotal          int64          `json:"ops_total,omitempty"`
	OpsLimit          int64          `json:"ops_limit,omitempty"`
	DaysSinceRotation int            `json:"days_since_rotation,omitempty"`
	KeyStatus         string         `json:"key_status,omitempty"`
	Labels            map[string]any `json:"labels,omitempty"`
}

type PolicyEvaluateResponse struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

type allowAllPolicyEvaluator struct{}

func (allowAllPolicyEvaluator) Evaluate(_ context.Context, _ PolicyEvaluateRequest) (PolicyEvaluateResponse, error) {
	return PolicyEvaluateResponse{Decision: "ALLOW", Reason: "policy evaluator disabled"}, nil
}

type HTTPPolicyClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPPolicyClient(baseURL string, timeout time.Duration) *HTTPPolicyClient {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &HTTPPolicyClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPPolicyClient) Evaluate(ctx context.Context, req PolicyEvaluateRequest) (PolicyEvaluateResponse, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return PolicyEvaluateResponse{}, errors.New("policy base url is empty")
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return PolicyEvaluateResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/policy/evaluate", bytes.NewReader(raw))
	if err != nil {
		return PolicyEvaluateResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return PolicyEvaluateResponse{}, err
	}
	defer resp.Body.Close() //nolint:errcheck

	var payload struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
		Error    struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return PolicyEvaluateResponse{}, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		msg := strings.TrimSpace(payload.Error.Message)
		if msg == "" {
			msg = "policy evaluate request failed"
		}
		return PolicyEvaluateResponse{}, errors.New(msg)
	}
	if strings.TrimSpace(payload.Decision) == "" {
		payload.Decision = "ALLOW"
	}
	return PolicyEvaluateResponse{
		Decision: strings.ToUpper(strings.TrimSpace(payload.Decision)),
		Reason:   strings.TrimSpace(payload.Reason),
	}, nil
}

type policyDeniedError struct {
	Reason string
}

func (e policyDeniedError) Error() string {
	if strings.TrimSpace(e.Reason) == "" {
		return "blocked by policy"
	}
	return e.Reason
}
