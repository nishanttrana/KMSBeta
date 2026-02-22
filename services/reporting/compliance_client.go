package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type HTTPComplianceClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPComplianceClient(baseURL string, timeout time.Duration) *HTTPComplianceClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPComplianceClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPComplianceClient) GetPosture(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return map[string]interface{}{}, nil
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/compliance/posture?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	out := map[string]interface{}{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, errors.New(extractErrorMessage(out))
	}
	posture, _ := out["posture"].(map[string]interface{})
	if posture == nil {
		return map[string]interface{}{}, nil
	}
	return posture, nil
}
