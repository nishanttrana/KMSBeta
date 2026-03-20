package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type AuditClient interface {
	ListEvents(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
}

type HTTPAuditClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewHTTPAuditClient(baseURL string) *HTTPAuditClient {
	return &HTTPAuditClient{
		baseURL:    strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *HTTPAuditClient) ListEvents(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error) {
	if c.baseURL == "" {
		return nil, errors.New("audit base url is not configured")
	}
	if limit <= 0 || limit > 1000 {
		limit = 250
	}
	values := url.Values{}
	values.Set("tenant_id", strings.TrimSpace(tenantID))
	values.Set("limit", fmt.Sprintf("%d", limit))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/audit/events?"+values.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("audit list events failed: status %d", resp.StatusCode)
	}
	var out struct {
		Items []map[string]interface{} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Items, nil
}
