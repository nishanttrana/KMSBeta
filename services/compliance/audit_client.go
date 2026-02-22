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

type AuditClient interface {
	ListEvents(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
	AlertStats(ctx context.Context, tenantID string) (map[string]interface{}, error)
}

type HTTPAuditClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPAuditClient(baseURL string, timeout time.Duration) *HTTPAuditClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPAuditClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPAuditClient) ListEvents(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	q.Set("limit", strconvItoa(limit))
	out, err := c.doJSON(ctx, http.MethodGet, "/audit/events?"+q.Encode())
	if err != nil {
		return nil, err
	}
	rawItems, ok := out["items"].([]interface{})
	if !ok {
		return []map[string]interface{}{}, nil
	}
	items := make([]map[string]interface{}, 0, len(rawItems))
	for _, it := range rawItems {
		m, ok := it.(map[string]interface{})
		if !ok {
			continue
		}
		items = append(items, m)
	}
	return items, nil
}

func (c *HTTPAuditClient) AlertStats(ctx context.Context, tenantID string) (map[string]interface{}, error) {
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	out, err := c.doJSON(ctx, http.MethodGet, "/alerts/stats?"+q.Encode())
	if err != nil {
		return map[string]interface{}{}, err
	}
	stats, ok := out["stats"].(map[string]interface{})
	if ok {
		return stats, nil
	}
	alerts, ok := out["alerts"].(map[string]interface{})
	if ok {
		return alerts, nil
	}
	return map[string]interface{}{}, nil
}

func (c *HTTPAuditClient) doJSON(ctx context.Context, method string, path string) (map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, errors.New("audit base url is empty")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
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
	return out, nil
}
