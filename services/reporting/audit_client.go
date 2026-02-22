package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

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
	if strings.TrimSpace(c.baseURL) == "" {
		return []map[string]interface{}{}, nil
	}
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	q.Set("limit", strconv.Itoa(limit))
	out, err := c.doJSON(ctx, "/audit/events?"+q.Encode())
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

func (c *HTTPAuditClient) GetEvent(ctx context.Context, tenantID string, id string) (map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return map[string]interface{}{}, nil
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	out, err := c.doJSON(ctx, "/audit/events/"+url.PathEscape(strings.TrimSpace(id))+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	item, _ := out["event"].(map[string]interface{})
	if item == nil {
		return map[string]interface{}{}, nil
	}
	return item, nil
}

func (c *HTTPAuditClient) doJSON(ctx context.Context, path string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
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

func extractErrorMessage(v map[string]interface{}) string {
	errAny, ok := v["error"]
	if !ok {
		return "request failed"
	}
	errMap, ok := errAny.(map[string]interface{})
	if !ok {
		return "request failed"
	}
	msg, _ := errMap["message"].(string)
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return "request failed"
	}
	return msg
}
