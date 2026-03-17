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

type HTTPPostureClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPPostureClient(baseURL string, timeout time.Duration) *HTTPPostureClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPPostureClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPPostureClient) ListFindings(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return []map[string]interface{}{}, nil
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	q.Set("limit", strconv.Itoa(max(1, limit)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/posture/findings?"+q.Encode(), nil)
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
	return toMapSlice(out["items"]), nil
}

func (c *HTTPPostureClient) ListActions(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return []map[string]interface{}{}, nil
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	q.Set("limit", strconv.Itoa(max(1, limit)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/posture/actions?"+q.Encode(), nil)
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
	return toMapSlice(out["items"]), nil
}

func toMapSlice(v interface{}) []map[string]interface{} {
	items, ok := v.([]interface{})
	if !ok {
		return []map[string]interface{}{}
	}
	out := make([]map[string]interface{}, 0, len(items))
	for _, raw := range items {
		item, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		out = append(out, item)
	}
	return out
}
