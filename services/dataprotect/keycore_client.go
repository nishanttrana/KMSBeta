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

type HTTPKeyCoreClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPKeyCoreClient(baseURL string, timeout time.Duration) *HTTPKeyCoreClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPKeyCoreClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPKeyCoreClient) GetKey(ctx context.Context, tenantID string, keyID string) (map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return map[string]interface{}{}, nil
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/keys/"+url.PathEscape(strings.TrimSpace(keyID))+"?"+q.Encode(), nil)
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
		return nil, errors.New(sanitizeErrorMessage(out))
	}
	item, _ := out["key"].(map[string]interface{})
	if item == nil {
		return map[string]interface{}{}, nil
	}
	return item, nil
}
