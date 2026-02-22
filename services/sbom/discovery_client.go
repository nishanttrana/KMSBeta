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

type HTTPDiscoveryClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPDiscoveryClient(baseURL string, timeout time.Duration) *HTTPDiscoveryClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPDiscoveryClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPDiscoveryClient) ListCryptoAssets(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return []map[string]interface{}{}, nil
	}
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	paths := []string{"/discovery/crypto/assets", "/discovery/assets"}
	var lastErr error
	for _, p := range paths {
		q := url.Values{}
		q.Set("tenant_id", strings.TrimSpace(tenantID))
		q.Set("limit", strconv.Itoa(limit))
		out, err := c.doJSON(ctx, p+"?"+q.Encode())
		if err != nil {
			lastErr = err
			continue
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
	if lastErr != nil {
		return nil, lastErr
	}
	return []map[string]interface{}{}, nil
}

func (c *HTTPDiscoveryClient) doJSON(ctx context.Context, path string) (map[string]interface{}, error) {
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
