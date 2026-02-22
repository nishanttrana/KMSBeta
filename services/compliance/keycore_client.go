package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type KeyCoreClient interface {
	ListKeys(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
}

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

func (c *HTTPKeyCoreClient) ListKeys(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, errors.New("keycore base url is empty")
	}
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	q.Set("limit", strconvItoa(limit))
	path := "/keys?" + q.Encode()
	out, err := c.doJSON(ctx, http.MethodGet, path, nil)
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

func (c *HTTPKeyCoreClient) doJSON(ctx context.Context, method string, path string, payload interface{}) (map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, errors.New("base url is empty")
	}
	var bodyReader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
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

func strconvItoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := false
	if v < 0 {
		neg = true
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
