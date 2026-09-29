package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"vecta-kms/pkg/servicetoken"
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

func (c *HTTPKeyCoreClient) ListKeys(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return []map[string]interface{}{}, nil
	}
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	q.Set("limit", strconv.Itoa(limit))
	out, err := c.doJSON(ctx, http.MethodGet, "/keys?"+q.Encode(), nil)
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

var errKeycoreNotConfigured = errors.New("keycore URL not configured")

func (c *HTTPKeyCoreClient) RotateKey(ctx context.Context, tenantID string, keyID string, reason string) error {
	if strings.TrimSpace(c.baseURL) == "" {
		return errKeycoreNotConfigured
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	body := map[string]string{"reason": strings.TrimSpace(reason)}
	_, err := c.doJSON(ctx, http.MethodPost, "/keys/"+url.PathEscape(strings.TrimSpace(keyID))+"/rotate?"+q.Encode(), body)
	return err
}

// CreateKey creates a key in keycore and returns its id.
func (c *HTTPKeyCoreClient) CreateKey(ctx context.Context, tenantID string, req map[string]interface{}) (string, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return "", errKeycoreNotConfigured
	}
	req["tenant_id"] = strings.TrimSpace(tenantID)
	out, err := c.doJSON(ctx, http.MethodPost, "/keys?"+url.Values{"tenant_id": {strings.TrimSpace(tenantID)}}.Encode(), req)
	if err != nil {
		return "", err
	}
	id, _ := out["key_id"].(string)
	if id == "" {
		return "", errors.New("keycore returned no key_id")
	}
	return id, nil
}

// DeactivateKey takes a key out of service in keycore.
func (c *HTTPKeyCoreClient) DeactivateKey(ctx context.Context, tenantID string, keyID string, reason string) error {
	if strings.TrimSpace(c.baseURL) == "" {
		return errKeycoreNotConfigured
	}
	q := url.Values{"tenant_id": {strings.TrimSpace(tenantID)}}
	_, err := c.doJSON(ctx, http.MethodPost, "/keys/"+url.PathEscape(strings.TrimSpace(keyID))+"/deactivate?"+q.Encode(), map[string]string{"reason": reason})
	return err
}

func (c *HTTPKeyCoreClient) doJSON(ctx context.Context, method string, path string, body interface{}) (map[string]interface{}, error) {
	var payload *bytes.Reader
	if body == nil {
		payload = bytes.NewReader(nil)
	} else {
		raw, _ := json.Marshal(body)
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, payload)
	if err != nil {
		return nil, err
	}
	servicetoken.Authorize(ctx, req)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	out := map[string]interface{}{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		if resp.StatusCode >= http.StatusBadRequest {
			return nil, errors.New("request failed")
		}
		return map[string]interface{}{}, nil
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return nil, errors.New(sanitizeErrorMessage(out))
	}
	return out, nil
}
