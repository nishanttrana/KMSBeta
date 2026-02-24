package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type keycoreHTTPError struct {
	Status  int
	Code    string
	Message string
}

func (e keycoreHTTPError) Error() string {
	if strings.TrimSpace(e.Message) != "" {
		return strings.TrimSpace(e.Message)
	}
	return "keycore request failed"
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

func (c *HTTPKeyCoreClient) GetKey(ctx context.Context, tenantID string, keyID string) (map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, errors.New("keycore base url is not configured")
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
		return nil, parseKeycoreError(resp.StatusCode, out)
	}
	item, _ := out["key"].(map[string]interface{})
	if item == nil {
		return map[string]interface{}{}, nil
	}
	return item, nil
}

func (c *HTTPKeyCoreClient) MeterUsage(ctx context.Context, tenantID string, keyID string, operation string) error {
	if strings.TrimSpace(c.baseURL) == "" {
		return errors.New("keycore base url is not configured")
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	payload, err := json.Marshal(map[string]interface{}{
		"operation": strings.TrimSpace(operation),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/keys/"+url.PathEscape(strings.TrimSpace(keyID))+"/usage/meter?"+q.Encode(),
		bytes.NewReader(payload),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	out := map[string]interface{}{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return parseKeycoreError(resp.StatusCode, out)
	}
	return nil
}

func parseKeycoreError(status int, out map[string]interface{}) error {
	errAny, ok := out["error"]
	if !ok {
		return keycoreHTTPError{Status: status, Message: "keycore request failed"}
	}
	errMap, ok := errAny.(map[string]interface{})
	if !ok {
		return keycoreHTTPError{Status: status, Message: "keycore request failed"}
	}
	return keycoreHTTPError{
		Status:  status,
		Code:    firstString(errMap["code"]),
		Message: firstString(errMap["message"]),
	}
}
