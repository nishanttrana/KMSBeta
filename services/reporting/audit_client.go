package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"vecta-kms/pkg/servicetoken"
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
	// Audit authenticates every read; reporting is a verified service
	// principal there. Without the token the alert sync gets 401 and the
	// Alert Center stays empty.
	servicetoken.Authorize(ctx, req)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	return decodeResponse(resp)
}

// decodeResponse returns the JSON body of a successful response, or an error
// naming the status and the service's message. An error body need not be
// JSON (the JWT gate answers in plain text).
func decodeResponse(resp *http.Response) (map[string]interface{}, error) {
	out := map[string]interface{}{}
	decErr := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&out)
	if resp.StatusCode >= http.StatusBadRequest {
		msg := "request failed"
		if decErr == nil {
			msg = extractErrorMessage(out)
		}
		return nil, fmt.Errorf("%s: %s", resp.Status, msg)
	}
	if decErr != nil {
		return nil, decErr
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
