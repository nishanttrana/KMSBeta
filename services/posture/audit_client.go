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
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	return c.listEvents(ctx, tenantID, q)
}

func (c *HTTPAuditClient) ListEventsRange(ctx context.Context, tenantID string, from, to time.Time, offset, limit int) ([]map[string]interface{}, error) {
	q := url.Values{}
	q.Set("order", "asc")
	q.Set("limit", strconv.Itoa(limit))
	q.Set("offset", strconv.Itoa(max(0, offset)))
	if !from.IsZero() {
		q.Set("from", from.UTC().Format(time.RFC3339Nano))
	}
	if !to.IsZero() {
		q.Set("to", to.UTC().Format(time.RFC3339Nano))
	}
	return c.listEvents(ctx, tenantID, q)
}

func (c *HTTPAuditClient) listEvents(ctx context.Context, tenantID string, q url.Values) ([]map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return []map[string]interface{}{}, nil
	}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	out, err := c.doJSON(ctx, "/audit/events?"+q.Encode())
	if err != nil {
		return nil, err
	}
	rawItems, ok := out["items"].([]interface{})
	if !ok {
		return []map[string]interface{}{}, nil
	}
	items := make([]map[string]interface{}, 0, len(rawItems))
	for _, raw := range rawItems {
		item, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		items = append(items, item)
	}
	return items, nil
}

func (c *HTTPAuditClient) doJSON(ctx context.Context, path string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	// Audit requires a verified token; posture reads a tenant's events as
	// its kms-posture service identity.
	servicetoken.Authorize(ctx, req)
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
