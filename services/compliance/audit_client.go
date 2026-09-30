package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vecta-kms/pkg/servicetoken"
)

type AuditClient interface {
	ListEvents(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
	AlertStats(ctx context.Context, tenantID string) (map[string]interface{}, error)
}

type HTTPAuditClient struct {
	baseURL      string
	reportingURL string // alert stats live in reporting, not audit
	client       *http.Client
}

func NewHTTPAuditClient(baseURL, reportingURL string, timeout time.Duration) *HTTPAuditClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPAuditClient{
		baseURL:      strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		reportingURL: strings.TrimRight(strings.TrimSpace(reportingURL), "/"),
		client:       &http.Client{Timeout: timeout},
	}
}

func (c *HTTPAuditClient) ListEvents(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	q.Set("limit", strconvItoa(limit))
	out, err := c.doJSON(ctx, http.MethodGet, c.baseURL, "/audit/events?"+q.Encode())
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
	out, err := c.doJSON(ctx, http.MethodGet, c.reportingURL, "/alerts/stats?"+q.Encode())
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

func (c *HTTPAuditClient) doJSON(ctx context.Context, method, base, path string) (map[string]interface{}, error) {
	if base == "" {
		return nil, errors.New("base url is empty")
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, nil)
	if err != nil {
		return nil, err
	}
	// Audit refuses tokenless callers; compliance reads as its own identity.
	servicetoken.Authorize(ctx, req)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	out := map[string]interface{}{}
	decErr := json.NewDecoder(resp.Body).Decode(&out)
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
