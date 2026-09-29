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

type HTTPCertsClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPCertsClient(baseURL string, timeout time.Duration) *HTTPCertsClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPCertsClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPCertsClient) ListCertificates(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return []map[string]interface{}{}, errors.New("certs base url is empty")
	}
	if limit <= 0 || limit > 5000 {
		limit = 2000
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	q.Set("limit", strconv.Itoa(limit))
	out, err := c.doJSON(ctx, http.MethodGet, "/certs?"+q.Encode())
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

// EdgeMeasurement reads the external listeners' measured key exchange.
func (c *HTTPCertsClient) EdgeMeasurement(ctx context.Context, tenantID string) ([]ListenerMeasurement, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, errors.New("certs base url is empty")
	}
	q := url.Values{"tenant_id": {strings.TrimSpace(tenantID)}}
	out, err := c.doJSON(ctx, http.MethodGet, "/certs/edge-tls/measurement?"+q.Encode())
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(out["listeners"])
	if err != nil {
		return nil, err
	}
	items := []ListenerMeasurement{}
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	return items, nil
}

func (c *HTTPCertsClient) doJSON(ctx context.Context, method string, path string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
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
		return nil, errors.New(sanitizeErrorMessage(out))
	}
	return out, nil
}
