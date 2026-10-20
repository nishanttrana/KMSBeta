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

// certsPageMax is the most rows one GET /certs answers.
const certsPageMax = 500

// AllCertificates reads every certificate of the tenant, a page at a time.
// A single request for more than 500 rows came back with 100 and no error,
// so this service saw only the newest 100 certificates (13.24.0-beta).
func (c *HTTPCertsClient) AllCertificates(ctx context.Context, tenantID string) ([]map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return []map[string]interface{}{}, errors.New("certs base url is empty")
	}
	items := make([]map[string]interface{}, 0, certsPageMax)
	for offset := 0; ; offset += certsPageMax {
		q := url.Values{}
		q.Set("tenant_id", strings.TrimSpace(tenantID))
		q.Set("limit", strconv.Itoa(certsPageMax))
		q.Set("offset", strconv.Itoa(offset))
		out, err := c.doJSON(ctx, http.MethodGet, "/certs?"+q.Encode())
		if err != nil {
			return nil, err
		}
		rawItems, _ := out["items"].([]interface{})
		for _, it := range rawItems {
			if m, ok := it.(map[string]interface{}); ok {
				items = append(items, m)
			}
		}
		if len(rawItems) < certsPageMax {
			return items, nil
		}
	}
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
