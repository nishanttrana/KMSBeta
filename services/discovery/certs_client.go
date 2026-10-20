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
		return []map[string]interface{}{}, nil
	}
	items := make([]map[string]interface{}, 0, certsPageMax)
	for offset := 0; ; offset += certsPageMax {
		q := url.Values{}
		q.Set("tenant_id", strings.TrimSpace(tenantID))
		q.Set("limit", strconv.Itoa(certsPageMax))
		q.Set("offset", strconv.Itoa(offset))
		out, err := c.doJSON(ctx, "/certs?"+q.Encode())
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

func (c *HTTPCertsClient) doJSON(ctx context.Context, path string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
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
