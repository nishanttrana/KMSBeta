package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"vecta-kms/pkg/servicetoken"
)

type PolicyClient interface {
	AllPolicies(ctx context.Context, tenantID string) ([]map[string]interface{}, error)
}

type HTTPPolicyClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPPolicyClient(baseURL string, timeout time.Duration) *HTTPPolicyClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPPolicyClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

// policyPageMax is the most rows one GET /policies answers.
const policyPageMax = 1000

// AllPolicies reads every policy of the tenant, a page at a time. One
// request for 2000 came back with 100 rows and no error, so the assessment
// saw only the newest 100 policies (13.24.0-beta).
func (c *HTTPPolicyClient) AllPolicies(ctx context.Context, tenantID string) ([]map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, errors.New("policy base url is empty")
	}
	items := make([]map[string]interface{}, 0)
	for offset := 0; ; offset += policyPageMax {
		q := url.Values{}
		q.Set("tenant_id", strings.TrimSpace(tenantID))
		q.Set("limit", strconvItoa(policyPageMax))
		q.Set("offset", strconvItoa(offset))
		out, err := c.doJSON(ctx, http.MethodGet, "/policies?"+q.Encode())
		if err != nil {
			return nil, err
		}
		rawItems, _ := out["items"].([]interface{})
		for _, it := range rawItems {
			if m, ok := it.(map[string]interface{}); ok {
				items = append(items, m)
			}
		}
		if len(rawItems) < policyPageMax {
			return items, nil
		}
	}
}

func (c *HTTPPolicyClient) doJSON(ctx context.Context, method string, path string) (map[string]interface{}, error) {
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
		return nil, errors.New(extractErrorMessage(out))
	}
	return out, nil
}
