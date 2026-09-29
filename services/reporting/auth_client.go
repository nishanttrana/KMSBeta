package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/servicetoken"
)

// HTTPAuthTenantClient lists tenant IDs from auth as the kms-reporting
// service identity (auth refuses any other caller).
type HTTPAuthTenantClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPAuthTenantClient(baseURL string, timeout time.Duration) *HTTPAuthTenantClient {
	return &HTTPAuthTenantClient{baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"), client: &http.Client{Timeout: timeout}}
}

func (c *HTTPAuthTenantClient) ListTenantIDs(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/internal/tenant-ids", nil)
	if err != nil {
		return nil, err
	}
	servicetoken.Authorize(ctx, req)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth tenant list: status %d", resp.StatusCode)
	}
	var out struct {
		Items []string `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Items, nil
}
