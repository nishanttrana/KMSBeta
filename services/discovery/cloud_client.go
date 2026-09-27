package main

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"
)

// CloudClient reads registered cloud accounts and their live KMS key
// inventory from the cloud service (which calls the provider APIs).
type CloudClient interface {
	ListAccounts(ctx context.Context, tenantID string) ([]map[string]interface{}, error)
	Inventory(ctx context.Context, tenantID string, accountID string) ([]map[string]interface{}, error)
}

type HTTPCloudClient struct{ kc *HTTPKeyCoreClient }

func NewHTTPCloudClient(baseURL string, timeout time.Duration) *HTTPCloudClient {
	return &HTTPCloudClient{kc: NewHTTPKeyCoreClient(baseURL, timeout)}
}

func (c *HTTPCloudClient) ListAccounts(ctx context.Context, tenantID string) ([]map[string]interface{}, error) {
	return c.items(ctx, "/cloud/accounts?"+url.Values{"tenant_id": {strings.TrimSpace(tenantID)}}.Encode())
}

func (c *HTTPCloudClient) Inventory(ctx context.Context, tenantID string, accountID string) ([]map[string]interface{}, error) {
	return c.items(ctx, "/cloud/inventory?"+url.Values{"tenant_id": {strings.TrimSpace(tenantID)}, "account_id": {accountID}}.Encode())
}

func (c *HTTPCloudClient) items(ctx context.Context, path string) ([]map[string]interface{}, error) {
	if c.kc.baseURL == "" {
		return nil, errors.New("cloud service URL not configured")
	}
	out, err := c.kc.doJSON(ctx, path)
	if err != nil {
		return nil, err
	}
	raw, _ := out["items"].([]interface{})
	items := make([]map[string]interface{}, 0, len(raw))
	for _, it := range raw {
		if m, ok := it.(map[string]interface{}); ok {
			items = append(items, m)
		}
	}
	return items, nil
}
