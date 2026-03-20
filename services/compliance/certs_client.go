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
)

type CertsClient interface {
	ListCertificates(ctx context.Context, tenantID string, limit int) ([]map[string]interface{}, error)
	GetRenewalSummary(ctx context.Context, tenantID string) (CertRenewalSummary, error)
}

type HTTPCertsClient struct {
	baseURL string
	client  *http.Client
}

type CertRenewalSummary struct {
	ARIEnabled              bool `json:"ari_enabled"`
	RecommendedPollHours    int  `json:"recommended_poll_hours"`
	MissedWindowCount       int  `json:"missed_window_count"`
	EmergencyRotationCount  int  `json:"emergency_rotation_count"`
	DueSoonCount            int  `json:"due_soon_count"`
	NonCompliantCount       int  `json:"non_compliant_count"`
	MassRenewalRiskCount    int  `json:"mass_renewal_risk_count"`
	CADirectedScheduleCount int  `json:"ca_directed_schedule_count"`
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
	q.Set("limit", strconvItoa(limit))
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

func (c *HTTPCertsClient) GetRenewalSummary(ctx context.Context, tenantID string) (CertRenewalSummary, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return CertRenewalSummary{}, errors.New("certs base url is empty")
	}
	q := url.Values{}
	q.Set("tenant_id", strings.TrimSpace(tenantID))
	out, err := c.doJSON(ctx, http.MethodGet, "/certs/renewal-intelligence?"+q.Encode())
	if err != nil {
		return CertRenewalSummary{}, err
	}
	raw, ok := out["summary"].(map[string]interface{})
	if !ok {
		return CertRenewalSummary{}, nil
	}
	summary := CertRenewalSummary{
		ARIEnabled:             boolValue(raw["ari_enabled"]),
		RecommendedPollHours:   intValue(raw["recommended_poll_hours"]),
		MissedWindowCount:      intValue(raw["missed_window_count"]),
		EmergencyRotationCount: intValue(raw["emergency_rotation_count"]),
		DueSoonCount:           intValue(raw["due_soon_count"]),
		NonCompliantCount:      intValue(raw["non_compliant_count"]),
	}
	if items, ok := raw["mass_renewal_risks"].([]interface{}); ok {
		summary.MassRenewalRiskCount = len(items)
	}
	if items, ok := raw["ca_directed_schedule"].([]interface{}); ok {
		summary.CADirectedScheduleCount = len(items)
	}
	return summary, nil
}

func (c *HTTPCertsClient) doJSON(ctx context.Context, method string, path string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
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
		return nil, errors.New(extractErrorMessage(out))
	}
	return out, nil
}

func boolValue(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(strings.TrimSpace(x), "true")
	default:
		return false
	}
}

func intValue(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case int32:
		return int(x)
	case int64:
		return int(x)
	case float64:
		return int(x)
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	default:
		return 0
	}
}
