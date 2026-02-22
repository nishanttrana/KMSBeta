package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type governanceApprovalClient struct {
	baseURL string
	client  *http.Client
}

type governanceApprovalInput struct {
	TenantID       string
	KeyID          string
	Operation      string
	PayloadHash    string
	RequesterID    string
	RequesterEmail string
	RequesterIP    string
	PolicyID       string
}

type governanceRequestItem struct {
	ID            string                 `json:"id"`
	Action        string                 `json:"action"`
	Status        string                 `json:"status"`
	TargetDetails map[string]interface{} `json:"target_details"`
}

type governanceAPIError struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func newGovernanceApprovalClient(baseURL string, timeout time.Duration) *governanceApprovalClient {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &governanceApprovalClient{
		baseURL: base,
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *governanceApprovalClient) ensureApproval(ctx context.Context, in governanceApprovalInput) (approved bool, requestID string, err error) {
	if c == nil {
		return false, "", errors.New("governance approvals are not configured")
	}
	tenantID := strings.TrimSpace(in.TenantID)
	if tenantID == "" {
		return false, "", errors.New("tenant_id is required")
	}
	keyID := strings.TrimSpace(in.KeyID)
	if keyID == "" {
		return false, "", errors.New("key_id is required")
	}
	action := "key." + strings.ToLower(strings.TrimSpace(in.Operation))

	items, err := c.listRequests(ctx, tenantID, "approved", keyID)
	if err != nil {
		return false, "", err
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Action), action) && payloadHashOf(item.TargetDetails) == in.PayloadHash {
			return true, item.ID, nil
		}
	}

	items, err = c.listRequests(ctx, tenantID, "pending", keyID)
	if err != nil {
		return false, "", err
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Action), action) && payloadHashOf(item.TargetDetails) == in.PayloadHash {
			return false, item.ID, nil
		}
	}

	body := map[string]interface{}{
		"tenant_id":        tenantID,
		"key_id":           keyID,
		"operation":        strings.TrimSpace(in.Operation),
		"payload_hash":     in.PayloadHash,
		"requester_id":     firstNonEmptyString(in.RequesterID, "keycore"),
		"requester_email":  firstNonEmptyString(in.RequesterEmail, "keycore@vecta.local"),
		"requester_ip":     strings.TrimSpace(in.RequesterIP),
		"callback_service": "",
		"callback_action":  "",
		"callback_payload": map[string]interface{}{
			"service":    "keycore",
			"key_id":     keyID,
			"operation":  strings.TrimSpace(in.Operation),
			"payload_hash": in.PayloadHash,
		},
	}
	if strings.TrimSpace(in.PolicyID) != "" {
		body["policy_id"] = strings.TrimSpace(in.PolicyID)
	}
	var out struct {
		Request struct {
			ID string `json:"id"`
		} `json:"request"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/governance/key-approval", tenantID, body, &out); err != nil {
		return false, "", err
	}
	return false, strings.TrimSpace(out.Request.ID), nil
}

func (c *governanceApprovalClient) listRequests(ctx context.Context, tenantID string, status string, keyID string) ([]governanceRequestItem, error) {
	q := url.Values{}
	q.Set("tenant_id", tenantID)
	q.Set("status", strings.TrimSpace(status))
	q.Set("target_type", "key")
	q.Set("target_id", keyID)
	path := "/governance/requests?" + q.Encode()
	var out struct {
		Items []governanceRequestItem `json:"items"`
	}
	if err := c.doJSON(ctx, http.MethodGet, path, tenantID, nil, &out); err != nil {
		return nil, err
	}
	if out.Items == nil {
		return []governanceRequestItem{}, nil
	}
	return out.Items, nil
}

func (c *governanceApprovalClient) doJSON(ctx context.Context, method string, path string, tenantID string, payload interface{}, out interface{}) error {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr governanceAPIError
		if err := json.Unmarshal(raw, &apiErr); err == nil && apiErr.Error != nil && strings.TrimSpace(apiErr.Error.Message) != "" {
			return errors.New(strings.TrimSpace(apiErr.Error.Message))
		}
		return fmt.Errorf("governance request failed (%d)", resp.StatusCode)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func payloadHashOf(details map[string]interface{}) string {
	if details == nil {
		return ""
	}
	if raw, ok := details["payload_hash"]; ok {
		return strings.TrimSpace(fmt.Sprintf("%v", raw))
	}
	return ""
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
