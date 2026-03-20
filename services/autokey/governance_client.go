package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type HTTPGovernanceClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPGovernanceClient(baseURL string, timeout time.Duration) *HTTPGovernanceClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPGovernanceClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPGovernanceClient) CreateApprovalRequest(ctx context.Context, req GovernanceCreateApprovalRequest) (GovernanceApprovalRequest, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return GovernanceApprovalRequest{}, errors.New("governance base url is empty")
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return GovernanceApprovalRequest{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/governance/requests", bytes.NewReader(raw))
	if err != nil {
		return GovernanceApprovalRequest{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return GovernanceApprovalRequest{}, err
	}
	defer resp.Body.Close() //nolint:errcheck
	var out struct {
		Request GovernanceApprovalRequest `json:"request"`
		Error   *struct {
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return GovernanceApprovalRequest{}, err
	}
	if resp.StatusCode >= 400 {
		if out.Error != nil && strings.TrimSpace(out.Error.Message) != "" {
			return GovernanceApprovalRequest{}, errors.New(strings.TrimSpace(out.Error.Message))
		}
		return GovernanceApprovalRequest{}, fmt.Errorf("governance request failed (%d)", resp.StatusCode)
	}
	return out.Request, nil
}

func (c *HTTPGovernanceClient) GetApprovalRequest(ctx context.Context, tenantID string, requestID string) (GovernanceApprovalRequest, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return GovernanceApprovalRequest{}, errors.New("governance base url is empty")
	}
	path := fmt.Sprintf("%s/governance/requests/%s?tenant_id=%s", c.baseURL, strings.TrimSpace(requestID), strings.TrimSpace(tenantID))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return GovernanceApprovalRequest{}, err
	}
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return GovernanceApprovalRequest{}, err
	}
	defer resp.Body.Close() //nolint:errcheck
	var out struct {
		Request GovernanceApprovalRequest `json:"request"`
		Error   *struct {
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return GovernanceApprovalRequest{}, err
	}
	if resp.StatusCode >= 400 {
		if out.Error != nil && strings.TrimSpace(out.Error.Message) != "" {
			return GovernanceApprovalRequest{}, errors.New(strings.TrimSpace(out.Error.Message))
		}
		return GovernanceApprovalRequest{}, fmt.Errorf("governance read failed (%d)", resp.StatusCode)
	}
	return out.Request, nil
}
