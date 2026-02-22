package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type GovernanceClient interface {
	CreateKeyApproval(ctx context.Context, req GovernanceApprovalRequest) (string, error)
	GetApprovalStatus(ctx context.Context, tenantID string, requestID string) (GovernanceApprovalStatus, error)
}

type HTTPGovernanceClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPGovernanceClient(baseURL string, timeout time.Duration) *HTTPGovernanceClient {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &HTTPGovernanceClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPGovernanceClient) CreateKeyApproval(ctx context.Context, req GovernanceApprovalRequest) (string, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return "", errors.New("governance base url is empty")
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/governance/key-approval", bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck

	out := map[string]interface{}{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		msg := extractErrorMessage(out)
		if msg == "" {
			msg = "governance key approval failed"
		}
		return "", errors.New(msg)
	}
	reqAny, ok := out["request"]
	if !ok {
		return "", errors.New("invalid governance response")
	}
	reqMap, ok := reqAny.(map[string]interface{})
	if !ok {
		return "", errors.New("invalid governance response payload")
	}
	id, _ := reqMap["id"].(string)
	id = strings.TrimSpace(id)
	if id == "" {
		return "", errors.New("approval request id missing")
	}
	return id, nil
}

func (c *HTTPGovernanceClient) GetApprovalStatus(ctx context.Context, tenantID string, requestID string) (GovernanceApprovalStatus, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return GovernanceApprovalStatus{}, errors.New("governance base url is empty")
	}
	path := c.baseURL + "/governance/key-approval/" + strings.TrimSpace(requestID) + "/status?tenant_id=" + strings.TrimSpace(tenantID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return GovernanceApprovalStatus{}, err
	}
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return GovernanceApprovalStatus{}, err
	}
	defer resp.Body.Close() //nolint:errcheck

	var payload struct {
		Status GovernanceApprovalStatus `json:"status"`
		Error  struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return GovernanceApprovalStatus{}, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		msg := strings.TrimSpace(payload.Error.Message)
		if msg == "" {
			msg = "governance status request failed"
		}
		return GovernanceApprovalStatus{}, errors.New(msg)
	}
	return payload.Status, nil
}
