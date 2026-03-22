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

	var payload struct {
		Request GovernanceApprovalRequest `json:"request"`
		Error   struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return GovernanceApprovalRequest{}, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		msg := strings.TrimSpace(payload.Error.Message)
		if msg == "" {
			msg = "governance approval creation failed"
		}
		return GovernanceApprovalRequest{}, errors.New(msg)
	}
	return payload.Request, nil
}
