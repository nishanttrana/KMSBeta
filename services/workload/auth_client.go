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

type AuthClient interface {
	IssueWorkloadToken(ctx context.Context, req AuthWorkloadTokenRequest) (AuthWorkloadTokenResponse, error)
}

type AuthWorkloadTokenRequest struct {
	TenantID            string   `json:"tenant_id"`
	ClientID            string   `json:"client_id"`
	SubjectID           string   `json:"subject_id"`
	InterfaceName       string   `json:"interface_name"`
	Permissions         []string `json:"permissions"`
	AllowedKeyIDs       []string `json:"allowed_key_ids,omitempty"`
	WorkloadTrustDomain string   `json:"workload_trust_domain,omitempty"`
	TTLSeconds          int      `json:"ttl_seconds,omitempty"`
}

type AuthWorkloadTokenResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
	RequestID   string    `json:"request_id"`
}

type HTTPAuthClient struct {
	baseURL      string
	sharedSecret string
	httpClient   *http.Client
}

func NewHTTPAuthClient(baseURL string, sharedSecret string) *HTTPAuthClient {
	return &HTTPAuthClient{
		baseURL:      strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		sharedSecret: strings.TrimSpace(sharedSecret),
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *HTTPAuthClient) IssueWorkloadToken(ctx context.Context, req AuthWorkloadTokenRequest) (AuthWorkloadTokenResponse, error) {
	if c.baseURL == "" {
		return AuthWorkloadTokenResponse{}, errors.New("auth base url is not configured")
	}
	if c.sharedSecret == "" {
		return AuthWorkloadTokenResponse{}, errors.New("workload identity shared secret is not configured")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return AuthWorkloadTokenResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/auth/workload-token", bytes.NewReader(body))
	if err != nil {
		return AuthWorkloadTokenResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Workload-Identity-Secret", c.sharedSecret)
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return AuthWorkloadTokenResponse{}, err
	}
	defer resp.Body.Close()

	var out AuthWorkloadTokenResponse
	if resp.StatusCode >= 400 {
		var failure map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&failure)
		if msg := strings.TrimSpace(toString(failure["message"])); msg != "" {
			return AuthWorkloadTokenResponse{}, fmt.Errorf("auth workload token issuance failed: %s", msg)
		}
		return AuthWorkloadTokenResponse{}, fmt.Errorf("auth workload token issuance failed: status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return AuthWorkloadTokenResponse{}, err
	}
	out.ExpiresAt = parseTimeValue(out.ExpiresAt)
	return out, nil
}
