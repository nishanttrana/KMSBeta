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

type HTTPKeyCoreClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPKeyCoreClient(baseURL string, timeout time.Duration) *HTTPKeyCoreClient {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &HTTPKeyCoreClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPKeyCoreClient) CreateKey(ctx context.Context, req KeyCoreCreateKeyRequest) (KeyCoreCreateKeyResponse, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return KeyCoreCreateKeyResponse{}, errors.New("keycore base url is empty")
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return KeyCoreCreateKeyResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/keys", bytes.NewReader(raw))
	if err != nil {
		return KeyCoreCreateKeyResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return KeyCoreCreateKeyResponse{}, err
	}
	defer resp.Body.Close() //nolint:errcheck
	var out struct {
		KeyID     string `json:"key_id"`
		TenantID  string `json:"tenant_id"`
		KCV       string `json:"kcv"`
		RequestID string `json:"request_id"`
		Error     *struct {
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return KeyCoreCreateKeyResponse{}, err
	}
	if resp.StatusCode >= 400 {
		if out.Error != nil && strings.TrimSpace(out.Error.Message) != "" {
			return KeyCoreCreateKeyResponse{}, errors.New(strings.TrimSpace(out.Error.Message))
		}
		return KeyCoreCreateKeyResponse{}, fmt.Errorf("key creation failed (%d)", resp.StatusCode)
	}
	return KeyCoreCreateKeyResponse{
		KeyID:     strings.TrimSpace(out.KeyID),
		TenantID:  strings.TrimSpace(out.TenantID),
		KCV:       strings.TrimSpace(out.KCV),
		RequestID: strings.TrimSpace(out.RequestID),
	}, nil
}
