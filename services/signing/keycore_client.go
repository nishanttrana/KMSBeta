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

func (c *HTTPKeyCoreClient) Sign(ctx context.Context, keyID string, req KeyCoreSignRequest) (KeyCoreSignResponse, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return KeyCoreSignResponse{}, errors.New("keycore base url is empty")
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return KeyCoreSignResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/keys/"+strings.TrimSpace(keyID)+"/sign", bytes.NewReader(payload))
	if err != nil {
		return KeyCoreSignResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return KeyCoreSignResponse{}, err
	}
	defer resp.Body.Close() //nolint:errcheck
	var out struct {
		Signature string `json:"signature"`
		Version   int    `json:"version"`
		KeyID     string `json:"key_id"`
		Error     *struct {
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return KeyCoreSignResponse{}, err
	}
	if resp.StatusCode >= 400 {
		if out.Error != nil && strings.TrimSpace(out.Error.Message) != "" {
			return KeyCoreSignResponse{}, errors.New(out.Error.Message)
		}
		return KeyCoreSignResponse{}, fmt.Errorf("key sign failed (%d)", resp.StatusCode)
	}
	return KeyCoreSignResponse{SignatureB64: strings.TrimSpace(out.Signature), Version: out.Version, KeyID: firstNonEmpty(out.KeyID, keyID)}, nil
}

func (c *HTTPKeyCoreClient) Verify(ctx context.Context, keyID string, req KeyCoreVerifyRequest) (KeyCoreVerifyResponse, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return KeyCoreVerifyResponse{}, errors.New("keycore base url is empty")
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return KeyCoreVerifyResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/keys/"+strings.TrimSpace(keyID)+"/verify", bytes.NewReader(payload))
	if err != nil {
		return KeyCoreVerifyResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(httpReq)
	if err != nil {
		return KeyCoreVerifyResponse{}, err
	}
	defer resp.Body.Close() //nolint:errcheck
	var out struct {
		Verified bool `json:"verified"`
		Error    *struct {
			Message string `json:"message"`
		} `json:"error,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return KeyCoreVerifyResponse{}, err
	}
	if resp.StatusCode >= 400 {
		if out.Error != nil && strings.TrimSpace(out.Error.Message) != "" {
			return KeyCoreVerifyResponse{}, errors.New(out.Error.Message)
		}
		return KeyCoreVerifyResponse{}, fmt.Errorf("key verify failed (%d)", resp.StatusCode)
	}
	return KeyCoreVerifyResponse{Valid: out.Verified}, nil
}
