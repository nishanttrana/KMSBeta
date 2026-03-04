package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// QRNGClient draws conditioned quantum random entropy from the QRNG service.
type QRNGClient interface {
	DrawEntropy(ctx context.Context, tenantID string, n int) ([]byte, error)
	IsHealthy(ctx context.Context, tenantID string) bool
}

type HTTPQRNGClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPQRNGClient(baseURL string, timeout time.Duration) *HTTPQRNGClient {
	return &HTTPQRNGClient{
		baseURL: baseURL,
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPQRNGClient) DrawEntropy(ctx context.Context, tenantID string, n int) ([]byte, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"tenant_id": tenantID,
		"bytes":     n,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/qrng/v1/draw", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("qrng draw request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("qrng draw: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("qrng draw status %d: %s", resp.StatusCode, string(raw))
	}

	var envelope struct {
		Result struct {
			EntropyB64 string `json:"entropy"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("qrng draw decode: %w", err)
	}

	if envelope.Result.EntropyB64 == "" {
		return nil, fmt.Errorf("qrng draw: empty entropy response")
	}
	decoded, err := base64.StdEncoding.DecodeString(envelope.Result.EntropyB64)
	if err != nil {
		return nil, fmt.Errorf("qrng draw base64: %w", err)
	}
	return decoded, nil
}

// SetQRNGClient sets the QRNG entropy client on the service.
func (s *Service) SetQRNGClient(client QRNGClient) {
	s.qrng = client
}

func (c *HTTPQRNGClient) IsHealthy(ctx context.Context, tenantID string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL+"/qrng/v1/pool/status?tenant_id="+tenantID, nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-Tenant-ID", tenantID)
	resp, err := c.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var envelope struct {
		Pool struct {
			PoolHealthy bool `json:"pool_healthy"`
		} `json:"pool"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return false
	}
	return envelope.Pool.PoolHealthy
}
