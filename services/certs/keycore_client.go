package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type KeyCoreSigner interface {
	EnsureKey(ctx context.Context, tenantID string, requestedRef string, algorithm string, name string) (string, error)
	Sign(ctx context.Context, tenantID string, keyRef string, data []byte) ([]byte, error)
}

type NoopKeyCoreSigner struct{}

func (NoopKeyCoreSigner) EnsureKey(_ context.Context, _ string, requestedRef string, _ string, _ string) (string, error) {
	return strings.TrimSpace(requestedRef), nil
}

func (NoopKeyCoreSigner) Sign(_ context.Context, _ string, _ string, _ []byte) ([]byte, error) {
	return nil, errors.New("keycore signing is not configured")
}

type HTTPKeyCoreSigner struct {
	baseURL string
	client  *http.Client
}

func NewHTTPKeyCoreSigner(baseURL string, timeout time.Duration) *HTTPKeyCoreSigner {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &HTTPKeyCoreSigner{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (h *HTTPKeyCoreSigner) EnsureKey(ctx context.Context, tenantID string, requestedRef string, algorithm string, name string) (string, error) {
	if strings.TrimSpace(requestedRef) != "" {
		return strings.TrimSpace(requestedRef), nil
	}
	if h == nil || h.baseURL == "" {
		return "", errors.New("keycore base url is empty")
	}
	body := map[string]interface{}{
		"tenant_id":  strings.TrimSpace(tenantID),
		"name":       strings.TrimSpace(name),
		"algorithm":  normalizeAlgorithm(algorithm),
		"key_type":   "symmetric",
		"purpose":    "sign",
		"owner":      "kms-certs",
		"iv_mode":    "internal",
		"created_by": "kms-certs",
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+"/keys", bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close() //nolint:errcheck

	var payload struct {
		KeyID string `json:"key_id"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		msg := strings.TrimSpace(payload.Error.Message)
		if msg == "" {
			msg = "keycore create key failed"
		}
		return "", errors.New(msg)
	}
	if strings.TrimSpace(payload.KeyID) == "" {
		return "", errors.New("keycore create key returned empty key_id")
	}
	return strings.TrimSpace(payload.KeyID), nil
}

func (h *HTTPKeyCoreSigner) Sign(ctx context.Context, tenantID string, keyRef string, data []byte) ([]byte, error) {
	if h == nil || h.baseURL == "" {
		return nil, errors.New("keycore base url is empty")
	}
	keyRef = strings.TrimSpace(keyRef)
	if keyRef == "" {
		return nil, errors.New("key_ref is required")
	}
	body := map[string]interface{}{
		"tenant_id": strings.TrimSpace(tenantID),
		"data":      base64.StdEncoding.EncodeToString(data),
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+"/keys/"+keyRef+"/sign", bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	var payload struct {
		Signature string `json:"signature"`
		Error     struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		msg := strings.TrimSpace(payload.Error.Message)
		if msg == "" {
			msg = "keycore sign failed"
		}
		return nil, errors.New(msg)
	}
	sig, err := base64.StdEncoding.DecodeString(payload.Signature)
	if err != nil {
		return nil, err
	}
	return sig, nil
}
