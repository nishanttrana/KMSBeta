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

type KeyCoreClient interface {
	CreateAsymmetricKey(ctx context.Context, tenantID string, name string, algorithm string, labels map[string]string) (string, error)
	GetKey(ctx context.Context, tenantID string, keyID string) (map[string]interface{}, error)
	RotateKey(ctx context.Context, tenantID string, keyID string, reason string) (map[string]interface{}, error)
	DestroyKeyImmediately(ctx context.Context, tenantID string, keyID string, keyName string, justification string) error
	Wrap(ctx context.Context, tenantID string, keyID string, plaintextB64 string, ivB64 string, referenceID string) (map[string]interface{}, error)
	Unwrap(ctx context.Context, tenantID string, keyID string, ciphertextB64 string, ivB64 string) (map[string]interface{}, error)
}

type HTTPKeyCoreClient struct {
	baseURL string
	client  *http.Client
}

func NewHTTPKeyCoreClient(baseURL string, timeout time.Duration) *HTTPKeyCoreClient {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &HTTPKeyCoreClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		client:  &http.Client{Timeout: timeout},
	}
}

func (c *HTTPKeyCoreClient) CreateAsymmetricKey(ctx context.Context, tenantID string, name string, algorithm string, labels map[string]string) (string, error) {
	payload := map[string]interface{}{
		"tenant_id":  strings.TrimSpace(tenantID),
		"name":       defaultString(name, "ekm-tde-key"),
		"algorithm":  defaultString(algorithm, DefaultTDEAlgorithm),
		"key_type":   "asymmetric",
		"purpose":    "wrap",
		"owner":      "ekm",
		"iv_mode":    "internal",
		"created_by": "ekm-agent-hub",
		"labels":     labels,
	}
	out, err := c.doJSON(ctx, http.MethodPost, "/keys", payload)
	if err != nil {
		return "", err
	}
	keyID := strings.TrimSpace(firstString(out["key_id"]))
	if keyID == "" {
		return "", errors.New("keycore create response missing key_id")
	}
	return keyID, nil
}

func (c *HTTPKeyCoreClient) GetKey(ctx context.Context, tenantID string, keyID string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "?tenant_id=" + strings.TrimSpace(tenantID)
	out, err := c.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if keyAny, ok := out["key"]; ok {
		if keyMap, ok := keyAny.(map[string]interface{}); ok {
			return keyMap, nil
		}
	}
	return map[string]interface{}{}, nil
}

func (c *HTTPKeyCoreClient) RotateKey(ctx context.Context, tenantID string, keyID string, reason string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "/rotate?tenant_id=" + strings.TrimSpace(tenantID)
	return c.doJSON(ctx, http.MethodPost, path, map[string]interface{}{
		"reason": defaultString(reason, "scheduled-rotation"),
	})
}

func (c *HTTPKeyCoreClient) DestroyKeyImmediately(ctx context.Context, tenantID string, keyID string, keyName string, justification string) error {
	path := "/keys/" + strings.TrimSpace(keyID) + "/destroy?tenant_id=" + strings.TrimSpace(tenantID)
	_, err := c.doJSON(ctx, http.MethodPost, path, map[string]interface{}{
		"mode":               "immediate",
		"confirm_name":       strings.TrimSpace(keyName),
		"justification":      defaultString(strings.TrimSpace(justification), "ekm-agent-delete"),
		"destroy_after_days": 0,
		"checks": map[string]interface{}{
			"no_active_workloads": true,
			"backup_completed":    true,
			"irreversible_ack":    true,
		},
	})
	return err
}

func (c *HTTPKeyCoreClient) Wrap(ctx context.Context, tenantID string, keyID string, plaintextB64 string, ivB64 string, referenceID string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "/wrap?tenant_id=" + strings.TrimSpace(tenantID)
	return c.doJSON(ctx, http.MethodPost, path, map[string]interface{}{
		"tenant_id":    strings.TrimSpace(tenantID),
		"plaintext":    strings.TrimSpace(plaintextB64),
		"iv":           strings.TrimSpace(ivB64),
		"reference_id": strings.TrimSpace(referenceID),
	})
}

func (c *HTTPKeyCoreClient) Unwrap(ctx context.Context, tenantID string, keyID string, ciphertextB64 string, ivB64 string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "/unwrap?tenant_id=" + strings.TrimSpace(tenantID)
	return c.doJSON(ctx, http.MethodPost, path, map[string]interface{}{
		"tenant_id":  strings.TrimSpace(tenantID),
		"ciphertext": strings.TrimSpace(ciphertextB64),
		"iv":         strings.TrimSpace(ivB64),
	})
}

func (c *HTTPKeyCoreClient) doJSON(ctx context.Context, method string, path string, payload interface{}) (map[string]interface{}, error) {
	if strings.TrimSpace(c.baseURL) == "" {
		return nil, errors.New("keycore base url is empty")
	}
	var body []byte
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = raw
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
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
		msg := extractErrorMessage(out)
		if msg == "" {
			msg = "keycore request failed"
		}
		return nil, errors.New(msg)
	}
	return out, nil
}

func extractErrorMessage(v map[string]interface{}) string {
	errAny, ok := v["error"]
	if !ok {
		return ""
	}
	errMap, ok := errAny.(map[string]interface{})
	if !ok {
		return ""
	}
	msg, _ := errMap["message"].(string)
	return strings.TrimSpace(msg)
}
