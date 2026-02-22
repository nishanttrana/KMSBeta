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
	CreateKey(ctx context.Context, tenantID string, req CreateRequest) (string, error)
	ImportKey(ctx context.Context, tenantID string, req RegisterRequest) (string, error)
	GetKey(ctx context.Context, tenantID string, keyID string) (map[string]interface{}, error)
	RotateKey(ctx context.Context, tenantID string, keyID string, reason string) (map[string]interface{}, error)
	SetKeyStatus(ctx context.Context, tenantID string, keyID string, status string) error
	Encrypt(ctx context.Context, tenantID string, keyID string, plaintextB64 string, ivB64 string, referenceID string) (map[string]interface{}, error)
	Decrypt(ctx context.Context, tenantID string, keyID string, ciphertextB64 string, ivB64 string) (map[string]interface{}, error)
	Sign(ctx context.Context, tenantID string, keyID string, dataB64 string, algorithm string) (map[string]interface{}, error)
	Verify(ctx context.Context, tenantID string, keyID string, dataB64 string, signatureB64 string, algorithm string) (map[string]interface{}, error)
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

func (c *HTTPKeyCoreClient) CreateKey(ctx context.Context, tenantID string, req CreateRequest) (string, error) {
	payload := map[string]interface{}{
		"tenant_id":          strings.TrimSpace(tenantID),
		"name":               defaultString(req.Name, "kmip-key"),
		"algorithm":          defaultString(req.Algorithm, "AES-256"),
		"key_type":           defaultString(req.KeyType, "symmetric"),
		"purpose":            defaultString(req.Purpose, "encrypt"),
		"owner":              "kmip",
		"iv_mode":            defaultString(req.IVMode, "internal"),
		"created_by":         "kmip-server",
		"ops_limit":          req.OpsLimit,
		"ops_limit_window":   defaultString(req.OpsWindow, "total"),
		"approval_required":  req.ApprovalRequired,
		"approval_policy_id": req.ApprovalPolicyID,
	}
	raw, err := c.doJSON(ctx, http.MethodPost, "/keys", payload)
	if err != nil {
		return "", err
	}
	return stringField(raw, "key_id"), nil
}

func (c *HTTPKeyCoreClient) ImportKey(ctx context.Context, tenantID string, req RegisterRequest) (string, error) {
	payload := map[string]interface{}{
		"tenant_id":    strings.TrimSpace(tenantID),
		"name":         defaultString(req.Name, "kmip-imported-key"),
		"algorithm":    defaultString(req.Algorithm, "AES-256"),
		"key_type":     defaultString(req.KeyType, "symmetric"),
		"purpose":      defaultString(req.Purpose, "encrypt"),
		"owner":        "kmip",
		"iv_mode":      "internal",
		"created_by":   "kmip-server",
		"material":     req.MaterialB64,
		"expected_kcv": req.ExpectedKCV,
	}
	raw, err := c.doJSON(ctx, http.MethodPost, "/keys/import", payload)
	if err != nil {
		return "", err
	}
	return stringField(raw, "key_id"), nil
}

func (c *HTTPKeyCoreClient) GetKey(ctx context.Context, tenantID string, keyID string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "?tenant_id=" + strings.TrimSpace(tenantID)
	raw, err := c.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if keyAny, ok := raw["key"]; ok {
		if keyMap, ok := keyAny.(map[string]interface{}); ok {
			return keyMap, nil
		}
	}
	return map[string]interface{}{}, nil
}

func (c *HTTPKeyCoreClient) RotateKey(ctx context.Context, tenantID string, keyID string, reason string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "/rotate?tenant_id=" + strings.TrimSpace(tenantID)
	raw, err := c.doJSON(ctx, http.MethodPost, path, map[string]interface{}{"reason": reason})
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *HTTPKeyCoreClient) SetKeyStatus(ctx context.Context, tenantID string, keyID string, status string) error {
	tenant := strings.TrimSpace(tenantID)
	key := strings.TrimSpace(keyID)
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "active":
		_, err := c.doJSON(ctx, http.MethodPost, "/keys/"+key+"/activate?tenant_id="+tenant, map[string]interface{}{"mode": "immediate"})
		return err
	case "disabled":
		_, err := c.doJSON(ctx, http.MethodPost, "/keys/"+key+"/disable?tenant_id="+tenant, map[string]interface{}{})
		return err
	case "revoked", "deactivated", "inactive":
		_, err := c.doJSON(ctx, http.MethodPost, "/keys/"+key+"/deactivate?tenant_id="+tenant, map[string]interface{}{})
		return err
	case "destroyed", "destroy-pending", "deleted":
		keyMeta, err := c.GetKey(ctx, tenant, key)
		if err != nil {
			return err
		}
		confirmName, _ := keyMeta["name"].(string)
		if strings.TrimSpace(confirmName) == "" {
			confirmName = key
		}
		_, err = c.doJSON(ctx, http.MethodPost, "/keys/"+key+"/destroy?tenant_id="+tenant, map[string]interface{}{
			"mode":               "immediate",
			"confirm_name":       confirmName,
			"justification":      "kmip destroy",
			"destroy_after_days": 0,
			"checks": map[string]interface{}{
				"no_active_workloads": true,
				"backup_completed":    true,
				"irreversible_ack":    true,
			},
		})
		return err
	default:
		_, err := c.doJSON(ctx, http.MethodPost, "/keys/"+key+"/deactivate?tenant_id="+tenant, map[string]interface{}{})
		return err
	}
}

func (c *HTTPKeyCoreClient) Encrypt(ctx context.Context, tenantID string, keyID string, plaintextB64 string, ivB64 string, referenceID string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "/encrypt"
	raw, err := c.doJSON(ctx, http.MethodPost, path, map[string]interface{}{
		"tenant_id":    tenantID,
		"plaintext":    plaintextB64,
		"iv":           ivB64,
		"reference_id": referenceID,
	})
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *HTTPKeyCoreClient) Decrypt(ctx context.Context, tenantID string, keyID string, ciphertextB64 string, ivB64 string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "/decrypt"
	raw, err := c.doJSON(ctx, http.MethodPost, path, map[string]interface{}{
		"tenant_id":  tenantID,
		"ciphertext": ciphertextB64,
		"iv":         ivB64,
	})
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *HTTPKeyCoreClient) Sign(ctx context.Context, tenantID string, keyID string, dataB64 string, algorithm string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "/sign"
	payload := map[string]interface{}{
		"tenant_id": tenantID,
		"data":      dataB64,
	}
	if strings.TrimSpace(algorithm) != "" {
		payload["algorithm"] = strings.TrimSpace(algorithm)
	}
	raw, err := c.doJSON(ctx, http.MethodPost, path, payload)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func (c *HTTPKeyCoreClient) Verify(ctx context.Context, tenantID string, keyID string, dataB64 string, signatureB64 string, algorithm string) (map[string]interface{}, error) {
	path := "/keys/" + strings.TrimSpace(keyID) + "/verify"
	payload := map[string]interface{}{
		"tenant_id": tenantID,
		"data":      dataB64,
		"signature": signatureB64,
	}
	if strings.TrimSpace(algorithm) != "" {
		payload["algorithm"] = strings.TrimSpace(algorithm)
	}
	raw, err := c.doJSON(ctx, http.MethodPost, path, payload)
	if err != nil {
		return nil, err
	}
	return raw, nil
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

	var decoded map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		msg := errorMessage(decoded)
		if msg == "" {
			msg = "keycore request failed"
		}
		return nil, errors.New(msg)
	}
	return decoded, nil
}

func errorMessage(v map[string]interface{}) string {
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

func stringField(v map[string]interface{}, k string) string {
	out, _ := v[k].(string)
	return strings.TrimSpace(out)
}
