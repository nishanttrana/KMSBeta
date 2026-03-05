package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/agentauth"
)

// KMSClient provides HTTP access to the Vecta KMS EKM endpoints.
type KMSClient struct {
	baseURL string
	auth    *agentauth.Provider
	http    *http.Client
}

func NewKMSClient(cfg ProviderConfig) (*KMSClient, error) {
	authCfg := agentauth.Config{
		MTLSCertPath: cfg.MTLSCertPath,
		MTLSKeyPath:  cfg.MTLSKeyPath,
		MTLSCAPath:   cfg.MTLSCAPath,
		APIKey:       cfg.APIKey,
		JWTEndpoint:  cfg.JWTEndpoint,
		AuthToken:    cfg.AuthToken,
		TenantID:     cfg.TenantID,
	}
	auth, err := agentauth.New(authCfg)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: auth init: %w", err)
	}

	transport := &http.Transport{}
	if auth.HasMTLS() {
		transport.TLSClientConfig = auth.TLSConfig()
	}

	return &KMSClient{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		auth:    auth,
		http: &http.Client{
			Timeout:   15 * time.Second,
			Transport: transport,
		},
	}, nil
}

// ListKeys returns all keys visible to this tenant.
func (c *KMSClient) ListKeys(ctx context.Context) ([]KeyObject, error) {
	url := c.baseURL + "/ekm/tde/keys"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	_ = c.auth.ApplyAuth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list keys: status %d", resp.StatusCode)
	}

	var result struct {
		Keys []struct {
			KeyID        string `json:"key_id"`
			Label        string `json:"label"`
			Algorithm    string `json:"algorithm"`
			KeySize      int    `json:"key_size"`
			Exportable   bool   `json:"export_allowed"`
			Version      int    `json:"version"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	objects := make([]KeyObject, len(result.Keys))
	for i, k := range result.Keys {
		objects[i] = KeyObject{
			ObjectHandle: uint64(i + 1),
			KeyID:        k.KeyID,
			Label:        k.Label,
			Algorithm:    k.Algorithm,
			KeySize:      k.KeySize,
			Exportable:   k.Exportable,
			Version:      k.Version,
		}
	}
	return objects, nil
}

// ExportKey exports key material (if exportable).
func (c *KMSClient) ExportKey(ctx context.Context, keyID string) (material []byte, algorithm string, version int, err error) {
	url := fmt.Sprintf("%s/ekm/tde/keys/%s/export", c.baseURL, keyID)
	body := fmt.Sprintf(`{"tenant_id":"%s","purpose":"pkcs11_cache"}`, c.auth.AuthMethod())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	_ = c.auth.ApplyAuth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", 0, fmt.Errorf("export key: status %d", resp.StatusCode)
	}

	var result struct {
		Material  string `json:"material"`
		Algorithm string `json:"algorithm"`
		Version   int    `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, "", 0, err
	}
	return []byte(result.Material), result.Algorithm, result.Version, nil
}

// Wrap encrypts plaintext using a KMS key (remote operation).
func (c *KMSClient) Wrap(ctx context.Context, keyID string, plaintext []byte) (ciphertext []byte, iv []byte, err error) {
	url := fmt.Sprintf("%s/ekm/tde/keys/%s/wrap", c.baseURL, keyID)
	payload := fmt.Sprintf(`{"plaintext":"%s"}`, string(plaintext))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	_ = c.auth.ApplyAuth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Ciphertext string `json:"ciphertext"`
		IV         string `json:"iv"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, err
	}
	return []byte(result.Ciphertext), []byte(result.IV), nil
}

// Unwrap decrypts ciphertext using a KMS key (remote operation).
func (c *KMSClient) Unwrap(ctx context.Context, keyID string, ciphertext, iv []byte) ([]byte, error) {
	url := fmt.Sprintf("%s/ekm/tde/keys/%s/unwrap", c.baseURL, keyID)
	payload := fmt.Sprintf(`{"ciphertext":"%s","iv":"%s"}`, string(ciphertext), string(iv))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	_ = c.auth.ApplyAuth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return []byte(result.Plaintext), nil
}

// Sign signs data using a KMS key (always remote for asymmetric ops).
func (c *KMSClient) Sign(ctx context.Context, keyID string, data []byte, algorithm string) ([]byte, error) {
	url := fmt.Sprintf("%s/ekm/tde/keys/%s/sign", c.baseURL, keyID)
	payload := fmt.Sprintf(`{"data":"%s","algorithm":"%s"}`, string(data), algorithm)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	_ = c.auth.ApplyAuth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return []byte(result.Signature), nil
}

// Verify verifies a signature using a KMS key (always remote).
func (c *KMSClient) Verify(ctx context.Context, keyID string, data, signature []byte, algorithm string) (bool, error) {
	url := fmt.Sprintf("%s/ekm/tde/keys/%s/verify", c.baseURL, keyID)
	payload := fmt.Sprintf(`{"data":"%s","signature":"%s","algorithm":"%s"}`, string(data), string(signature), algorithm)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	_ = c.auth.ApplyAuth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var result struct {
		Valid bool `json:"valid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}
	return result.Valid, nil
}
