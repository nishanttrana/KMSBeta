package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const azureAPIVersion = "7.4"

// AzureEKMProvider implements real Azure Key Vault and Managed HSM REST API calls.
type AzureEKMProvider struct {
	httpClient *http.Client
	logger     *log.Logger
}

func NewAzureEKMProvider(logger *log.Logger) *AzureEKMProvider {
	if logger == nil {
		logger = log.Default()
	}
	return &AzureEKMProvider{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
	}
}

// azureTokenResponse is the OAuth2 token endpoint response from Azure AD.
type azureTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error,omitempty"`
	ErrorDesc   string `json:"error_description,omitempty"`
}

// azureKeyBundle is the response envelope for key operations from Azure Key Vault.
type azureKeyBundle struct {
	Key        map[string]interface{} `json:"key"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// azureKeyListResult is the paginated list response from Azure Key Vault.
type azureKeyListResult struct {
	Value    []map[string]interface{} `json:"value"`
	NextLink string                   `json:"nextLink,omitempty"`
}

// azureKeyOperationResult is the response for wrap/unwrap operations.
type azureKeyOperationResult struct {
	KID   string `json:"kid,omitempty"`
	Value string `json:"value,omitempty"`
}

// azureErrorResponse captures Azure REST API error payloads.
type azureErrorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Authenticate obtains a bearer token from Azure AD using OAuth2 client_credentials grant.
// Endpoint: POST https://login.microsoftonline.com/{azure_tenant_id}/oauth2/v2.0/token
func (p *AzureEKMProvider) Authenticate(cfg AzureEKMConfig) (string, error) {
	if cfg.AuthMode == "managed_identity" {
		return p.authenticateManagedIdentity()
	}

	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(cfg.AzureTenantID))

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", cfg.ClientID)
	data.Set("client_secret", cfg.ClientSecret)
	data.Set("scope", "https://vault.azure.net/.default")

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("azure auth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("azure auth: request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("azure auth: read body: %w", err)
	}

	var tokenResp azureTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("azure auth: decode response: %w", err)
	}

	if resp.StatusCode != http.StatusOK || tokenResp.AccessToken == "" {
		errMsg := tokenResp.ErrorDesc
		if errMsg == "" {
			errMsg = tokenResp.Error
		}
		if errMsg == "" {
			errMsg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return "", fmt.Errorf("azure auth: %s", errMsg)
	}

	p.logger.Printf("[azure-ekm] authenticated for tenant %s", cfg.AzureTenantID)
	return tokenResp.AccessToken, nil
}

// authenticateManagedIdentity obtains a token via the Azure IMDS endpoint for managed identity.
func (p *AzureEKMProvider) authenticateManagedIdentity() (string, error) {
	imdsURL := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=https://vault.azure.net"

	req, err := http.NewRequest("GET", imdsURL, nil)
	if err != nil {
		return "", fmt.Errorf("azure managed identity: build request: %w", err)
	}
	req.Header.Set("Metadata", "true")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("azure managed identity: request failed (not running in Azure?): %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("azure managed identity: read body: %w", err)
	}

	var tokenResp azureTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("azure managed identity: decode response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("azure managed identity: empty token, status %d", resp.StatusCode)
	}
	return tokenResp.AccessToken, nil
}

// ImportKeyToVault imports key material into Azure Key Vault.
// PUT {vaultURL}/keys/{keyName}?api-version=7.4
func (p *AzureEKMProvider) ImportKeyToVault(ctx context.Context, token, vaultURL, keyName string, keyMaterial []byte, keyType string) (string, error) {
	if keyType == "" {
		keyType = "RSA"
	}
	reqURL := fmt.Sprintf("%s/keys/%s?api-version=%s", strings.TrimRight(vaultURL, "/"), url.PathEscape(keyName), azureAPIVersion)

	// Build JWK key import payload
	payload := map[string]interface{}{
		"key": map[string]interface{}{
			"kty":     keyType,
			"key_ops": []string{"encrypt", "decrypt", "wrapKey", "unwrapKey"},
			"k":       base64.RawURLEncoding.EncodeToString(keyMaterial),
		},
	}

	respBody, err := p.doAzureRequest(ctx, "PUT", reqURL, token, payload)
	if err != nil {
		return "", fmt.Errorf("import key to vault: %w", err)
	}

	var bundle azureKeyBundle
	if err := json.Unmarshal(respBody, &bundle); err != nil {
		return "", fmt.Errorf("import key: decode response: %w", err)
	}

	kid, _ := bundle.Key["kid"].(string)
	if kid == "" {
		return "", fmt.Errorf("import key: no kid in response")
	}
	p.logger.Printf("[azure-ekm] imported key %s -> %s", keyName, kid)
	return kid, nil
}

// CreateKeyInVault creates a new key in Azure Key Vault.
// POST {vaultURL}/keys/{keyName}/create?api-version=7.4
func (p *AzureEKMProvider) CreateKeyInVault(ctx context.Context, token, vaultURL, keyName, keyType string, keySize int) (string, error) {
	if keyType == "" {
		keyType = "RSA"
	}
	if keySize == 0 {
		keySize = 2048
	}
	reqURL := fmt.Sprintf("%s/keys/%s/create?api-version=%s", strings.TrimRight(vaultURL, "/"), url.PathEscape(keyName), azureAPIVersion)

	payload := map[string]interface{}{
		"kty":     keyType,
		"key_size": keySize,
		"key_ops": []string{"encrypt", "decrypt", "wrapKey", "unwrapKey", "sign", "verify"},
	}

	respBody, err := p.doAzureRequest(ctx, "POST", reqURL, token, payload)
	if err != nil {
		return "", fmt.Errorf("create key in vault: %w", err)
	}

	var bundle azureKeyBundle
	if err := json.Unmarshal(respBody, &bundle); err != nil {
		return "", fmt.Errorf("create key: decode response: %w", err)
	}

	kid, _ := bundle.Key["kid"].(string)
	if kid == "" {
		return "", fmt.Errorf("create key: no kid in response")
	}
	p.logger.Printf("[azure-ekm] created key %s -> %s", keyName, kid)
	return kid, nil
}

// RotateKeyInVault rotates a key in Azure Key Vault, creating a new version.
// POST {vaultURL}/keys/{keyName}/rotate?api-version=7.4
func (p *AzureEKMProvider) RotateKeyInVault(ctx context.Context, token, vaultURL, keyName string) (string, error) {
	reqURL := fmt.Sprintf("%s/keys/%s/rotate?api-version=%s", strings.TrimRight(vaultURL, "/"), url.PathEscape(keyName), azureAPIVersion)

	respBody, err := p.doAzureRequest(ctx, "POST", reqURL, token, nil)
	if err != nil {
		return "", fmt.Errorf("rotate key in vault: %w", err)
	}

	var bundle azureKeyBundle
	if err := json.Unmarshal(respBody, &bundle); err != nil {
		return "", fmt.Errorf("rotate key: decode response: %w", err)
	}

	kid, _ := bundle.Key["kid"].(string)
	if kid == "" {
		return "", fmt.Errorf("rotate key: no kid in response")
	}
	// Extract version from the kid URI (last path segment)
	parts := strings.Split(kid, "/")
	version := parts[len(parts)-1]
	p.logger.Printf("[azure-ekm] rotated key %s -> version %s", keyName, version)
	return version, nil
}

// GetKeyFromVault retrieves a key from Azure Key Vault.
// GET {vaultURL}/keys/{keyName}?api-version=7.4
func (p *AzureEKMProvider) GetKeyFromVault(ctx context.Context, token, vaultURL, keyName string) (map[string]interface{}, error) {
	reqURL := fmt.Sprintf("%s/keys/%s?api-version=%s", strings.TrimRight(vaultURL, "/"), url.PathEscape(keyName), azureAPIVersion)

	respBody, err := p.doAzureRequest(ctx, "GET", reqURL, token, nil)
	if err != nil {
		return nil, fmt.Errorf("get key from vault: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("get key: decode response: %w", err)
	}
	return result, nil
}

// ListKeysInVault lists all keys in Azure Key Vault with pagination.
// GET {vaultURL}/keys?api-version=7.4
func (p *AzureEKMProvider) ListKeysInVault(ctx context.Context, token, vaultURL string) ([]map[string]interface{}, error) {
	reqURL := fmt.Sprintf("%s/keys?api-version=%s", strings.TrimRight(vaultURL, "/"), azureAPIVersion)

	var allKeys []map[string]interface{}
	for reqURL != "" {
		respBody, err := p.doAzureRequest(ctx, "GET", reqURL, token, nil)
		if err != nil {
			return nil, fmt.Errorf("list keys in vault: %w", err)
		}

		var listResult azureKeyListResult
		if err := json.Unmarshal(respBody, &listResult); err != nil {
			return nil, fmt.Errorf("list keys: decode response: %w", err)
		}

		allKeys = append(allKeys, listResult.Value...)
		reqURL = listResult.NextLink

		// Safety limit to prevent infinite pagination
		if len(allKeys) > 10000 {
			break
		}
	}
	return allKeys, nil
}

// DeleteKeyFromVault deletes a key from Azure Key Vault.
// DELETE {vaultURL}/keys/{keyName}?api-version=7.4
func (p *AzureEKMProvider) DeleteKeyFromVault(ctx context.Context, token, vaultURL, keyName string) error {
	reqURL := fmt.Sprintf("%s/keys/%s?api-version=%s", strings.TrimRight(vaultURL, "/"), url.PathEscape(keyName), azureAPIVersion)

	_, err := p.doAzureRequest(ctx, "DELETE", reqURL, token, nil)
	if err != nil {
		return fmt.Errorf("delete key from vault: %w", err)
	}
	p.logger.Printf("[azure-ekm] deleted key %s from vault", keyName)
	return nil
}

// WrapKey wraps (encrypts) a value using a key in Azure Key Vault.
// POST {vaultURL}/keys/{keyName}/wrapkey?api-version=7.4
func (p *AzureEKMProvider) WrapKey(ctx context.Context, token, vaultURL, keyName, algorithm string, value []byte) ([]byte, error) {
	if algorithm == "" {
		algorithm = "RSA-OAEP-256"
	}
	reqURL := fmt.Sprintf("%s/keys/%s/wrapkey?api-version=%s", strings.TrimRight(vaultURL, "/"), url.PathEscape(keyName), azureAPIVersion)

	payload := map[string]interface{}{
		"alg":   algorithm,
		"value": base64.RawURLEncoding.EncodeToString(value),
	}

	respBody, err := p.doAzureRequest(ctx, "POST", reqURL, token, payload)
	if err != nil {
		return nil, fmt.Errorf("wrap key: %w", err)
	}

	var result azureKeyOperationResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("wrap key: decode response: %w", err)
	}

	wrapped, err := base64.RawURLEncoding.DecodeString(result.Value)
	if err != nil {
		return nil, fmt.Errorf("wrap key: decode result value: %w", err)
	}
	return wrapped, nil
}

// UnwrapKey unwraps (decrypts) a value using a key in Azure Key Vault.
// POST {vaultURL}/keys/{keyName}/unwrapkey?api-version=7.4
func (p *AzureEKMProvider) UnwrapKey(ctx context.Context, token, vaultURL, keyName, algorithm string, value []byte) ([]byte, error) {
	if algorithm == "" {
		algorithm = "RSA-OAEP-256"
	}
	reqURL := fmt.Sprintf("%s/keys/%s/unwrapkey?api-version=%s", strings.TrimRight(vaultURL, "/"), url.PathEscape(keyName), azureAPIVersion)

	payload := map[string]interface{}{
		"alg":   algorithm,
		"value": base64.RawURLEncoding.EncodeToString(value),
	}

	respBody, err := p.doAzureRequest(ctx, "POST", reqURL, token, payload)
	if err != nil {
		return nil, fmt.Errorf("unwrap key: %w", err)
	}

	var result azureKeyOperationResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("unwrap key: decode response: %w", err)
	}

	unwrapped, err := base64.RawURLEncoding.DecodeString(result.Value)
	if err != nil {
		return nil, fmt.Errorf("unwrap key: decode result value: %w", err)
	}
	return unwrapped, nil
}

// ImportKeyToManagedHSM imports key material into Azure Managed HSM.
// PUT {hsmURL}/keys/{keyName}?api-version=7.4
func (p *AzureEKMProvider) ImportKeyToManagedHSM(ctx context.Context, token, hsmURL, keyName string, keyMaterial []byte, keyType string) (string, error) {
	if keyType == "" {
		keyType = "RSA-HSM"
	}
	reqURL := fmt.Sprintf("%s/keys/%s?api-version=%s", strings.TrimRight(hsmURL, "/"), url.PathEscape(keyName), azureAPIVersion)

	payload := map[string]interface{}{
		"key": map[string]interface{}{
			"kty":     keyType,
			"key_ops": []string{"encrypt", "decrypt", "wrapKey", "unwrapKey"},
			"k":       base64.RawURLEncoding.EncodeToString(keyMaterial),
		},
	}

	respBody, err := p.doAzureRequest(ctx, "PUT", reqURL, token, payload)
	if err != nil {
		return "", fmt.Errorf("import key to managed HSM: %w", err)
	}

	var bundle azureKeyBundle
	if err := json.Unmarshal(respBody, &bundle); err != nil {
		return "", fmt.Errorf("import key to HSM: decode response: %w", err)
	}

	kid, _ := bundle.Key["kid"].(string)
	if kid == "" {
		return "", fmt.Errorf("import key to HSM: no kid in response")
	}
	p.logger.Printf("[azure-ekm] imported key %s to managed HSM -> %s", keyName, kid)
	return kid, nil
}

// RotateKeyInManagedHSM rotates a key in Azure Managed HSM.
// POST {hsmURL}/keys/{keyName}/rotate?api-version=7.4
func (p *AzureEKMProvider) RotateKeyInManagedHSM(ctx context.Context, token, hsmURL, keyName string) (string, error) {
	reqURL := fmt.Sprintf("%s/keys/%s/rotate?api-version=%s", strings.TrimRight(hsmURL, "/"), url.PathEscape(keyName), azureAPIVersion)

	respBody, err := p.doAzureRequest(ctx, "POST", reqURL, token, nil)
	if err != nil {
		return "", fmt.Errorf("rotate key in managed HSM: %w", err)
	}

	var bundle azureKeyBundle
	if err := json.Unmarshal(respBody, &bundle); err != nil {
		return "", fmt.Errorf("rotate key in HSM: decode response: %w", err)
	}

	kid, _ := bundle.Key["kid"].(string)
	if kid == "" {
		return "", fmt.Errorf("rotate key in HSM: no kid in response")
	}
	parts := strings.Split(kid, "/")
	version := parts[len(parts)-1]
	p.logger.Printf("[azure-ekm] rotated key %s in managed HSM -> version %s", keyName, version)
	return version, nil
}

// doAzureRequest executes an HTTP request to Azure REST APIs with Bearer token auth.
func (p *AzureEKMProvider) doAzureRequest(ctx context.Context, method, reqURL, token string, payload interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		jsonBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal payload: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", reqURL, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var azErr azureErrorResponse
		if jsonErr := json.Unmarshal(body, &azErr); jsonErr == nil && azErr.Error.Message != "" {
			return nil, fmt.Errorf("azure API %d: %s: %s", resp.StatusCode, azErr.Error.Code, azErr.Error.Message)
		}
		return nil, fmt.Errorf("azure API %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}
