package dynamicsecrets

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GCPTokenProviderConfig configures the GCP service account token provider.
type GCPTokenProviderConfig struct {
	ServiceAccountEmail string
	PrivateKeyPEM       []byte   // PEM-encoded RSA private key from the service account JSON
	Scopes              []string // OAuth2 scopes (default: cloud-platform)
	TokenURL            string   // Override for testing (default: https://oauth2.googleapis.com/token)
}

// GCPTokenProvider generates short-lived GCP access tokens via JWT assertion.
type GCPTokenProvider struct {
	email      string
	privateKey *rsa.PrivateKey
	scopes     string
	tokenURL   string
	httpClient *http.Client
}

// NewGCPTokenProvider creates a provider for GCP short-lived access tokens.
func NewGCPTokenProvider(cfg GCPTokenProviderConfig) (*GCPTokenProvider, error) {
	if cfg.ServiceAccountEmail == "" {
		return nil, fmt.Errorf("dynamicsecrets/gcp: service account email is required")
	}
	if len(cfg.PrivateKeyPEM) == 0 {
		return nil, fmt.Errorf("dynamicsecrets/gcp: private key PEM is required")
	}

	block, _ := pem.Decode(cfg.PrivateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("dynamicsecrets/gcp: failed to decode PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 as fallback
		rsaKey, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("dynamicsecrets/gcp: parse private key: %w (pkcs1: %v)", err, err2)
		}
		key = rsaKey
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("dynamicsecrets/gcp: expected RSA private key, got %T", key)
	}

	scopes := strings.Join(cfg.Scopes, " ")
	if scopes == "" {
		scopes = "https://www.googleapis.com/auth/cloud-platform"
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = "https://oauth2.googleapis.com/token"
	}

	return &GCPTokenProvider{
		email:      cfg.ServiceAccountEmail,
		privateKey: rsaKey,
		scopes:     scopes,
		tokenURL:   tokenURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (p *GCPTokenProvider) Generate(ctx context.Context, req LeaseRequest) (*Credential, error) {
	now := time.Now()
	ttl := req.TTL
	if ttl > time.Hour {
		ttl = time.Hour // GCP max token lifetime is 1 hour by default
	}
	expiresAt := now.Add(ttl)

	// Build JWT assertion
	header := base64URLEncode([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claimSet := map[string]interface{}{
		"iss":   p.email,
		"sub":   p.email,
		"aud":   p.tokenURL,
		"iat":   now.Unix(),
		"exp":   expiresAt.Unix(),
		"scope": p.scopes,
	}
	claimBytes, err := json.Marshal(claimSet)
	if err != nil {
		return nil, fmt.Errorf("dynamicsecrets/gcp: marshal claims: %w", err)
	}
	payload := header + "." + base64URLEncode(claimBytes)

	// Sign with RSA-SHA256
	hash := sha256.Sum256([]byte(payload))
	sig, err := rsa.SignPKCS1v15(nil, p.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("dynamicsecrets/gcp: sign jwt: %w", err)
	}
	assertion := payload + "." + base64URLEncode(sig)

	// Exchange for access token
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("dynamicsecrets/gcp: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("dynamicsecrets/gcp: token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("dynamicsecrets/gcp: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dynamicsecrets/gcp: token request returned %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("dynamicsecrets/gcp: parse token response: %w", err)
	}

	credID := "gcpcred_" + randomHex(16)
	leaseID := "gcplease_" + randomHex(16)

	return &Credential{
		ID:        credID,
		TenantID:  req.TenantID,
		Provider:  "gcp_token",
		Username:  p.email,
		Token:     tokenResp.AccessToken,
		Endpoint:  "https://www.googleapis.com",
		ExpiresAt: expiresAt,
		LeaseID:   leaseID,
	}, nil
}

// Revoke is a no-op for GCP tokens; they expire naturally.
func (p *GCPTokenProvider) Revoke(_ context.Context, _ string) error {
	return nil
}

// ---------- Azure Client Credentials ----------

// AzureTokenProviderConfig configures the Azure AD client credentials provider.
type AzureTokenProviderConfig struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	Scope        string // default: https://management.azure.com/.default
	TokenURL     string // Override for testing
}

// AzureTokenProvider generates short-lived Azure AD access tokens.
type AzureTokenProvider struct {
	tenantID     string
	clientID     string
	clientSecret string
	scope        string
	tokenURL     string
	httpClient   *http.Client
}

// NewAzureTokenProvider creates a provider for Azure AD client_credentials tokens.
func NewAzureTokenProvider(cfg AzureTokenProviderConfig) (*AzureTokenProvider, error) {
	if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("dynamicsecrets/azure: tenant_id, client_id, and client_secret are required")
	}
	scope := cfg.Scope
	if scope == "" {
		scope = "https://management.azure.com/.default"
	}
	tokenURL := cfg.TokenURL
	if tokenURL == "" {
		tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", cfg.TenantID)
	}
	return &AzureTokenProvider{
		tenantID:     cfg.TenantID,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		scope:        scope,
		tokenURL:     tokenURL,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (p *AzureTokenProvider) Generate(ctx context.Context, req LeaseRequest) (*Credential, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {p.clientID},
		"client_secret": {p.clientSecret},
		"scope":         {p.scope},
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("dynamicsecrets/azure: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("dynamicsecrets/azure: token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("dynamicsecrets/azure: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dynamicsecrets/azure: token request returned %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("dynamicsecrets/azure: parse token response: %w", err)
	}

	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	credID := "azurecred_" + randomHex(16)
	leaseID := "azurelease_" + randomHex(16)

	return &Credential{
		ID:        credID,
		TenantID:  req.TenantID,
		Provider:  "azure_token",
		Username:  p.clientID,
		Token:     tokenResp.AccessToken,
		Endpoint:  fmt.Sprintf("https://login.microsoftonline.com/%s", p.tenantID),
		ExpiresAt: expiresAt,
		LeaseID:   leaseID,
	}, nil
}

// Revoke is a no-op for Azure tokens; they expire naturally.
func (p *AzureTokenProvider) Revoke(_ context.Context, _ string) error {
	return nil
}

func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
