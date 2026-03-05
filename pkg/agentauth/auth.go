package agentauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// Config describes all supported authentication methods.
// Priority: mTLS (transport) → JWT (auto-refreshed) → API Key → static Bearer token.
type Config struct {
	// mTLS paths — if all three are set, mutual TLS is used at the transport layer.
	MTLSCertPath string `json:"mtls_cert_path"`
	MTLSKeyPath  string `json:"mtls_key_path"`
	MTLSCAPath   string `json:"mtls_ca_path"`

	// API Key for KMS authentication (sent as X-API-Key header).
	APIKey string `json:"api_key"`

	// JWT endpoint — if set together with APIKey, the provider will exchange
	// the API key for a short-lived JWT and refresh it before expiry.
	JWTEndpoint string `json:"jwt_endpoint"`

	// Static bearer token (lowest priority, used as fallback).
	AuthToken string `json:"auth_token"`

	// Tenant context.
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
}

// Provider implements the multi-auth strategy shared by all Vecta agents.
type Provider struct {
	cfg       Config
	tlsCfg    *tls.Config
	mu        sync.RWMutex
	jwt       string
	jwtExpiry time.Time
}

// New creates a Provider from the given config, loading mTLS certificates if configured.
func New(cfg Config) (*Provider, error) {
	p := &Provider{cfg: cfg}

	if cfg.MTLSCertPath != "" && cfg.MTLSKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.MTLSCertPath, cfg.MTLSKeyPath)
		if err != nil {
			return nil, fmt.Errorf("agentauth: load mTLS keypair: %w", err)
		}
		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		if cfg.MTLSCAPath != "" {
			caPEM, err := os.ReadFile(cfg.MTLSCAPath)
			if err != nil {
				return nil, fmt.Errorf("agentauth: read CA bundle: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, errors.New("agentauth: no valid certs found in CA bundle")
			}
			tlsCfg.RootCAs = pool
		}
		p.tlsCfg = tlsCfg
	}
	return p, nil
}

// TLSConfig returns the mTLS config for use with http.Transport, or nil.
func (p *Provider) TLSConfig() *tls.Config {
	return p.tlsCfg
}

// ApplyAuth sets the appropriate auth header on the request.
func (p *Provider) ApplyAuth(req *http.Request) error {
	// Add tenant header if configured
	if p.cfg.TenantID != "" {
		req.Header.Set("X-Tenant-ID", p.cfg.TenantID)
	}

	// Try JWT first
	p.mu.RLock()
	jwt := p.jwt
	exp := p.jwtExpiry
	p.mu.RUnlock()

	if jwt != "" && time.Now().Before(exp) {
		req.Header.Set("Authorization", "Bearer "+jwt)
		return nil
	}

	// Try auto-refresh JWT if endpoint is configured
	if p.cfg.JWTEndpoint != "" && p.cfg.APIKey != "" {
		if err := p.RefreshJWT(req.Context()); err == nil {
			p.mu.RLock()
			req.Header.Set("Authorization", "Bearer "+p.jwt)
			p.mu.RUnlock()
			return nil
		}
		// Fall through to API key on refresh failure
	}

	// API Key header
	if p.cfg.APIKey != "" {
		req.Header.Set("X-API-Key", p.cfg.APIKey)
		return nil
	}

	// Static bearer token (lowest priority)
	if p.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.AuthToken)
		return nil
	}

	return nil // no auth configured — request goes unauthenticated
}

// jwtResponse is the expected response from the JWT exchange endpoint.
type jwtResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expires_in"` // seconds
}

// RefreshJWT exchanges the API key for a short-lived JWT.
func (p *Provider) RefreshJWT(ctx context.Context) error {
	if p.cfg.JWTEndpoint == "" || p.cfg.APIKey == "" {
		return errors.New("agentauth: JWT endpoint or API key not configured")
	}

	body, _ := json.Marshal(map[string]string{
		"api_key":   p.cfg.APIKey,
		"tenant_id": p.cfg.TenantID,
		"role":      p.cfg.Role,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.JWTEndpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("agentauth: build JWT request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	if p.tlsCfg != nil {
		client.Transport = &http.Transport{TLSClientConfig: p.tlsCfg}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("agentauth: JWT exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agentauth: JWT exchange returned %d", resp.StatusCode)
	}

	var jr jwtResponse
	if err := json.NewDecoder(resp.Body).Decode(&jr); err != nil {
		return fmt.Errorf("agentauth: decode JWT response: %w", err)
	}
	if jr.Token == "" {
		return errors.New("agentauth: empty token in response")
	}

	ttl := time.Duration(jr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 15 * time.Minute // default if server doesn't specify
	}
	// Refresh 30s early to avoid using an expired token
	expiry := time.Now().Add(ttl - 30*time.Second)

	p.mu.Lock()
	p.jwt = jr.Token
	p.jwtExpiry = expiry
	p.mu.Unlock()
	return nil
}

// HasMTLS returns true if mutual TLS is configured.
func (p *Provider) HasMTLS() bool {
	return p.tlsCfg != nil
}

// AuthMethod returns a human-readable label for the active auth method.
func (p *Provider) AuthMethod() string {
	switch {
	case p.tlsCfg != nil && p.cfg.JWTEndpoint != "":
		return "mTLS+JWT"
	case p.tlsCfg != nil:
		return "mTLS"
	case p.cfg.JWTEndpoint != "" && p.cfg.APIKey != "":
		return "JWT"
	case p.cfg.APIKey != "":
		return "API-Key"
	case p.cfg.AuthToken != "":
		return "Bearer"
	default:
		return "none"
	}
}
