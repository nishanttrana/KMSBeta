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
// Priority: mTLS (transport) → JWT exchanged for an API key → static Bearer token.
type Config struct {
	// mTLS paths — if all three are set, mutual TLS is used at the transport layer.
	MTLSCertPath string `json:"mtls_cert_path"`
	MTLSKeyPath  string `json:"mtls_key_path"`
	MTLSCAPath   string `json:"mtls_ca_path"`

	// APIKey is an API client's key. It is only ever sent to JWTEndpoint
	// (auth's POST /auth/client-token, in the X-API-Key header), which
	// exchanges it for a short-lived JWT; no other service reads it.
	APIKey string `json:"api_key"`
	// ClientID is the API client the key belongs to.
	ClientID string `json:"client_id"`
	// JWTEndpoint is auth's client-token URL (https://<kms>/svc/auth/auth/client-token).
	JWTEndpoint string `json:"jwt_endpoint"`

	// Static bearer token (lowest priority, used as fallback).
	AuthToken string `json:"auth_token"`

	// HTTPClient, when set, carries the token exchange (it holds the trust
	// for the KMS edge's CA); otherwise one is built from the mTLS settings.
	HTTPClient *http.Client `json:"-"`

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

	// An API key is exchanged for a JWT. A failed exchange is an error:
	// until 13.33.0-beta the key was then sent as X-API-Key on the request
	// itself, which no service reads, so the call went out unauthenticated.
	if p.cfg.APIKey != "" {
		if err := p.RefreshJWT(req.Context()); err != nil {
			return err
		}
		p.mu.RLock()
		req.Header.Set("Authorization", "Bearer "+p.jwt)
		p.mu.RUnlock()
		return nil
	}

	// Static bearer token (lowest priority)
	if p.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.cfg.AuthToken)
		return nil
	}

	return nil // no auth configured — request goes unauthenticated
}

// jwtResponse is auth's POST /auth/client-token answer.
type jwtResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresAt   string `json:"expires_at"` // RFC 3339
}

// RefreshJWT exchanges the API key for a short-lived JWT.
func (p *Provider) RefreshJWT(ctx context.Context) error {
	if p.cfg.JWTEndpoint == "" || p.cfg.APIKey == "" || p.cfg.ClientID == "" {
		return errors.New("agentauth: an API key needs jwt_endpoint and client_id")
	}

	body, _ := json.Marshal(map[string]string{
		"tenant_id": p.cfg.TenantID,
		"client_id": p.cfg.ClientID,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.JWTEndpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("agentauth: build JWT request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", p.cfg.APIKey)

	client := p.cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
		if p.tlsCfg != nil {
			client.Transport = &http.Transport{TLSClientConfig: p.tlsCfg}
		}
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
	if jr.AccessToken == "" {
		return errors.New("agentauth: empty token in response")
	}
	exp, err := time.Parse(time.RFC3339, jr.ExpiresAt)
	if err != nil {
		return fmt.Errorf("agentauth: expires_at: %w", err)
	}
	// Refresh 30s early to avoid using an expired token
	expiry := exp.Add(-30 * time.Second)

	p.mu.Lock()
	p.jwt = jr.AccessToken
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
	case p.cfg.APIKey != "":
		return "API key exchanged for JWT"
	case p.cfg.AuthToken != "":
		return "Bearer"
	default:
		return "none"
	}
}
