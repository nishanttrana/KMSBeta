package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OIDCDiscovery holds discovered OIDC endpoints from .well-known/openid-configuration.
type OIDCDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

// ssoStateEntry stores SSO state parameters with expiry.
type ssoStateEntry struct {
	TenantID  string
	Provider  string
	CreatedAt time.Time
}

var (
	ssoStateStore sync.Map
)

func init() {
	// Cleanup expired SSO states every 2 minutes
	go func() {
		for {
			time.Sleep(2 * time.Minute)
			now := time.Now()
			ssoStateStore.Range(func(key, value any) bool {
				entry, ok := value.(*ssoStateEntry)
				if ok && now.Sub(entry.CreatedAt) > 10*time.Minute {
					ssoStateStore.Delete(key)
				}
				return true
			})
		}
	}()
}

// generateSSOState creates a random state value and stores the tenant/provider mapping.
func generateSSOState(tenantID, provider string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	state := base64.RawURLEncoding.EncodeToString(buf)
	ssoStateStore.Store(state, &ssoStateEntry{
		TenantID:  tenantID,
		Provider:  provider,
		CreatedAt: time.Now(),
	})
	return state, nil
}

// validateSSOState checks and consumes a state parameter, returning the associated tenant/provider.
func validateSSOState(state string) (tenantID string, provider string, err error) {
	state = strings.TrimSpace(state)
	if state == "" {
		return "", "", errors.New("missing state parameter")
	}
	raw, ok := ssoStateStore.LoadAndDelete(state)
	if !ok {
		return "", "", errors.New("invalid or expired state parameter")
	}
	entry := raw.(*ssoStateEntry)
	if time.Since(entry.CreatedAt) > 10*time.Minute {
		return "", "", errors.New("state parameter has expired")
	}
	return entry.TenantID, entry.Provider, nil
}

// discoverOIDCEndpoints fetches the OIDC discovery document.
func discoverOIDCEndpoints(ctx context.Context, issuerURL string) (OIDCDiscovery, error) {
	issuerURL = strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if issuerURL == "" {
		return OIDCDiscovery{}, errors.New("oidc issuer_url is required")
	}
	wellKnown := issuerURL + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return OIDCDiscovery{}, err
	}
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return OIDCDiscovery{}, fmt.Errorf("oidc discovery request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return OIDCDiscovery{}, fmt.Errorf("oidc discovery failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var discovery OIDCDiscovery
	if err := json.Unmarshal(body, &discovery); err != nil {
		return OIDCDiscovery{}, fmt.Errorf("oidc discovery parse failed: %w", err)
	}
	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" {
		return OIDCDiscovery{}, errors.New("oidc discovery document missing required endpoints")
	}
	return discovery, nil
}

// buildOIDCAuthURL constructs the authorization redirect URL.
func buildOIDCAuthURL(cfg IdentityProviderConfig, state string) (string, error) {
	issuerURL := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "issuer_url", ""))
	clientID := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "client_id", ""))
	redirectURI := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "redirect_uri", ""))
	scopes := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "scopes", "openid profile email"))
	responseType := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "response_type", "code"))

	if issuerURL == "" {
		return "", errors.New("oidc issuer_url is required")
	}
	if clientID == "" {
		return "", errors.New("oidc client_id is required")
	}
	if redirectURI == "" {
		return "", errors.New("oidc redirect_uri is required")
	}

	discovery, err := discoverOIDCEndpoints(context.Background(), issuerURL)
	if err != nil {
		return "", err
	}

	params := url.Values{
		"response_type": {responseType},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {scopes},
		"state":         {state},
	}

	return discovery.AuthorizationEndpoint + "?" + params.Encode(), nil
}

// exchangeOIDCCode exchanges an authorization code for tokens and extracts user attributes.
func exchangeOIDCCode(ctx context.Context, cfg IdentityProviderConfig, code string) (SSOUserAttributes, error) {
	issuerURL := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "issuer_url", ""))
	clientID := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "client_id", ""))
	clientSecret := strings.TrimSpace(identityProviderConfigMapString(cfg.Secrets, "client_secret", ""))
	redirectURI := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "redirect_uri", ""))

	attrUsername := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "attr_username", "preferred_username"))
	attrEmail := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "attr_email", "email"))
	attrDisplayName := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "attr_display_name", "name"))

	discovery, err := discoverOIDCEndpoints(ctx, issuerURL)
	if err != nil {
		return SSOUserAttributes{}, err
	}

	// Exchange code for tokens
	values := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	}
	if clientSecret != "" {
		values.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, discovery.TokenEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return SSOUserAttributes{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return SSOUserAttributes{}, fmt.Errorf("oidc token exchange failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SSOUserAttributes{}, fmt.Errorf("oidc token exchange failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tokenResp struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return SSOUserAttributes{}, fmt.Errorf("oidc token response parse failed: %w", err)
	}

	// Parse ID token claims (JWT without full signature validation for now)
	claims, err := parseJWTClaims(tokenResp.IDToken)
	if err != nil {
		// Fallback: try userinfo endpoint
		if discovery.UserinfoEndpoint != "" && tokenResp.AccessToken != "" {
			claims, err = fetchOIDCUserInfo(ctx, discovery.UserinfoEndpoint, tokenResp.AccessToken)
			if err != nil {
				return SSOUserAttributes{}, fmt.Errorf("oidc failed to extract user info: %w", err)
			}
		} else {
			return SSOUserAttributes{}, fmt.Errorf("oidc id_token parse failed: %w", err)
		}
	}

	attrs := SSOUserAttributes{
		ExternalID: anyString(claims["sub"]),
		Username:   anyString(claims[attrUsername]),
		Email:      anyString(claims[attrEmail]),
		Provider:   identityProviderOIDC,
	}
	if v := anyString(claims[attrDisplayName]); v != "" {
		attrs.DisplayName = v
	}
	if attrs.Username == "" && attrs.Email != "" {
		attrs.Username = sanitizeImportedUsername(strings.SplitN(attrs.Email, "@", 2)[0])
	}
	if attrs.Username == "" {
		return SSOUserAttributes{}, errors.New("oidc token did not contain a usable username")
	}

	return attrs, nil
}

// parseJWTClaims extracts claims from a JWT without full signature validation.
func parseJWTClaims(token string) (map[string]any, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, errors.New("empty token")
	}
	parts := strings.SplitN(token, ".", 4)
	if len(parts) < 3 {
		return nil, errors.New("invalid JWT format")
	}
	payload := parts[1]
	// Pad base64
	if m := len(payload) % 4; m != 0 {
		payload += strings.Repeat("=", 4-m)
	}
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		// Try URL-safe encoding
		decoded, err = base64.URLEncoding.DecodeString(payload)
		if err != nil {
			return nil, err
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// fetchOIDCUserInfo fetches user info from the OIDC userinfo endpoint.
func fetchOIDCUserInfo(ctx context.Context, endpoint string, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("userinfo request failed (%d)", resp.StatusCode)
	}
	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}
