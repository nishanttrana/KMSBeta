package main

import (
	"context"
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

	"vecta-kms/pkg/oidc"
	"vecta-kms/pkg/ssrfguard"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// ssoStateEntry stores SSO state parameters with expiry. Bind is the value
// the IdP must echo back: the SAML AuthnRequest ID or the OIDC nonce.
type ssoStateEntry struct {
	TenantID  string
	Provider  string
	Bind      string
	CreatedAt time.Time
}

var (
	ssoStateStore sync.Map
	oidcVerifier  = oidc.NewVerifier()
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

// generateSSOState creates a random one-time state value bound to the
// tenant, provider and the value the IdP must echo (request ID or nonce).
func generateSSOState(tenantID, provider, bind string) (string, error) {
	buf := make([]byte, 32)
	if _, err := pkgcrypto.Reader.Read(buf); err != nil {
		return "", err
	}
	state := base64.RawURLEncoding.EncodeToString(buf)
	ssoStateStore.Store(state, &ssoStateEntry{
		TenantID:  tenantID,
		Provider:  provider,
		Bind:      bind,
		CreatedAt: time.Now(),
	})
	return state, nil
}

// validateSSOState checks and consumes a state parameter.
func validateSSOState(state string) (ssoStateEntry, error) {
	state = strings.TrimSpace(state)
	if state == "" {
		return ssoStateEntry{}, errors.New("missing state parameter")
	}
	raw, ok := ssoStateStore.LoadAndDelete(state)
	if !ok {
		return ssoStateEntry{}, errors.New("invalid or expired state parameter")
	}
	entry, ok2 := raw.(*ssoStateEntry)
	if !ok2 {
		return ssoStateEntry{}, errors.New("corrupted state entry")
	}
	if time.Since(entry.CreatedAt) > 10*time.Minute {
		return ssoStateEntry{}, errors.New("state parameter has expired")
	}
	return *entry, nil
}

// buildOIDCAuthURL constructs the authorization-code redirect URL with a
// one-time state and nonce.
func buildOIDCAuthURL(ctx context.Context, cfg IdentityProviderConfig, tenantID string) (string, error) {
	issuerURL := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "issuer_url", ""))
	clientID := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "client_id", ""))
	redirectURI := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "redirect_uri", ""))
	scopes := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "scopes", "openid profile email"))

	if issuerURL == "" {
		return "", errors.New("oidc issuer_url is required")
	}
	if clientID == "" {
		return "", errors.New("oidc client_id is required")
	}
	if redirectURI == "" {
		return "", errors.New("oidc redirect_uri is required")
	}
	discovery, err := oidcVerifier.Discover(ctx, issuerURL)
	if err != nil {
		return "", err
	}
	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" {
		return "", errors.New("oidc discovery document missing required endpoints")
	}
	nonceRaw := make([]byte, 24)
	if _, err := pkgcrypto.Reader.Read(nonceRaw); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceRaw)
	state, err := generateSSOState(tenantID, identityProviderOIDC, nonce)
	if err != nil {
		return "", err
	}
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {scopes},
		"state":         {state},
		"nonce":         {nonce},
	}
	sep := "?"
	if strings.Contains(discovery.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return discovery.AuthorizationEndpoint + sep + params.Encode(), nil
}

// exchangeOIDCCode exchanges an authorization code for tokens and returns the
// user from the ID token, after verifying its signature against the issuer's
// JWKS and its iss, aud, exp and nonce.
func exchangeOIDCCode(ctx context.Context, cfg IdentityProviderConfig, code string, nonce string) (SSOUserAttributes, error) {
	issuerURL := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "issuer_url", ""))
	clientID := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "client_id", ""))
	clientSecret := strings.TrimSpace(identityProviderConfigMapString(cfg.Secrets, "client_secret", ""))
	redirectURI := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "redirect_uri", ""))

	attrUsername := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "attr_username", "preferred_username"))
	attrEmail := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "attr_email", "email"))
	attrDisplayName := strings.TrimSpace(identityProviderConfigMapString(cfg.Config, "attr_display_name", "name"))

	discovery, err := oidcVerifier.Discover(ctx, issuerURL)
	if err != nil {
		return SSOUserAttributes{}, err
	}

	values := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	}
	if clientSecret != "" {
		values.Set("client_secret", clientSecret)
	}
	if err := ssrfguard.ValidateWebhookURL(discovery.TokenEndpoint); err != nil {
		return SSOUserAttributes{}, fmt.Errorf("oidc token endpoint blocked: %w", err)
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
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SSOUserAttributes{}, fmt.Errorf("oidc token exchange failed (%d)", resp.StatusCode)
	}
	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return SSOUserAttributes{}, fmt.Errorf("oidc token response parse failed: %w", err)
	}
	claims, err := oidcVerifier.VerifyIDToken(ctx, tokenResp.IDToken, discovery, clientID, nonce, time.Now())
	if err != nil {
		return SSOUserAttributes{}, err
	}

	attrs := SSOUserAttributes{
		ExternalID:  anyString(claims["sub"]),
		Username:    anyString(claims[attrUsername]),
		Email:       anyString(claims[attrEmail]),
		DisplayName: anyString(claims[attrDisplayName]),
		Provider:    identityProviderOIDC,
	}
	if attrs.Username == "" && attrs.Email != "" {
		attrs.Username = sanitizeImportedUsername(strings.SplitN(attrs.Email, "@", 2)[0])
	}
	if attrs.Username == "" {
		return SSOUserAttributes{}, errors.New("oidc token did not contain a usable username")
	}
	return attrs, nil
}
