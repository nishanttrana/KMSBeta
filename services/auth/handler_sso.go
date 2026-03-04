package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	pkgcrypto "vecta-kms/pkg/crypto"
)

// handleListSSOProviders returns enabled SSO providers for a tenant (public, no auth).
func (h *Handler) handleListSSOProviders(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	configs, err := h.store.ListIdentityProviderConfigs(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to list providers", reqID, tenantID)
		return
	}
	type ssoProvider struct {
		Provider    string `json:"provider"`
		DisplayName string `json:"display_name"`
		Type        string `json:"type"` // saml or oidc
	}
	var providers []ssoProvider
	for _, cfg := range configs {
		if !cfg.Enabled {
			continue
		}
		switch cfg.Provider {
		case identityProviderSAML:
			providers = append(providers, ssoProvider{
				Provider:    cfg.Provider,
				DisplayName: identityProviderConfigMapString(cfg.Config, "display_name", "SAML SSO"),
				Type:        "saml",
			})
		case identityProviderOIDC:
			providers = append(providers, ssoProvider{
				Provider:    cfg.Provider,
				DisplayName: identityProviderConfigMapString(cfg.Config, "display_name", "OpenID Connect"),
				Type:        "oidc",
			})
		}
	}
	if providers == nil {
		providers = []ssoProvider{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"providers":  providers,
		"request_id": reqID,
	})
}

// handleSSOLogin initiates an SSO login flow (public, no auth).
func (h *Handler) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	provider := strings.TrimSpace(r.PathValue("provider"))
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}

	cfg, err := h.store.GetIdentityProviderConfig(r.Context(), tenantID, provider)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "provider not configured", reqID, tenantID)
		return
	}
	if !cfg.Enabled {
		writeErr(w, http.StatusBadRequest, "bad_request", "provider is not enabled", reqID, tenantID)
		return
	}

	var redirectURL string
	switch provider {
	case identityProviderSAML:
		redirectURL, err = buildSAMLAuthnRequest(cfg)
	case identityProviderOIDC:
		var state string
		state, err = generateSSOState(tenantID, provider)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "state_error", "failed to generate state", reqID, tenantID)
			return
		}
		redirectURL, err = buildOIDCAuthURL(cfg, state)
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "SSO login not supported for provider: "+provider, reqID, tenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "sso_error", err.Error(), reqID, tenantID)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"redirect_url": redirectURL,
		"request_id":   reqID,
	})
}

// handleSSOCallback handles the IdP callback after SSO authentication (public, no auth).
func (h *Handler) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	provider := strings.TrimSpace(r.PathValue("provider"))

	var attrs SSOUserAttributes
	var tenantID string
	var err error

	switch provider {
	case identityProviderSAML:
		// SAML responses come as POST with SAMLResponse form field
		if parseErr := r.ParseForm(); parseErr != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "failed to parse form", reqID, "")
			return
		}
		samlResponse := r.FormValue("SAMLResponse")
		relayState := r.FormValue("RelayState")
		if samlResponse == "" {
			writeErr(w, http.StatusBadRequest, "bad_request", "missing SAMLResponse", reqID, "")
			return
		}
		// RelayState carries tenant_id for SAML
		tenantID = strings.TrimSpace(relayState)
		if tenantID == "" {
			writeErr(w, http.StatusBadRequest, "bad_request", "missing RelayState (tenant_id)", reqID, "")
			return
		}
		cfg, cfgErr := h.store.GetIdentityProviderConfig(r.Context(), tenantID, provider)
		if cfgErr != nil {
			writeErr(w, http.StatusNotFound, "not_found", "SAML provider not configured", reqID, tenantID)
			return
		}
		attrs, err = parseSAMLResponse(cfg, samlResponse)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "saml_error", err.Error(), reqID, tenantID)
			return
		}

	case identityProviderOIDC:
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if code == "" || state == "" {
			// Check for error response from IdP
			if errCode := r.URL.Query().Get("error"); errCode != "" {
				errDesc := r.URL.Query().Get("error_description")
				writeErr(w, http.StatusUnauthorized, "oidc_error", errCode+": "+errDesc, reqID, "")
				return
			}
			writeErr(w, http.StatusBadRequest, "bad_request", "missing code or state parameter", reqID, "")
			return
		}
		var stateProvider string
		tenantID, stateProvider, err = validateSSOState(state)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "state_error", err.Error(), reqID, "")
			return
		}
		if stateProvider != identityProviderOIDC {
			writeErr(w, http.StatusBadRequest, "bad_request", "state mismatch", reqID, tenantID)
			return
		}
		cfg, cfgErr := h.store.GetIdentityProviderConfig(r.Context(), tenantID, provider)
		if cfgErr != nil {
			writeErr(w, http.StatusNotFound, "not_found", "OIDC provider not configured", reqID, tenantID)
			return
		}
		attrs, err = exchangeOIDCCode(r.Context(), cfg, code)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "oidc_error", err.Error(), reqID, tenantID)
			return
		}

	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "SSO callback not supported for provider: "+provider, reqID, "")
		return
	}

	// Resolve or create user
	cfg, _ := h.store.GetIdentityProviderConfig(r.Context(), tenantID, provider)
	autoCreate := identityProviderConfigMapString(cfg.Config, "auto_create_users", "false") == "true"
	defaultRole := identityProviderConfigMapString(cfg.Config, "default_role", "viewer")

	user, err := h.findOrCreateSSOUser(r.Context(), tenantID, attrs, autoCreate, defaultRole)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "sso_user_error", err.Error(), reqID, tenantID)
		return
	}

	// Issue JWT
	tokenPerms, err := h.resolveEffectivePermissions(r.Context(), tenantID, user.ID, user.Role)
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, tenantID)
		return
	}

	token, exp, err := h.logic.IssueJWT(tenantID, user.Role, tokenPerms, user.ID, false)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "jwt_issue_failed", "failed to issue token", reqID, tenantID)
		return
	}

	sHash := tokenHash(token)
	defer pkgcrypto.Zeroize(sHash)
	if err := h.store.CreateSession(r.Context(), Session{
		ID:        NewID("sess"),
		TenantID:  tenantID,
		UserID:    user.ID,
		TokenHash: sHash,
		IPAddress: clientIP(r),
		UserAgent: r.UserAgent(),
		ExpiresAt: exp,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to create session", reqID, tenantID)
		return
	}

	if h.meter != nil {
		_ = h.meter.IncrementOps()
	}
	_ = h.publishAudit(r.Context(), "audit.auth.sso_login", reqID, tenantID, map[string]any{
		"user_id":  user.ID,
		"provider": provider,
	})

	// Redirect back to frontend with SSO token
	redirectBase := identityProviderConfigMapString(cfg.Config, "redirect_uri", "/")
	// For SAML, redirect_uri is the ACS URL; use a frontend base instead
	frontendURL := fmt.Sprintf("/?sso_provider=%s&sso_token=%s&sso_tenant=%s", provider, token, tenantID)
	_ = redirectBase // might be used for OIDC origin check in the future

	http.Redirect(w, r, frontendURL, http.StatusFound)
}

// handleSAMLMetadata returns the SP metadata XML for SAML configuration (public, no auth).
func (h *Handler) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	cfg, err := h.store.GetIdentityProviderConfig(r.Context(), tenantID, identityProviderSAML)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "SAML provider not configured", reqID, tenantID)
		return
	}
	metadata, err := buildSPMetadata(cfg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "metadata_error", err.Error(), reqID, tenantID)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(metadata))
}

// findOrCreateSSOUser resolves an existing user or creates a new one from SSO attributes.
func (h *Handler) findOrCreateSSOUser(ctx context.Context, tenantID string, attrs SSOUserAttributes, autoCreate bool, defaultRole string) (User, error) {
	// Try by username first
	u, err := h.store.GetUserByUsername(ctx, tenantID, attrs.Username)
	if err == nil {
		if normalizeUserStatus(u.Status) != "active" {
			return User{}, errors.New("user account is disabled")
		}
		return u, nil
	}

	// Try by email
	if attrs.Email != "" {
		u, err = h.store.GetUserByEmail(ctx, tenantID, attrs.Email)
		if err == nil {
			if normalizeUserStatus(u.Status) != "active" {
				return User{}, errors.New("user account is disabled")
			}
			return u, nil
		}
	}

	if !autoCreate {
		return User{}, errors.New("user not found and auto-creation is disabled")
	}

	// Generate a random password for SSO-created users (they won't use it)
	randPwd := make([]byte, 32)
	if _, err := rand.Read(randPwd); err != nil {
		return User{}, fmt.Errorf("failed to generate password: %w", err)
	}
	pwdHash, err := HashPassword(hex.EncodeToString(randPwd))
	if err != nil {
		return User{}, fmt.Errorf("failed to hash password: %w", err)
	}

	role := strings.TrimSpace(defaultRole)
	if role == "" {
		role = "viewer"
	}

	newUser := User{
		ID:                 NewID("usr"),
		TenantID:           tenantID,
		Username:           attrs.Username,
		Email:              attrs.Email,
		Password:           pwdHash,
		Role:               role,
		Status:             "active",
		MustChangePassword: false,
		CreatedAt:          time.Now().UTC(),
	}

	if err := h.store.CreateUser(ctx, newUser); err != nil {
		return User{}, fmt.Errorf("failed to create SSO user: %w", err)
	}

	return newUser, nil
}

// tryLDAPBind attempts LDAP bind authentication for the given credentials.
// Uses the existing ldapDirectoryClient for connection, then performs user-bind verification.
func (h *Handler) tryLDAPBind(ctx context.Context, tenantID, username, password string) (User, error) {
	cfg, err := h.store.GetIdentityProviderConfig(ctx, tenantID, identityProviderLDAP)
	if err != nil {
		return User{}, fmt.Errorf("ldap not configured: %w", err)
	}
	if !cfg.Enabled {
		return User{}, errors.New("ldap provider is not enabled")
	}

	client := newLDAPDirectoryClient(cfg)

	// Dial and bind with service account
	conn, err := client.dial(ctx)
	if err != nil {
		return User{}, fmt.Errorf("ldap connection failed: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	// Search for user DN
	filter := fmt.Sprintf("(&%s(%s=%s))", client.UserSearchFilter, ldap.EscapeFilter(client.UserLoginAttr), ldap.EscapeFilter(username))
	searchReq := ldap.NewSearchRequest(
		client.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		filter, []string{"dn", client.UserLoginAttr, client.UserEmailAttr, client.UserDisplayAttr}, nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return User{}, fmt.Errorf("ldap user search failed: %w", err)
	}
	if len(result.Entries) == 0 {
		return User{}, errors.New("ldap user not found")
	}
	if len(result.Entries) > 1 {
		return User{}, errors.New("ldap search returned multiple users")
	}

	entry := result.Entries[0]

	// Bind as the user to verify password
	if err := conn.Bind(entry.DN, password); err != nil {
		return User{}, errors.New("ldap authentication failed")
	}

	// Extract user attributes
	ldapUsername := entry.GetAttributeValue(client.UserLoginAttr)
	if ldapUsername == "" {
		ldapUsername = username
	}

	attrs := SSOUserAttributes{
		ExternalID:  entry.DN,
		Username:    sanitizeImportedUsername(ldapUsername),
		Email:       entry.GetAttributeValue(client.UserEmailAttr),
		DisplayName: entry.GetAttributeValue(client.UserDisplayAttr),
		Provider:    identityProviderLDAP,
	}

	autoCreate := identityProviderConfigMapString(cfg.Config, "auto_create_users", "false") == "true"
	defaultRole := identityProviderConfigMapString(cfg.Config, "default_role", "viewer")

	return h.findOrCreateSSOUser(ctx, tenantID, attrs, autoCreate, defaultRole)
}
