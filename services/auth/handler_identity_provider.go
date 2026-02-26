package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
)

type identityProviderPatchRequest struct {
	TenantID     string         `json:"tenant_id"`
	Enabled      *bool          `json:"enabled"`
	Config       map[string]any `json:"config"`
	Secrets      map[string]any `json:"secrets"`
	ClearSecrets []string       `json:"clear_secrets"`
}

func (h *Handler) handleListIdentityProviderConfigs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.read", r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	providers := []string{identityProviderAD, identityProviderEntra}
	items := make([]IdentityProviderConfigView, 0, len(providers))
	for _, provider := range providers {
		cfg, getErr := h.store.GetIdentityProviderConfig(r.Context(), targetTenant, provider)
		if errors.Is(getErr, errNotFound) {
			cfg = defaultIdentityProviderConfig(targetTenant, provider)
		} else if getErr != nil {
			writeErr(w, http.StatusInternalServerError, "store_error", "failed to list identity providers", reqID, targetTenant)
			return
		}
		cfg = normalizeIdentityProviderConfig(cfg)
		cfg.TenantID = targetTenant
		cfg.Provider = provider
		items = append(items, identityProviderConfigView(cfg))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":      items,
		"request_id": reqID,
	})
}

func (h *Handler) handleGetIdentityProviderConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.read", r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	provider, ok := normalizeIdentityProvider(r.PathValue("provider"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request", "provider must be ad or entra", reqID, targetTenant)
		return
	}
	cfg, getErr := h.store.GetIdentityProviderConfig(r.Context(), targetTenant, provider)
	if errors.Is(getErr, errNotFound) {
		cfg = defaultIdentityProviderConfig(targetTenant, provider)
	} else if getErr != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read identity provider config", reqID, targetTenant)
		return
	}
	cfg = normalizeIdentityProviderConfig(cfg)
	cfg.TenantID = targetTenant
	cfg.Provider = provider
	writeJSON(w, http.StatusOK, map[string]any{
		"config":     identityProviderConfigView(cfg),
		"request_id": reqID,
	})
}

func (h *Handler) handleUpsertIdentityProviderConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	provider, ok := normalizeIdentityProvider(r.PathValue("provider"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request", "provider must be ad or entra", reqID, claims.TenantID)
		return
	}
	var req identityProviderPatchRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, claims.TenantID)
		return
	}
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.write", req.TenantID, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	cfg := defaultIdentityProviderConfig(targetTenant, provider)
	existing, getErr := h.store.GetIdentityProviderConfig(r.Context(), targetTenant, provider)
	if getErr == nil {
		cfg = normalizeIdentityProviderConfig(existing)
		cfg.TenantID = targetTenant
		cfg.Provider = provider
	} else if !errors.Is(getErr, errNotFound) {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read identity provider config", reqID, targetTenant)
		return
	}
	cfg = applyIdentityProviderPatch(cfg, req)
	cfg.UpdatedBy = identityProviderActor(claims)
	cfg, err = sanitizeIdentityProviderConfigRecord(cfg)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, targetTenant)
		return
	}
	updated, err := h.store.UpsertIdentityProviderConfig(r.Context(), cfg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to save identity provider config", reqID, targetTenant)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.identity_provider_config_updated", reqID, targetTenant, map[string]any{
		"provider":       provider,
		"enabled":        updated.Enabled,
		"actor_user_id":  claims.UserID,
		"actor_tenant":   claims.TenantID,
		"updated_tenant": targetTenant,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, targetTenant)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":     identityProviderConfigView(updated),
		"request_id": reqID,
	})
}

func (h *Handler) handleTestIdentityProviderConnection(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	provider, ok := normalizeIdentityProvider(r.PathValue("provider"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request", "provider must be ad or entra", reqID, claims.TenantID)
		return
	}
	var req identityProviderPatchRequest
	if r.Body != nil && r.Body != http.NoBody {
		if err := decodeJSON(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, claims.TenantID)
			return
		}
	}
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.write", req.TenantID, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	cfg := defaultIdentityProviderConfig(targetTenant, provider)
	existing, getErr := h.store.GetIdentityProviderConfig(r.Context(), targetTenant, provider)
	if getErr == nil {
		cfg = normalizeIdentityProviderConfig(existing)
	} else if !errors.Is(getErr, errNotFound) {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read identity provider config", reqID, targetTenant)
		return
	}
	cfg.TenantID = targetTenant
	cfg.Provider = provider
	cfg = applyIdentityProviderPatch(cfg, req)
	cfg, err = sanitizeIdentityProviderConfigRecord(cfg)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, targetTenant)
		return
	}
	client, err := newDirectoryClient(cfg)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, targetTenant)
		return
	}
	result, err := client.Test(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadRequest, "directory_test_failed", err.Error(), reqID, targetTenant)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.identity_provider_tested", reqID, targetTenant, map[string]any{
		"provider":       provider,
		"actor_user_id":  claims.UserID,
		"actor_tenant":   claims.TenantID,
		"updated_tenant": targetTenant,
		"success":        true,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, targetTenant)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"result":     result,
		"provider":   provider,
		"request_id": reqID,
	})
}

func (h *Handler) handleListIdentityProviderUsers(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	provider, ok := normalizeIdentityProvider(r.PathValue("provider"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request", "provider must be ad or entra", reqID, claims.TenantID)
		return
	}
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.read", r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	client, cfg, err := h.identityProviderDirectoryClientForOps(r.Context(), targetTenant, provider)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, targetTenant)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	if query == "" {
		query = strings.TrimSpace(r.URL.Query().Get("q"))
	}
	limit := parseIdentityLimitQuery(r.URL.Query().Get("limit"), 50, 200)
	items, err := client.ListUsers(r.Context(), query, limit)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "directory_query_failed", err.Error(), reqID, targetTenant)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.identity_directory_users_listed", reqID, targetTenant, map[string]any{
		"provider":       provider,
		"query":          query,
		"count":          len(items),
		"enabled":        cfg.Enabled,
		"actor_user_id":  claims.UserID,
		"actor_tenant":   claims.TenantID,
		"updated_tenant": targetTenant,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, targetTenant)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"provider":    provider,
		"tenant_id":   targetTenant,
		"request_id":  reqID,
		"query":       query,
		"result_size": len(items),
	})
}

func (h *Handler) handleListIdentityProviderGroups(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	provider, ok := normalizeIdentityProvider(r.PathValue("provider"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request", "provider must be ad or entra", reqID, claims.TenantID)
		return
	}
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.read", r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	client, cfg, err := h.identityProviderDirectoryClientForOps(r.Context(), targetTenant, provider)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, targetTenant)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	if query == "" {
		query = strings.TrimSpace(r.URL.Query().Get("q"))
	}
	limit := parseIdentityLimitQuery(r.URL.Query().Get("limit"), 50, 200)
	items, err := client.ListGroups(r.Context(), query, limit)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "directory_query_failed", err.Error(), reqID, targetTenant)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.identity_directory_groups_listed", reqID, targetTenant, map[string]any{
		"provider":       provider,
		"query":          query,
		"count":          len(items),
		"enabled":        cfg.Enabled,
		"actor_user_id":  claims.UserID,
		"actor_tenant":   claims.TenantID,
		"updated_tenant": targetTenant,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, targetTenant)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"provider":    provider,
		"tenant_id":   targetTenant,
		"request_id":  reqID,
		"query":       query,
		"result_size": len(items),
	})
}

func (h *Handler) handleListIdentityProviderGroupMembers(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	provider, ok := normalizeIdentityProvider(r.PathValue("provider"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request", "provider must be ad or entra", reqID, claims.TenantID)
		return
	}
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.read", r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	groupID := strings.TrimSpace(r.PathValue("id"))
	if groupID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "group id is required", reqID, targetTenant)
		return
	}
	client, cfg, err := h.identityProviderDirectoryClientForOps(r.Context(), targetTenant, provider)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, targetTenant)
		return
	}
	limit := parseIdentityLimitQuery(r.URL.Query().Get("limit"), 200, 500)
	items, err := client.ListGroupMembers(r.Context(), groupID, limit)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "directory_query_failed", err.Error(), reqID, targetTenant)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.identity_directory_group_members_listed", reqID, targetTenant, map[string]any{
		"provider":       provider,
		"group_id":       groupID,
		"count":          len(items),
		"enabled":        cfg.Enabled,
		"actor_user_id":  claims.UserID,
		"actor_tenant":   claims.TenantID,
		"updated_tenant": targetTenant,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, targetTenant)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"provider":    provider,
		"tenant_id":   targetTenant,
		"group_id":    groupID,
		"request_id":  reqID,
		"result_size": len(items),
	})
}

func (h *Handler) handleImportIdentityUsers(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	var req struct {
		TenantID           string                  `json:"tenant_id"`
		Provider           string                  `json:"provider"`
		GroupID            string                  `json:"group_id"`
		Role               string                  `json:"role"`
		Status             string                  `json:"status"`
		MustChangePassword *bool                   `json:"must_change_password"`
		Users              []ExternalDirectoryUser `json:"users"`
		Limit              int                     `json:"limit"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, claims.TenantID)
		return
	}
	provider, ok := normalizeIdentityProvider(req.Provider)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request", "provider must be ad or entra", reqID, claims.TenantID)
		return
	}
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.write", req.TenantID, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	if _, err := h.store.GetTenant(r.Context(), targetTenant); err != nil {
		if errors.Is(err, errNotFound) {
			writeErr(w, http.StatusNotFound, "not_found", "tenant not found", reqID, targetTenant)
			return
		}
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to validate tenant", reqID, targetTenant)
		return
	}
	usersToImport := req.Users
	groupID := strings.TrimSpace(req.GroupID)
	if len(usersToImport) == 0 && groupID != "" {
		client, _, clientErr := h.identityProviderDirectoryClientForOps(r.Context(), targetTenant, provider)
		if clientErr != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", clientErr.Error(), reqID, targetTenant)
			return
		}
		limit := clampIdentityLimit(req.Limit, 500, 1000)
		groupUsers, listErr := client.ListGroupMembers(r.Context(), groupID, limit)
		if listErr != nil {
			writeErr(w, http.StatusBadRequest, "directory_query_failed", listErr.Error(), reqID, targetTenant)
			return
		}
		usersToImport = groupUsers
	}
	if len(usersToImport) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "users[] is required (or provide group_id)", reqID, targetTenant)
		return
	}
	status := normalizeUserStatus(req.Status)
	role := strings.TrimSpace(req.Role)
	if role == "" {
		role = "readonly"
	}
	mustChange := true
	if req.MustChangePassword != nil {
		mustChange = *req.MustChangePassword
	}
	created, existing, failed := h.importExternalIdentityUsers(r.Context(), targetTenant, role, status, mustChange, provider, usersToImport)
	if err := h.publishAudit(r.Context(), "audit.auth.identity_users_imported", reqID, targetTenant, map[string]any{
		"provider":       provider,
		"group_id":       groupID,
		"created":        len(created),
		"existing":       len(existing),
		"failed":         len(failed),
		"actor_user_id":  claims.UserID,
		"actor_tenant":   claims.TenantID,
		"updated_tenant": targetTenant,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, targetTenant)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"provider":   provider,
		"tenant_id":  targetTenant,
		"group_id":   groupID,
		"created":    created,
		"existing":   existing,
		"failed":     failed,
		"request_id": reqID,
	})
}

func (h *Handler) identityProviderDirectoryClientForOps(
	ctx context.Context,
	tenantID string,
	provider string,
) (directoryClient, IdentityProviderConfig, error) {
	cfg, err := h.store.GetIdentityProviderConfig(ctx, tenantID, provider)
	if errors.Is(err, errNotFound) {
		return nil, IdentityProviderConfig{}, fmt.Errorf("%s provider is not configured for tenant %s", provider, tenantID)
	}
	if err != nil {
		return nil, IdentityProviderConfig{}, err
	}
	cfg = normalizeIdentityProviderConfig(cfg)
	cfg.TenantID = tenantID
	cfg.Provider = provider
	if !cfg.Enabled {
		return nil, IdentityProviderConfig{}, fmt.Errorf("%s provider is disabled for tenant %s", provider, tenantID)
	}
	cfg, err = sanitizeIdentityProviderConfigRecord(cfg)
	if err != nil {
		return nil, IdentityProviderConfig{}, err
	}
	client, err := newDirectoryClient(cfg)
	if err != nil {
		return nil, IdentityProviderConfig{}, err
	}
	return client, cfg, nil
}

func applyIdentityProviderPatch(cfg IdentityProviderConfig, req identityProviderPatchRequest) IdentityProviderConfig {
	out := normalizeIdentityProviderConfig(cfg)
	if req.Enabled != nil {
		out.Enabled = *req.Enabled
	}
	if req.Config != nil {
		if out.Config == nil {
			out.Config = map[string]any{}
		}
		for key, value := range req.Config {
			k := strings.TrimSpace(key)
			if k == "" {
				continue
			}
			if value == nil {
				delete(out.Config, k)
				continue
			}
			out.Config[k] = value
		}
	}
	if req.Secrets != nil {
		if out.Secrets == nil {
			out.Secrets = map[string]any{}
		}
		for key, value := range req.Secrets {
			k := strings.TrimSpace(key)
			if k == "" {
				continue
			}
			if value == nil {
				delete(out.Secrets, k)
				continue
			}
			out.Secrets[k] = strings.TrimSpace(anyString(value))
		}
	}
	if len(req.ClearSecrets) > 0 {
		if out.Secrets == nil {
			out.Secrets = map[string]any{}
		}
		for _, key := range req.ClearSecrets {
			k := strings.TrimSpace(key)
			if k == "" {
				continue
			}
			delete(out.Secrets, k)
		}
	}
	return out
}

func sanitizeIdentityProviderConfigRecord(cfg IdentityProviderConfig) (IdentityProviderConfig, error) {
	out := normalizeIdentityProviderConfig(cfg)
	switch out.Provider {
	case identityProviderAD:
		timeoutSec := identityProviderConfigMapInt(out.Config, "timeout_sec", 10)
		if timeoutSec < 3 {
			timeoutSec = 3
		}
		if timeoutSec > 60 {
			timeoutSec = 60
		}
		out.Config = map[string]any{
			"ldap_url":             strings.TrimSpace(identityProviderConfigMapString(out.Config, "ldap_url", "")),
			"base_dn":              strings.TrimSpace(identityProviderConfigMapString(out.Config, "base_dn", "")),
			"bind_dn":              strings.TrimSpace(identityProviderConfigMapString(out.Config, "bind_dn", "")),
			"user_login_attr":      strings.TrimSpace(identityProviderConfigMapString(out.Config, "user_login_attr", "sAMAccountName")),
			"user_email_attr":      strings.TrimSpace(identityProviderConfigMapString(out.Config, "user_email_attr", "mail")),
			"user_display_attr":    strings.TrimSpace(identityProviderConfigMapString(out.Config, "user_display_attr", "displayName")),
			"user_object_filter":   strings.TrimSpace(identityProviderConfigMapString(out.Config, "user_object_filter", "(objectClass=user)")),
			"group_name_attr":      strings.TrimSpace(identityProviderConfigMapString(out.Config, "group_name_attr", "cn")),
			"group_object_filter":  strings.TrimSpace(identityProviderConfigMapString(out.Config, "group_object_filter", "(objectClass=group)")),
			"use_start_tls":        identityProviderConfigMapBool(out.Config, "use_start_tls", false),
			"insecure_skip_verify": identityProviderConfigMapBool(out.Config, "insecure_skip_verify", false),
			"timeout_sec":          timeoutSec,
		}
		secret := strings.TrimSpace(identityProviderConfigMapString(out.Secrets, "bind_password", ""))
		out.Secrets = map[string]any{}
		if secret != "" {
			out.Secrets["bind_password"] = secret
		}
		return out, nil
	case identityProviderEntra:
		timeoutSec := identityProviderConfigMapInt(out.Config, "timeout_sec", 10)
		if timeoutSec < 3 {
			timeoutSec = 3
		}
		if timeoutSec > 60 {
			timeoutSec = 60
		}
		out.Config = map[string]any{
			"tenant_id":      strings.TrimSpace(identityProviderConfigMapString(out.Config, "tenant_id", "")),
			"client_id":      strings.TrimSpace(identityProviderConfigMapString(out.Config, "client_id", "")),
			"authority_host": strings.TrimSpace(strings.TrimRight(identityProviderConfigMapString(out.Config, "authority_host", "https://login.microsoftonline.com"), "/")),
			"graph_base":     strings.TrimSpace(strings.TrimRight(identityProviderConfigMapString(out.Config, "graph_base", "https://graph.microsoft.com/v1.0"), "/")),
			"timeout_sec":    timeoutSec,
		}
		secret := strings.TrimSpace(identityProviderConfigMapString(out.Secrets, "client_secret", ""))
		out.Secrets = map[string]any{}
		if secret != "" {
			out.Secrets["client_secret"] = secret
		}
		return out, nil
	default:
		return IdentityProviderConfig{}, fmt.Errorf("unsupported provider: %s", out.Provider)
	}
}

func parseIdentityLimitQuery(raw string, fallback int, max int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return clampIdentityLimit(fallback, fallback, max)
	}
	limit, err := strconv.Atoi(raw)
	if err != nil {
		return clampIdentityLimit(fallback, fallback, max)
	}
	return clampIdentityLimit(limit, fallback, max)
}

func identityProviderActor(claims *pkgauth.Claims) string {
	if claims == nil {
		return "system"
	}
	if strings.TrimSpace(claims.UserID) != "" {
		return strings.TrimSpace(claims.UserID)
	}
	if strings.TrimSpace(claims.Subject) != "" {
		return strings.TrimSpace(claims.Subject)
	}
	return "system"
}

func (h *Handler) importExternalIdentityUsers(
	ctx context.Context,
	tenantID string,
	role string,
	status string,
	mustChange bool,
	sourceProvider string,
	input []ExternalDirectoryUser,
) ([]map[string]any, []map[string]any, []map[string]any) {
	role = strings.TrimSpace(role)
	if role == "" {
		role = "readonly"
	}
	status = normalizeUserStatus(status)
	existingUsers, _ := h.store.ListUsers(ctx, tenantID)
	userByUsername := map[string]User{}
	userByEmail := map[string]User{}
	for _, user := range existingUsers {
		un := strings.TrimSpace(strings.ToLower(user.Username))
		if un != "" {
			userByUsername[un] = user
		}
		em := strings.TrimSpace(strings.ToLower(user.Email))
		if em != "" {
			userByEmail[em] = user
		}
	}

	created := make([]map[string]any, 0, len(input))
	existing := make([]map[string]any, 0, len(input))
	failed := make([]map[string]any, 0, len(input))
	seen := map[string]struct{}{}

	for _, raw := range input {
		user := normalizeExternalIdentityUser(raw)
		identityKey := strings.TrimSpace(strings.ToLower(user.ExternalID))
		if identityKey == "" {
			identityKey = strings.TrimSpace(strings.ToLower(user.Email))
		}
		if identityKey == "" {
			identityKey = strings.TrimSpace(strings.ToLower(user.Username))
		}
		if identityKey != "" {
			if _, ok := seen[identityKey]; ok {
				continue
			}
			seen[identityKey] = struct{}{}
		}
		if user.Username == "" || user.Email == "" {
			failed = append(failed, map[string]any{
				"external_id": user.ExternalID,
				"username":    user.Username,
				"email":       user.Email,
				"error":       "username and email are required",
			})
			continue
		}
		if existingByUsername, ok := userByUsername[strings.ToLower(user.Username)]; ok {
			existing = append(existing, map[string]any{
				"user_id":     existingByUsername.ID,
				"external_id": user.ExternalID,
				"username":    existingByUsername.Username,
				"email":       existingByUsername.Email,
				"status":      "existing",
			})
			continue
		}
		if existingByEmail, ok := userByEmail[strings.ToLower(user.Email)]; ok {
			existing = append(existing, map[string]any{
				"user_id":     existingByEmail.ID,
				"external_id": user.ExternalID,
				"username":    existingByEmail.Username,
				"email":       existingByEmail.Email,
				"status":      "existing",
			})
			continue
		}
		base := sanitizeImportedUsername(user.Username)
		if base == "" {
			base = fallbackIdentityUsername(user.Email, user.DisplayName, user.ExternalID)
		}
		if base == "" {
			failed = append(failed, map[string]any{
				"external_id": user.ExternalID,
				"username":    user.Username,
				"email":       user.Email,
				"error":       "failed to derive local username",
			})
			continue
		}
		var createdUser User
		var createErr error
		for i := 0; i < 16; i++ {
			candidate := base
			if i > 0 {
				candidate = fmt.Sprintf("%s-%d", base, i+1)
			}
			if _, inUse := userByUsername[strings.ToLower(candidate)]; inUse {
				continue
			}
			password, passErr := generateImportedUserPassword()
			if passErr != nil {
				createErr = passErr
				break
			}
			hash, hashErr := HashPassword(password)
			if hashErr != nil {
				createErr = hashErr
				break
			}
			defer pkgcrypto.Zeroize(hash)
			createdUser = User{
				ID:                 NewID("usr"),
				TenantID:           tenantID,
				Username:           candidate,
				Email:              user.Email,
				Password:           hash,
				Role:               role,
				Status:             status,
				MustChangePassword: mustChange,
			}
			createErr = h.store.CreateUser(ctx, createdUser)
			if createErr == nil {
				break
			}
			if !isIdentityUniqueViolation(createErr) {
				break
			}
		}
		if createErr != nil {
			failed = append(failed, map[string]any{
				"external_id": user.ExternalID,
				"username":    user.Username,
				"email":       user.Email,
				"error":       createErr.Error(),
			})
			continue
		}
		userByUsername[strings.ToLower(createdUser.Username)] = createdUser
		userByEmail[strings.ToLower(createdUser.Email)] = createdUser
		created = append(created, map[string]any{
			"user_id":      createdUser.ID,
			"external_id":  user.ExternalID,
			"username":     createdUser.Username,
			"email":        createdUser.Email,
			"display_name": user.DisplayName,
			"source":       sourceProvider,
			"status":       "created",
		})
	}
	return created, existing, failed
}

func normalizeExternalIdentityUser(in ExternalDirectoryUser) ExternalDirectoryUser {
	out := in
	out.ExternalID = strings.TrimSpace(out.ExternalID)
	out.DisplayName = strings.TrimSpace(out.DisplayName)
	out.Source = strings.TrimSpace(strings.ToLower(out.Source))
	out.Username = sanitizeImportedUsername(out.Username)
	out.Email = strings.TrimSpace(strings.ToLower(out.Email))
	if out.Username == "" {
		out.Username = fallbackIdentityUsername(out.Email, out.DisplayName, out.ExternalID)
	}
	if out.Email == "" && out.Username != "" {
		out.Email = fmt.Sprintf("%s@directory.local", out.Username)
	}
	return out
}

func isIdentityUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "unique constraint") ||
		(strings.Contains(msg, "constraint failed") && strings.Contains(msg, "auth_users"))
}
