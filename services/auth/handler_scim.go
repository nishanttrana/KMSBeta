package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
)

const (
	scimCoreUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimCoreGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema      = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimPatchSchema     = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

type scimPrincipal struct {
	TenantID string
	Actor    string
	Claims   *pkgauth.Claims
	Settings SCIMSettings
}

type scimUserPayload struct {
	Schemas     []string `json:"schemas,omitempty"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName,omitempty"`
	Active      *bool    `json:"active,omitempty"`
	Name        struct {
		GivenName  string `json:"givenName,omitempty"`
		FamilyName string `json:"familyName,omitempty"`
	} `json:"name,omitempty"`
	Emails []struct {
		Value   string `json:"value"`
		Type    string `json:"type,omitempty"`
		Primary bool   `json:"primary,omitempty"`
	} `json:"emails,omitempty"`
	Roles []struct {
		Value string `json:"value"`
	} `json:"roles,omitempty"`
}

type scimGroupPayload struct {
	Schemas     []string `json:"schemas,omitempty"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []struct {
		Value   string `json:"value"`
		Display string `json:"display,omitempty"`
	} `json:"members,omitempty"`
}

type scimPatchRequest struct {
	Schemas    []string `json:"schemas"`
	Operations []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"Operations"`
}

var scimFilterPattern = regexp.MustCompile(`(?i)^\s*([a-zA-Z0-9\._-]+)\s+eq\s+"([^"]+)"\s*$`)

func defaultSCIMSettings(tenantID string) SCIMSettings {
	return SCIMSettings{
		TenantID:                  strings.TrimSpace(tenantID),
		Enabled:                   false,
		DefaultRole:               "readonly",
		DefaultStatus:             "active",
		DefaultMustChangePassword: false,
		DeprovisionMode:           "disable",
		GroupRoleMappingsEnabled:  true,
	}
}

func normalizeSCIMSettings(settings SCIMSettings) SCIMSettings {
	out := settings
	out.TenantID = strings.TrimSpace(out.TenantID)
	if strings.TrimSpace(out.DefaultRole) == "" {
		out.DefaultRole = "readonly"
	}
	status := normalizeUserStatus(out.DefaultStatus)
	if status == "" {
		status = "active"
	}
	out.DefaultStatus = status
	mode := strings.ToLower(strings.TrimSpace(out.DeprovisionMode))
	if mode != "delete" {
		mode = "disable"
	}
	out.DeprovisionMode = mode
	return out
}

func generateSCIMBearerToken() (string, []byte, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, "", err
	}
	token := "scim_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	hash := make([]byte, len(sum))
	copy(hash, sum[:])
	prefix := token[:min(len(token), 16)]
	return token, hash, prefix, nil
}

func generateSCIMShadowPassword() string {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "ScimShadow@2026!Aa1"
	}
	return "Scim@" + base64.RawURLEncoding.EncodeToString(buf) + "Aa1!"
}

func (h *Handler) resolveSCIMSettings(ctx context.Context, tenantID string) (SCIMSettings, error) {
	settings, err := h.store.GetSCIMSettings(ctx, tenantID)
	if errors.Is(err, errNotFound) {
		return defaultSCIMSettings(tenantID), nil
	}
	if err != nil {
		return SCIMSettings{}, err
	}
	return normalizeSCIMSettings(settings), nil
}

func (h *Handler) authenticateSCIMRequest(w http.ResponseWriter, r *http.Request, requireWrite bool) (scimPrincipal, bool) {
	reqID := requestID(r)
	raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
	if raw == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "missing bearer token", reqID, "")
		return scimPrincipal{}, false
	}
	if claims, err := h.logic.ParseJWT(raw); err == nil && claims != nil {
		requiredPerm := "auth.user.read"
		if requireWrite {
			requiredPerm = "auth.user.write"
		}
		if !hasPermission(claims.Permissions, requiredPerm) && !hasPermission(claims.Permissions, "*") {
			writeErr(w, http.StatusForbidden, "forbidden", "insufficient permissions", reqID, claims.TenantID)
			return scimPrincipal{}, false
		}
		settings, settingsErr := h.resolveSCIMSettings(r.Context(), claims.TenantID)
		if settingsErr != nil {
			writeErr(w, http.StatusInternalServerError, "store_error", "failed to resolve scim settings", reqID, claims.TenantID)
			return scimPrincipal{}, false
		}
		return scimPrincipal{
			TenantID: claims.TenantID,
			Actor:    strings.TrimSpace(claims.UserID),
			Claims:   claims,
			Settings: settings,
		}, true
	}
	sum := sha256.Sum256([]byte(raw))
	settings, err := h.store.GetSCIMSettingsByTokenHash(r.Context(), sum[:])
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid scim bearer token", reqID, "")
		return scimPrincipal{}, false
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to validate scim token", reqID, "")
		return scimPrincipal{}, false
	}
	settings = normalizeSCIMSettings(settings)
	if !settings.Enabled {
		writeErr(w, http.StatusForbidden, "forbidden", "scim provisioning is disabled for this tenant", reqID, settings.TenantID)
		return scimPrincipal{}, false
	}
	return scimPrincipal{
		TenantID: settings.TenantID,
		Actor:    "scim-provisioner",
		Settings: settings,
	}, true
}

func writeSCIMJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func parseSCIMPage(r *http.Request) (int, int) {
	startIndex := parseSCIMInt(r.URL.Query().Get("startIndex"), 1, 1, 100000)
	count := parseSCIMInt(r.URL.Query().Get("count"), 100, 1, 500)
	return startIndex, count
}

func parseSCIMInt(raw string, fallback int, minValue int, maxValue int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		value = fallback
	}
	if value < minValue {
		value = minValue
	}
	if maxValue > 0 && value > maxValue {
		value = maxValue
	}
	return value
}

func paginateSCIM[T any](items []T, startIndex int, count int) []T {
	if startIndex < 1 {
		startIndex = 1
	}
	if count <= 0 {
		count = len(items)
	}
	start := startIndex - 1
	if start >= len(items) {
		return []T{}
	}
	end := start + count
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

func parseSCIMFilter(raw string) (string, string) {
	matches := scimFilterPattern.FindStringSubmatch(strings.TrimSpace(raw))
	if len(matches) != 3 {
		return "", ""
	}
	return strings.ToLower(strings.TrimSpace(matches[1])), strings.TrimSpace(matches[2])
}

func scimUserMatches(item SCIMUserRecord, attr string, value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	switch attr {
	case "id":
		return strings.EqualFold(strings.TrimSpace(item.ID), value)
	case "externalid":
		return strings.EqualFold(strings.TrimSpace(item.ExternalID), value)
	case "username":
		return strings.EqualFold(strings.TrimSpace(item.Username), value)
	case "displayname":
		return strings.EqualFold(strings.TrimSpace(item.DisplayName), value)
	case "email", "emails":
		return strings.EqualFold(strings.TrimSpace(item.Email), value)
	case "active":
		wantActive := value == "true"
		return (strings.EqualFold(item.Status, "active")) == wantActive
	default:
		return true
	}
}

func scimGroupMatches(item SCIMGroupRecord, attr string, value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	switch attr {
	case "id":
		return strings.EqualFold(strings.TrimSpace(item.ID), value)
	case "externalid":
		return strings.EqualFold(strings.TrimSpace(item.ExternalID), value)
	case "displayname":
		return strings.EqualFold(strings.TrimSpace(item.DisplayName), value)
	default:
		return true
	}
}

func scimUserResource(item SCIMUserRecord) map[string]any {
	active := strings.EqualFold(strings.TrimSpace(item.Status), "active")
	return map[string]any{
		"schemas":     []string{scimCoreUserSchema},
		"id":          item.ID,
		"externalId":  item.ExternalID,
		"userName":    item.Username,
		"displayName": item.DisplayName,
		"active":      active,
		"name": map[string]any{
			"givenName":  item.GivenName,
			"familyName": item.FamilyName,
		},
		"emails": []map[string]any{
			{"value": item.Email, "type": "work", "primary": true},
		},
		"roles": []map[string]any{
			{"value": item.Role},
		},
		"meta": map[string]any{
			"resourceType": "User",
			"created":      item.CreatedAt.UTC().Format(time.RFC3339),
			"lastModified": nonZeroTime(item.LastSyncedAt, item.CreatedAt).UTC().Format(time.RFC3339),
		},
	}
}

func scimGroupResource(item SCIMGroupRecord) map[string]any {
	members := make([]map[string]any, 0, len(item.MemberIDs))
	for _, memberID := range item.MemberIDs {
		members = append(members, map[string]any{"value": memberID})
	}
	return map[string]any{
		"schemas":     []string{scimCoreGroupSchema},
		"id":          item.ID,
		"externalId":  item.ExternalID,
		"displayName": item.DisplayName,
		"members":     members,
		"meta": map[string]any{
			"resourceType": "Group",
			"created":      item.CreatedAt.UTC().Format(time.RFC3339),
			"lastModified": item.UpdatedAt.UTC().Format(time.RFC3339),
		},
	}
}

func nonZeroTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value
		}
	}
	return time.Now().UTC()
}

func primaryEmailFromSCIM(payload scimUserPayload) string {
	for _, item := range payload.Emails {
		if item.Primary && strings.TrimSpace(item.Value) != "" {
			return strings.TrimSpace(item.Value)
		}
	}
	for _, item := range payload.Emails {
		if strings.TrimSpace(item.Value) != "" {
			return strings.TrimSpace(item.Value)
		}
	}
	return ""
}

func roleFromSCIM(payload scimUserPayload, settings SCIMSettings) string {
	for _, item := range payload.Roles {
		if strings.TrimSpace(item.Value) != "" {
			return strings.TrimSpace(item.Value)
		}
	}
	return settings.DefaultRole
}

func statusFromSCIMActive(active *bool, settings SCIMSettings) string {
	if active == nil {
		return settings.DefaultStatus
	}
	if *active {
		return "active"
	}
	return "disabled"
}

func (h *Handler) handleGetSCIMSettings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.read", r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	settings, err := h.resolveSCIMSettings(r.Context(), targetTenant)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read scim settings", reqID, targetTenant)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": settings, "request_id": reqID})
}

func (h *Handler) handleUpdateSCIMSettings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	var req struct {
		TenantID                  string `json:"tenant_id"`
		Enabled                   *bool  `json:"enabled"`
		DefaultRole               string `json:"default_role"`
		DefaultStatus             string `json:"default_status"`
		DefaultMustChangePassword *bool  `json:"default_must_change_password"`
		DeprovisionMode           string `json:"deprovision_mode"`
		GroupRoleMappingsEnabled  *bool  `json:"group_role_mappings_enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, claims.TenantID)
		return
	}
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.write", req.TenantID, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	current, err := h.resolveSCIMSettings(r.Context(), targetTenant)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read current scim settings", reqID, targetTenant)
		return
	}
	if req.Enabled != nil {
		current.Enabled = *req.Enabled
	}
	if strings.TrimSpace(req.DefaultRole) != "" {
		current.DefaultRole = strings.TrimSpace(req.DefaultRole)
	}
	if strings.TrimSpace(req.DefaultStatus) != "" {
		current.DefaultStatus = strings.TrimSpace(req.DefaultStatus)
	}
	if req.DefaultMustChangePassword != nil {
		current.DefaultMustChangePassword = *req.DefaultMustChangePassword
	}
	if strings.TrimSpace(req.DeprovisionMode) != "" {
		current.DeprovisionMode = strings.TrimSpace(req.DeprovisionMode)
	}
	if req.GroupRoleMappingsEnabled != nil {
		current.GroupRoleMappingsEnabled = *req.GroupRoleMappingsEnabled
	}
	current.UpdatedBy = claims.UserID
	current = normalizeSCIMSettings(current)
	updated, err := h.store.UpsertSCIMSettings(r.Context(), current, nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to update scim settings", reqID, targetTenant)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.scim_settings_updated", reqID, targetTenant, map[string]any{
		"enabled":                     updated.Enabled,
		"default_role":                updated.DefaultRole,
		"default_status":              updated.DefaultStatus,
		"deprovision_mode":            updated.DeprovisionMode,
		"group_role_mappings_enabled": updated.GroupRoleMappingsEnabled,
		"actor_user_id":               claims.UserID,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, targetTenant)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"settings": updated, "request_id": reqID})
}

func (h *Handler) handleRotateSCIMToken(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	var req struct {
		TenantID string `json:"tenant_id"`
	}
	_ = decodeJSON(r, &req)
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.write", req.TenantID, r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	current, err := h.resolveSCIMSettings(r.Context(), targetTenant)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read current scim settings", reqID, targetTenant)
		return
	}
	rawToken, hash, prefix, err := generateSCIMBearerToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token_generation_failed", "failed to generate scim token", reqID, targetTenant)
		return
	}
	current.TokenPrefix = prefix
	current.UpdatedBy = claims.UserID
	updated, err := h.store.UpsertSCIMSettings(r.Context(), current, hash)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to rotate scim token", reqID, targetTenant)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.scim_token_rotated", reqID, targetTenant, map[string]any{
		"token_prefix":   prefix,
		"actor_user_id":  claims.UserID,
		"updated_tenant": targetTenant,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, targetTenant)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings":     updated,
		"bearer_token": rawToken,
		"request_id":   reqID,
	})
}

func (h *Handler) handleGetSCIMSummary(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.read", r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	summary, err := h.store.GetSCIMSummary(r.Context(), targetTenant)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read scim summary", reqID, targetTenant)
		return
	}
	_ = h.publishAudit(r.Context(), "audit.auth.scim_summary_viewed", reqID, targetTenant, map[string]any{"actor_user_id": claims.UserID})
	writeJSON(w, http.StatusOK, map[string]any{"summary": summary, "request_id": reqID})
}

func (h *Handler) handleListSCIMUsersAdmin(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.read", r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	items, err := h.store.ListSCIMUsers(r.Context(), targetTenant)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to list scim users", reqID, targetTenant)
		return
	}
	_ = h.publishAudit(r.Context(), "audit.auth.scim_users_viewed", reqID, targetTenant, map[string]any{"actor_user_id": claims.UserID, "count": len(items)})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleListSCIMGroupsAdmin(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.read", r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	items, err := h.store.ListSCIMGroups(r.Context(), targetTenant)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to list scim groups", reqID, targetTenant)
		return
	}
	_ = h.publishAudit(r.Context(), "audit.auth.scim_groups_viewed", reqID, targetTenant, map[string]any{"actor_user_id": claims.UserID, "count": len(items)})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleSCIMServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authenticateSCIMRequest(w, r, false)
	if !ok {
		return
	}
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":   map[string]any{"supported": true},
		"bulk":    map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":  map[string]any{"supported": true, "maxResults": 500},
		"changePassword": map[string]any{
			"supported": false,
		},
		"sort": map[string]any{"supported": false},
		"etag": map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{
			{
				"name":        "Bearer Token",
				"type":        "oauthbearertoken",
				"description": fmt.Sprintf("Tenant-scoped SCIM provisioning token for %s", principal.TenantID),
				"primary":     true,
			},
		},
	})
}

func (h *Handler) handleSCIMSchemas(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authenticateSCIMRequest(w, r, false); !ok {
		return
	}
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": 2,
		"startIndex":   1,
		"itemsPerPage": 2,
		"Resources": []map[string]any{
			{
				"id":          scimCoreUserSchema,
				"name":        "User",
				"description": "Core User",
				"attributes":  []map[string]any{{"name": "userName"}, {"name": "displayName"}, {"name": "emails"}, {"name": "active"}},
			},
			{
				"id":          scimCoreGroupSchema,
				"name":        "Group",
				"description": "Core Group",
				"attributes":  []map[string]any{{"name": "displayName"}, {"name": "members"}},
			},
		},
	})
}

func (h *Handler) handleSCIMResourceTypes(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authenticateSCIMRequest(w, r, false); !ok {
		return
	}
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": 2,
		"startIndex":   1,
		"itemsPerPage": 2,
		"Resources": []map[string]any{
			{"id": "Users", "name": "User", "endpoint": "/Users", "schema": scimCoreUserSchema},
			{"id": "Groups", "name": "Group", "endpoint": "/Groups", "schema": scimCoreGroupSchema},
		},
	})
}

func (h *Handler) handleSCIMListUsers(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authenticateSCIMRequest(w, r, false)
	if !ok {
		return
	}
	items, err := h.store.ListSCIMUsers(r.Context(), principal.TenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to list scim users", requestID(r), principal.TenantID)
		return
	}
	attr, value := parseSCIMFilter(r.URL.Query().Get("filter"))
	filtered := make([]SCIMUserRecord, 0, len(items))
	for _, item := range items {
		if attr == "" || scimUserMatches(item, attr, value) {
			filtered = append(filtered, item)
		}
	}
	sort.Slice(filtered, func(i, j int) bool {
		return strings.ToLower(filtered[i].Username) < strings.ToLower(filtered[j].Username)
	})
	startIndex, count := parseSCIMPage(r)
	page := paginateSCIM(filtered, startIndex, count)
	resources := make([]map[string]any, 0, len(page))
	for _, item := range page {
		resources = append(resources, scimUserResource(item))
	}
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": len(filtered),
		"startIndex":   startIndex,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	})
}

func (h *Handler) handleSCIMGetUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authenticateSCIMRequest(w, r, false)
	if !ok {
		return
	}
	item, err := h.store.GetSCIMUserByID(r.Context(), principal.TenantID, r.PathValue("id"))
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "scim user not found", requestID(r), principal.TenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read scim user", requestID(r), principal.TenantID)
		return
	}
	writeSCIMJSON(w, http.StatusOK, scimUserResource(item))
}

func (h *Handler) handleSCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authenticateSCIMRequest(w, r, true)
	if !ok {
		return
	}
	var req scimUserPayload
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), requestID(r), principal.TenantID)
		return
	}
	email := primaryEmailFromSCIM(req)
	if strings.TrimSpace(req.UserName) == "" || email == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "userName and one email are required", requestID(r), principal.TenantID)
		return
	}
	password := generateSCIMShadowPassword()
	hash, err := HashPassword(password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash_error", "failed to generate shadow password", requestID(r), principal.TenantID)
		return
	}
	item, created, err := h.store.UpsertSCIMUser(r.Context(), SCIMUserRecord{
		User: User{
			TenantID:           principal.TenantID,
			Username:           strings.TrimSpace(req.UserName),
			Email:              email,
			Password:           hash,
			Role:               roleFromSCIM(req, principal.Settings),
			Status:             statusFromSCIMActive(req.Active, principal.Settings),
			MustChangePassword: principal.Settings.DefaultMustChangePassword,
		},
		ExternalID:  strings.TrimSpace(req.ExternalID),
		DisplayName: strings.TrimSpace(req.DisplayName),
		GivenName:   strings.TrimSpace(req.Name.GivenName),
		FamilyName:  strings.TrimSpace(req.Name.FamilyName),
		SCIMManaged: true,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "scim_user_upsert_failed", err.Error(), requestID(r), principal.TenantID)
		return
	}
	subject := "audit.auth.scim_user_updated"
	statusCode := http.StatusOK
	if created {
		subject = "audit.auth.scim_user_provisioned"
		statusCode = http.StatusCreated
	}
	_ = h.publishAudit(r.Context(), subject, requestID(r), principal.TenantID, map[string]any{
		"user_id":     item.ID,
		"external_id": item.ExternalID,
		"actor":       principal.Actor,
		"status":      item.Status,
		"role":        item.Role,
	})
	writeSCIMJSON(w, statusCode, scimUserResource(item))
}

func (h *Handler) handleSCIMReplaceUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authenticateSCIMRequest(w, r, true)
	if !ok {
		return
	}
	var req scimUserPayload
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), requestID(r), principal.TenantID)
		return
	}
	existing, err := h.store.GetSCIMUserByID(r.Context(), principal.TenantID, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "scim user not found", requestID(r), principal.TenantID)
		return
	}
	email := primaryEmailFromSCIM(req)
	if email == "" {
		email = existing.Email
	}
	shadow := generateSCIMShadowPassword()
	hash, err := HashPassword(shadow)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash_error", "failed to generate shadow password", requestID(r), principal.TenantID)
		return
	}
	item, _, err := h.store.UpsertSCIMUser(r.Context(), SCIMUserRecord{
		User: User{
			ID:                 existing.ID,
			TenantID:           principal.TenantID,
			Username:           firstNonEmpty(strings.TrimSpace(req.UserName), existing.Username),
			Email:              email,
			Password:           hash,
			Role:               firstNonEmpty(roleFromSCIM(req, principal.Settings), existing.Role),
			Status:             statusFromSCIMActive(req.Active, principal.Settings),
			MustChangePassword: existing.MustChangePassword,
		},
		ExternalID:  firstNonEmpty(strings.TrimSpace(req.ExternalID), existing.ExternalID),
		DisplayName: firstNonEmpty(strings.TrimSpace(req.DisplayName), existing.DisplayName),
		GivenName:   firstNonEmpty(strings.TrimSpace(req.Name.GivenName), existing.GivenName),
		FamilyName:  firstNonEmpty(strings.TrimSpace(req.Name.FamilyName), existing.FamilyName),
		SCIMManaged: true,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "scim_user_replace_failed", err.Error(), requestID(r), principal.TenantID)
		return
	}
	_ = h.publishAudit(r.Context(), "audit.auth.scim_user_updated", requestID(r), principal.TenantID, map[string]any{
		"user_id":     item.ID,
		"external_id": item.ExternalID,
		"actor":       principal.Actor,
		"status":      item.Status,
		"role":        item.Role,
	})
	writeSCIMJSON(w, http.StatusOK, scimUserResource(item))
}

func (h *Handler) handleSCIMPatchUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authenticateSCIMRequest(w, r, true)
	if !ok {
		return
	}
	var req scimPatchRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), requestID(r), principal.TenantID)
		return
	}
	patch := SCIMUserPatch{}
	for _, op := range req.Operations {
		path := strings.ToLower(strings.TrimSpace(op.Path))
		if path == "" {
			continue
		}
		switch path {
		case "active":
			var active bool
			if json.Unmarshal(op.Value, &active) == nil {
				status := "disabled"
				if active {
					status = "active"
				}
				patch.Status = &status
			}
		case "username":
			var value string
			if json.Unmarshal(op.Value, &value) == nil {
				patch.Username = &value
			}
		case "displayname":
			var value string
			if json.Unmarshal(op.Value, &value) == nil {
				patch.DisplayName = &value
			}
		case "externalid":
			var value string
			if json.Unmarshal(op.Value, &value) == nil {
				patch.ExternalID = &value
			}
		case "name.givenname":
			var value string
			if json.Unmarshal(op.Value, &value) == nil {
				patch.GivenName = &value
			}
		case "name.familyname":
			var value string
			if json.Unmarshal(op.Value, &value) == nil {
				patch.FamilyName = &value
			}
		case "roles":
			var roles []struct {
				Value string `json:"value"`
			}
			if json.Unmarshal(op.Value, &roles) == nil && len(roles) > 0 {
				value := roles[0].Value
				patch.Role = &value
			}
		case "emails":
			var emails []struct {
				Value string `json:"value"`
			}
			if json.Unmarshal(op.Value, &emails) == nil && len(emails) > 0 {
				value := emails[0].Value
				patch.Email = &value
			}
		}
	}
	item, err := h.store.ApplySCIMUserPatch(r.Context(), principal.TenantID, r.PathValue("id"), patch)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "scim_user_patch_failed", err.Error(), requestID(r), principal.TenantID)
		return
	}
	_ = h.publishAudit(r.Context(), "audit.auth.scim_user_updated", requestID(r), principal.TenantID, map[string]any{
		"user_id":     item.ID,
		"external_id": item.ExternalID,
		"actor":       principal.Actor,
		"status":      item.Status,
		"role":        item.Role,
	})
	writeSCIMJSON(w, http.StatusOK, scimUserResource(item))
}

func (h *Handler) handleSCIMDeleteUser(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authenticateSCIMRequest(w, r, true)
	if !ok {
		return
	}
	result, err := h.store.DeprovisionSCIMUser(r.Context(), principal.TenantID, r.PathValue("id"), principal.Settings.DeprovisionMode)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "scim_user_deprovision_failed", err.Error(), requestID(r), principal.TenantID)
		return
	}
	subject := "audit.auth.scim_user_disabled"
	if result == "deleted" {
		subject = "audit.auth.scim_user_deprovisioned"
	}
	_ = h.publishAudit(r.Context(), subject, requestID(r), principal.TenantID, map[string]any{
		"user_id": r.PathValue("id"),
		"actor":   principal.Actor,
		"mode":    result,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleSCIMListGroups(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authenticateSCIMRequest(w, r, false)
	if !ok {
		return
	}
	items, err := h.store.ListSCIMGroups(r.Context(), principal.TenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to list scim groups", requestID(r), principal.TenantID)
		return
	}
	attr, value := parseSCIMFilter(r.URL.Query().Get("filter"))
	filtered := make([]SCIMGroupRecord, 0, len(items))
	for _, item := range items {
		if attr == "" || scimGroupMatches(item, attr, value) {
			filtered = append(filtered, item)
		}
	}
	startIndex, count := parseSCIMPage(r)
	page := paginateSCIM(filtered, startIndex, count)
	resources := make([]map[string]any, 0, len(page))
	for _, item := range page {
		full, _ := h.store.GetSCIMGroupByID(r.Context(), principal.TenantID, item.ID)
		resources = append(resources, scimGroupResource(full))
	}
	writeSCIMJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{scimListSchema},
		"totalResults": len(filtered),
		"startIndex":   startIndex,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	})
}

func (h *Handler) handleSCIMGetGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authenticateSCIMRequest(w, r, false)
	if !ok {
		return
	}
	item, err := h.store.GetSCIMGroupByID(r.Context(), principal.TenantID, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "scim group not found", requestID(r), principal.TenantID)
		return
	}
	writeSCIMJSON(w, http.StatusOK, scimGroupResource(item))
}

func scimResolveMemberIDs(ctx context.Context, store Store, tenantID string, members []struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
}) ([]string, error) {
	out := make([]string, 0, len(members))
	for _, member := range members {
		value := strings.TrimSpace(member.Value)
		if value == "" {
			continue
		}
		if user, err := store.GetSCIMUserByID(ctx, tenantID, value); err == nil {
			out = append(out, user.ID)
			continue
		}
		if user, err := store.GetSCIMUserByExternalID(ctx, tenantID, value); err == nil {
			out = append(out, user.ID)
			continue
		}
		return nil, fmt.Errorf("member %s is not provisioned", value)
	}
	return out, nil
}

func (h *Handler) handleSCIMCreateGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authenticateSCIMRequest(w, r, true)
	if !ok {
		return
	}
	var req scimGroupPayload
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), requestID(r), principal.TenantID)
		return
	}
	item, created, err := h.store.UpsertSCIMGroup(r.Context(), SCIMGroupRecord{
		TenantID:    principal.TenantID,
		ExternalID:  strings.TrimSpace(req.ExternalID),
		DisplayName: strings.TrimSpace(req.DisplayName),
		Active:      true,
		SCIMManaged: true,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "scim_group_upsert_failed", err.Error(), requestID(r), principal.TenantID)
		return
	}
	memberIDs, err := scimResolveMemberIDs(r.Context(), h.store, principal.TenantID, req.Members)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "scim_group_members_failed", err.Error(), requestID(r), principal.TenantID)
		return
	}
	if err := h.store.ReplaceSCIMGroupMembers(r.Context(), principal.TenantID, item.ID, memberIDs); err != nil {
		writeErr(w, http.StatusBadRequest, "scim_group_members_failed", err.Error(), requestID(r), principal.TenantID)
		return
	}
	item, _ = h.store.GetSCIMGroupByID(r.Context(), principal.TenantID, item.ID)
	subject := "audit.auth.scim_group_updated"
	statusCode := http.StatusOK
	if created {
		subject = "audit.auth.scim_group_provisioned"
		statusCode = http.StatusCreated
	}
	_ = h.publishAudit(r.Context(), subject, requestID(r), principal.TenantID, map[string]any{
		"group_id":     item.ID,
		"external_id":  item.ExternalID,
		"member_count": item.MemberCount,
		"actor":        principal.Actor,
	})
	writeSCIMJSON(w, statusCode, scimGroupResource(item))
}

func (h *Handler) handleSCIMReplaceGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authenticateSCIMRequest(w, r, true)
	if !ok {
		return
	}
	var req scimGroupPayload
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), requestID(r), principal.TenantID)
		return
	}
	item, _, err := h.store.UpsertSCIMGroup(r.Context(), SCIMGroupRecord{
		ID:          r.PathValue("id"),
		TenantID:    principal.TenantID,
		ExternalID:  strings.TrimSpace(req.ExternalID),
		DisplayName: strings.TrimSpace(req.DisplayName),
		Active:      true,
		SCIMManaged: true,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "scim_group_replace_failed", err.Error(), requestID(r), principal.TenantID)
		return
	}
	memberIDs, err := scimResolveMemberIDs(r.Context(), h.store, principal.TenantID, req.Members)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "scim_group_members_failed", err.Error(), requestID(r), principal.TenantID)
		return
	}
	if err := h.store.ReplaceSCIMGroupMembers(r.Context(), principal.TenantID, item.ID, memberIDs); err != nil {
		writeErr(w, http.StatusBadRequest, "scim_group_members_failed", err.Error(), requestID(r), principal.TenantID)
		return
	}
	item, _ = h.store.GetSCIMGroupByID(r.Context(), principal.TenantID, item.ID)
	_ = h.publishAudit(r.Context(), "audit.auth.scim_group_updated", requestID(r), principal.TenantID, map[string]any{
		"group_id":     item.ID,
		"external_id":  item.ExternalID,
		"member_count": item.MemberCount,
		"actor":        principal.Actor,
	})
	writeSCIMJSON(w, http.StatusOK, scimGroupResource(item))
}

func (h *Handler) handleSCIMPatchGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authenticateSCIMRequest(w, r, true)
	if !ok {
		return
	}
	current, err := h.store.GetSCIMGroupByID(r.Context(), principal.TenantID, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "scim group not found", requestID(r), principal.TenantID)
		return
	}
	var req scimPatchRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), requestID(r), principal.TenantID)
		return
	}
	memberIDs := append([]string(nil), current.MemberIDs...)
	for _, op := range req.Operations {
		path := strings.ToLower(strings.TrimSpace(op.Path))
		switch path {
		case "displayname":
			_ = json.Unmarshal(op.Value, &current.DisplayName)
		case "externalid":
			_ = json.Unmarshal(op.Value, &current.ExternalID)
		case "members":
			var members []struct {
				Value   string `json:"value"`
				Display string `json:"display,omitempty"`
			}
			if json.Unmarshal(op.Value, &members) == nil {
				resolved, resolveErr := scimResolveMemberIDs(r.Context(), h.store, principal.TenantID, members)
				if resolveErr != nil {
					writeErr(w, http.StatusBadRequest, "scim_group_members_failed", resolveErr.Error(), requestID(r), principal.TenantID)
					return
				}
				memberIDs = resolved
			}
		}
	}
	current, _, err = h.store.UpsertSCIMGroup(r.Context(), current)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "scim_group_patch_failed", err.Error(), requestID(r), principal.TenantID)
		return
	}
	if err := h.store.ReplaceSCIMGroupMembers(r.Context(), principal.TenantID, current.ID, memberIDs); err != nil {
		writeErr(w, http.StatusBadRequest, "scim_group_members_failed", err.Error(), requestID(r), principal.TenantID)
		return
	}
	current, _ = h.store.GetSCIMGroupByID(r.Context(), principal.TenantID, current.ID)
	_ = h.publishAudit(r.Context(), "audit.auth.scim_group_updated", requestID(r), principal.TenantID, map[string]any{
		"group_id":     current.ID,
		"external_id":  current.ExternalID,
		"member_count": current.MemberCount,
		"actor":        principal.Actor,
	})
	writeSCIMJSON(w, http.StatusOK, scimGroupResource(current))
}

func (h *Handler) handleSCIMDeleteGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authenticateSCIMRequest(w, r, true)
	if !ok {
		return
	}
	if err := h.store.DeleteSCIMGroup(r.Context(), principal.TenantID, r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadRequest, "scim_group_delete_failed", err.Error(), requestID(r), principal.TenantID)
		return
	}
	_ = h.publishAudit(r.Context(), "audit.auth.scim_group_deleted", requestID(r), principal.TenantID, map[string]any{
		"group_id": r.PathValue("id"),
		"actor":    principal.Actor,
	})
	w.WriteHeader(http.StatusNoContent)
}
