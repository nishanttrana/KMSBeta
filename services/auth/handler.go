package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/metering"
)

type AuditPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

type Handler struct {
	store         Store
	logic         *AuthLogic
	events        AuditPublisher
	meter         *metering.Meter
	logger        *log.Logger
	healthChecker *SystemHealthChecker
	mux           *http.ServeMux
}

func NewHandler(store Store, logic *AuthLogic, events AuditPublisher, meter *metering.Meter, logger *log.Logger, healthChecker ...*SystemHealthChecker) *Handler {
	var checker *SystemHealthChecker
	if len(healthChecker) > 0 {
		checker = healthChecker[0]
	}
	h := &Handler{
		store:         store,
		logic:         logic,
		events:        events,
		meter:         meter,
		logger:        logger,
		healthChecker: checker,
	}
	h.mux = h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", h.handleRegister)
	mux.HandleFunc("GET /auth/register/{id}/status", h.handleRegistrationStatus)
	mux.HandleFunc("POST /auth/login", h.handleLogin)
	mux.HandleFunc("POST /auth/client-token", h.handleClientToken)
	mux.HandleFunc("GET /auth/system-health", h.withAuth(h.handleSystemHealth, "auth.self.read"))
	mux.HandleFunc("POST /auth/system-health/restart", h.withAuth(h.handleRestartSystemService, "auth.service.restart"))
	mux.HandleFunc("POST /auth/refresh", h.withAuth(h.handleRefresh, "auth.token.refresh"))
	mux.HandleFunc("POST /auth/change-password", h.withAuth(h.handleChangePassword, ""))

	mux.HandleFunc("POST /auth/register/{id}/activate", h.withAuth(h.handleActivateRegistration, "auth.client.activate"))
	mux.HandleFunc("POST /auth/logout", h.withAuth(h.handleLogout, "auth.session.logout"))
	mux.HandleFunc("GET /auth/me", h.withAuth(h.handleMe, "auth.self.read"))

	mux.HandleFunc("POST /tenants", h.withAuth(h.handleCreateTenant, "auth.tenant.write", "super-admin"))
	mux.HandleFunc("GET /tenants", h.withAuth(h.handleListTenants, "auth.tenant.read", "super-admin"))
	mux.HandleFunc("GET /tenants/{id}", h.withAuth(h.handleGetTenant, "auth.tenant.read", "super-admin"))
	mux.HandleFunc("PUT /tenants/{id}", h.withAuth(h.handleUpdateTenant, "auth.tenant.write", "super-admin"))
	mux.HandleFunc("POST /tenants/{id}/roles", h.withAuth(h.handleCreateTenantRole, "auth.role.write", "super-admin"))
	mux.HandleFunc("PUT /tenants/{id}/roles/{name}", h.withAuth(h.handleUpdateTenantRole, "auth.role.write", "super-admin"))
	mux.HandleFunc("DELETE /tenants/{id}/roles/{name}", h.withAuth(h.handleDeleteTenantRole, "auth.role.write", "super-admin"))

	mux.HandleFunc("GET /auth/users", h.withAuth(h.handleListUsers, "auth.user.read"))
	mux.HandleFunc("POST /auth/users", h.withAuth(h.handleCreateUser, "auth.user.write"))
	mux.HandleFunc("PUT /auth/users/{id}/role", h.withAuth(h.handleUpdateUserRole, "auth.user.write"))
	mux.HandleFunc("PUT /auth/users/{id}/status", h.withAuth(h.handleUpdateUserStatus, "auth.user.write"))
	mux.HandleFunc("POST /auth/users/{id}/reset-password", h.withAuth(h.handleResetUserPassword, "auth.user.write"))
	mux.HandleFunc("GET /auth/password-policy", h.withAuth(h.handleGetPasswordPolicy, "auth.user.read"))
	mux.HandleFunc("PUT /auth/password-policy", h.withAuth(h.handleUpdatePasswordPolicy, "auth.user.write"))
	mux.HandleFunc("GET /auth/security-policy", h.withAuth(h.handleGetSecurityPolicy, "auth.user.read"))
	mux.HandleFunc("PUT /auth/security-policy", h.withAuth(h.handleUpdateSecurityPolicy, "auth.user.write"))
	mux.HandleFunc("GET /auth/cli/status", h.withAuth(h.handleCLIStatus, "auth.user.read"))
	mux.HandleFunc("POST /auth/cli/session", h.withAuth(h.handleCLISession, "auth.user.read"))
	mux.HandleFunc("POST /auth/api-keys", h.withAuth(h.handleCreateAPIKey, "auth.api_key.write"))
	mux.HandleFunc("DELETE /auth/api-keys/{id}", h.withAuth(h.handleDeleteAPIKey, "auth.api_key.write"))

	mux.HandleFunc("GET /auth/clients", h.withAuth(h.handleListClients, "auth.client.read"))
	mux.HandleFunc("GET /auth/clients/{id}", h.withAuth(h.handleGetClient, "auth.client.read"))
	mux.HandleFunc("PUT /auth/clients/{id}", h.withAuth(h.handleUpdateClient, "auth.client.write"))
	mux.HandleFunc("POST /auth/clients/{id}/revoke", h.withAuth(h.handleRevokeClient, "auth.client.write"))
	mux.HandleFunc("POST /auth/clients/{id}/rotate-key", h.withAuth(h.handleRotateClientKey, "auth.client.write"))
	return mux
}

func (h *Handler) withAuth(next http.HandlerFunc, permission string, roles ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := requestID(r)
		raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
		if raw == "" {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "missing bearer token", reqID, "")
			return
		}
		claims, err := h.logic.ParseJWT(raw)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid token", reqID, "")
			return
		}
		if permission != "" && !contains(roles, claims.Role) && !hasPermission(claims.Permissions, permission) {
			writeErr(w, http.StatusForbidden, "forbidden", "insufficient permissions", reqID, claims.TenantID)
			return
		}
		next(w, r.WithContext(pkgauth.ContextWithClaims(r.Context(), claims)))
	}
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req struct {
		TenantID      string `json:"tenant_id"`
		ClientName    string `json:"client_name"`
		ClientType    string `json:"client_type"`
		InterfaceName string `json:"interface_name"`
		SubjectID     string `json:"subject_id"`
		Description   string `json:"description"`
		ContactEmail  string `json:"contact_email"`
		RequestedRole string `json:"requested_role"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	reg := ClientRegistration{
		ID:            NewID("reg"),
		TenantID:      strings.TrimSpace(req.TenantID),
		ClientName:    strings.TrimSpace(req.ClientName),
		ClientType:    strings.TrimSpace(req.ClientType),
		InterfaceName: strings.ToLower(strings.TrimSpace(req.InterfaceName)),
		SubjectID:     strings.TrimSpace(req.SubjectID),
		Description:   req.Description,
		ContactEmail:  req.ContactEmail,
		RequestedRole: req.RequestedRole,
		Status:        "pending",
		RateLimit:     1000,
	}
	if reg.TenantID == "" || reg.ClientName == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id and client_name are required", reqID, reg.TenantID)
		return
	}
	if reg.ClientType == "" {
		reg.ClientType = "service"
	}
	if reg.InterfaceName == "" {
		reg.InterfaceName = "rest"
	}
	if reg.SubjectID == "" {
		reg.SubjectID = reg.ClientName
	}
	if reg.InterfaceName == "" || reg.SubjectID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "interface_name and subject_id are required", reqID, reg.TenantID)
		return
	}
	if reg.RequestedRole == "" {
		reg.RequestedRole = "app-service"
	}
	tenant, err := h.store.GetTenant(r.Context(), reg.TenantID)
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusBadRequest, "bad_request", "unknown tenant_id", reqID, reg.TenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to validate tenant", reqID, reg.TenantID)
		return
	}
	if strings.TrimSpace(strings.ToLower(tenant.Status)) != "active" {
		writeErr(w, http.StatusForbidden, "forbidden", "tenant is not active", reqID, reg.TenantID)
		return
	}
	if err := h.store.CreateClientRegistration(r.Context(), reg); err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to create registration", reqID, reg.TenantID)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.client_registered", reqID, reg.TenantID, map[string]any{"registration_id": reg.ID}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, reg.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"registration_id": reg.ID,
		"status":          "pending",
		"message":         "Awaiting admin approval",
		"interface_name":  reg.InterfaceName,
		"subject_id":      reg.SubjectID,
		"request_id":      reqID,
	})
}

func (h *Handler) handleRegistrationStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id query parameter is required", reqID, "")
		return
	}
	reg, err := h.store.GetClientRegistration(r.Context(), tenantID, r.PathValue("id"))
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "registration not found", reqID, tenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read registration", reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"registration_id": reg.ID, "status": reg.Status, "request_id": reqID})
}

func (h *Handler) handleActivateRegistration(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	var req struct {
		TenantID          string   `json:"tenant_id"`
		ApprovalID        string   `json:"approval_id"`
		GovernanceEnabled bool     `json:"governance_enabled"`
		IPWhitelist       []string `json:"ip_whitelist"`
		RateLimit         int      `json:"rate_limit"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, claims.TenantID)
		return
	}
	tenantID := claims.TenantID
	if req.TenantID != "" {
		tenantID = req.TenantID
	}
	if req.GovernanceEnabled && req.ApprovalID == "" {
		// TODO: call governance service for M-of-N approval workflow.
		req.ApprovalID = "TODO-GOVERNANCE-HOOK"
	}
	if req.RateLimit <= 0 {
		req.RateLimit = 1000
	}
	if err := h.store.UpdateClientRegistrationSettings(r.Context(), tenantID, r.PathValue("id"), req.IPWhitelist, req.RateLimit); err != nil && !errors.Is(err, errNotFound) {
		writeErr(w, http.StatusBadRequest, "activation_failed", "failed to apply client settings", reqID, tenantID)
		return
	}
	rawKey, hash, prefix, err := GenerateAPIKey()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "key_generation_failed", "failed to generate api key", reqID, tenantID)
		return
	}
	defer pkgcrypto.Zeroize(hash)
	apiKey := APIKey{
		ID:          NewID("api"),
		TenantID:    tenantID,
		ClientID:    r.PathValue("id"),
		KeyHash:     hash,
		KeyPrefix:   prefix,
		Name:        "client:" + r.PathValue("id"),
		Permissions: []string{"kms.read", "kms.write"},
	}
	if err := h.store.ActivateClientRegistration(r.Context(), tenantID, r.PathValue("id"), apiKey, claims.UserID, req.ApprovalID); err != nil {
		writeErr(w, http.StatusBadRequest, "activation_failed", err.Error(), reqID, tenantID)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.client_activated", reqID, tenantID, map[string]any{"registration_id": r.PathValue("id"), "api_key_prefix": prefix}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"registration_id": r.PathValue("id"), "status": "approved", "api_key": rawKey, "api_key_prefix": prefix, "request_id": reqID})
}

func (h *Handler) handleClientToken(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req struct {
		TenantID      string   `json:"tenant_id"`
		ClientID      string   `json:"client_id"`
		SubjectID     string   `json:"subject_id"`
		InterfaceName string   `json:"interface_name"`
		Permissions   []string `json:"permissions"`
		TTLSeconds    int      `json:"ttl_seconds"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}

	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	clientID := strings.TrimSpace(req.ClientID)
	if tenantID == "" || clientID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id and client_id are required", reqID, tenantID)
		return
	}

	rawKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if rawKey == "" {
		authz := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(authz), "apikey ") {
			rawKey = strings.TrimSpace(authz[len("ApiKey "):])
		}
	}
	if rawKey == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "missing api key", reqID, tenantID)
		return
	}

	sum := sha256.Sum256([]byte(rawKey))
	apiKey, err := h.store.GetAPIKeyByHash(r.Context(), tenantID, sum[:])
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid api key", reqID, tenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to validate api key", reqID, tenantID)
		return
	}
	if apiKey.ExpiresAt != nil && time.Now().UTC().After(apiKey.ExpiresAt.UTC()) {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "api key is expired", reqID, tenantID)
		return
	}
	if strings.TrimSpace(apiKey.ClientID) == "" || !strings.EqualFold(strings.TrimSpace(apiKey.ClientID), clientID) {
		writeErr(w, http.StatusForbidden, "forbidden", "api key is not bound to requested client_id", reqID, tenantID)
		return
	}

	reg, err := h.store.GetClientRegistration(r.Context(), tenantID, clientID)
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "client registration not found", reqID, tenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read client registration", reqID, tenantID)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(reg.Status), "approved") {
		writeErr(w, http.StatusForbidden, "forbidden", "client registration is not approved", reqID, tenantID)
		return
	}

	boundSubject := strings.TrimSpace(reg.SubjectID)
	if boundSubject == "" {
		boundSubject = strings.TrimSpace(reg.ClientName)
	}
	requestedSubject := strings.TrimSpace(req.SubjectID)
	if requestedSubject != "" && !strings.EqualFold(boundSubject, requestedSubject) {
		writeErr(w, http.StatusForbidden, "forbidden", "subject_id is immutable for this registration", reqID, tenantID)
		return
	}
	interfaceName := strings.ToLower(strings.TrimSpace(reg.InterfaceName))
	if interfaceName == "" {
		interfaceName = "rest"
	}
	requestedInterface := strings.ToLower(strings.TrimSpace(req.InterfaceName))
	if requestedInterface != "" && requestedInterface != interfaceName {
		writeErr(w, http.StatusForbidden, "forbidden", "interface_name is immutable for this registration", reqID, tenantID)
		return
	}

	allowedSet := map[string]struct{}{}
	for _, p := range apiKey.Permissions {
		perm := strings.TrimSpace(p)
		if perm == "" {
			continue
		}
		allowedSet[perm] = struct{}{}
	}
	effectivePerms := make([]string, 0, len(allowedSet))
	if len(req.Permissions) > 0 {
		for _, p := range req.Permissions {
			perm := strings.TrimSpace(p)
			if perm == "" {
				continue
			}
			if _, ok := allowedSet[perm]; ok {
				effectivePerms = append(effectivePerms, perm)
			}
		}
	} else {
		for perm := range allowedSet {
			effectivePerms = append(effectivePerms, perm)
		}
	}
	if len(effectivePerms) == 0 {
		writeErr(w, http.StatusForbidden, "forbidden", "no permitted scopes for requested token", reqID, tenantID)
		return
	}

	ttlSeconds := req.TTLSeconds
	if ttlSeconds <= 0 {
		ttlSeconds = 300
	}
	if ttlSeconds < 60 {
		ttlSeconds = 60
	}
	if ttlSeconds > 3600 {
		ttlSeconds = 3600
	}

	token, exp, err := h.logic.IssueClientJWT(
		tenantID,
		clientID,
		boundSubject,
		interfaceName,
		effectivePerms,
		time.Duration(ttlSeconds)*time.Second,
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "jwt_issue_failed", "failed to issue client token", reqID, tenantID)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.client_token_issued", reqID, tenantID, map[string]any{
		"client_id":      clientID,
		"subject_id":     boundSubject,
		"interface_name": interfaceName,
		"ttl_seconds":    ttlSeconds,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":   token,
		"token_type":     "Bearer",
		"expires_at":     exp.UTC().Format(time.RFC3339),
		"tenant_id":      tenantID,
		"client_id":      clientID,
		"subject_id":     boundSubject,
		"interface_name": interfaceName,
		"request_id":     reqID,
	})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req struct {
		TenantID string `json:"tenant_id"`
		Username string `json:"username"`
		Password string `json:"password"`
		TOTPCode string `json:"totp_code"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	securityPolicy, err := h.resolveSecurityPolicy(r.Context(), req.TenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to resolve security policy", reqID, req.TenantID)
		return
	}
	lockoutWindow := time.Duration(securityPolicy.LockoutMinutes) * time.Minute
	loginUser := strings.ToLower(strings.TrimSpace(req.Username))
	rlKey := req.TenantID + "|" + loginUser + "|" + clientIP(r)
	if lockUntil, locked := h.logic.limiter.IsLocked(rlKey, time.Now().UTC()); locked {
		retryAfter := int(time.Until(lockUntil).Seconds())
		if retryAfter < 1 {
			retryAfter = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeJSON(w, http.StatusTooManyRequests, map[string]any{
			"error": map[string]any{
				"code":             "rate_limited",
				"message":          "too many failed attempts",
				"request_id":       reqID,
				"tenant_id":        req.TenantID,
				"retry_after_sec":  retryAfter,
				"locked_until_utc": lockUntil.UTC().Format(time.RFC3339),
			},
		})
		return
	}
	u, err := h.store.GetUserByUsername(r.Context(), req.TenantID, req.Username)
	if err != nil || !VerifyPassword(u.Password, req.Password) {
		_, _ = h.logic.limiter.FailWithPolicy(rlKey, time.Now().UTC(), securityPolicy.MaxFailedAttempts, lockoutWindow)
		writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid credentials", reqID, req.TenantID)
		return
	}
	if normalizeUserStatus(u.Status) != "active" {
		_, _ = h.logic.limiter.FailWithPolicy(rlKey, time.Now().UTC(), securityPolicy.MaxFailedAttempts, lockoutWindow)
		writeErr(w, http.StatusUnauthorized, "unauthorized", "user is disabled", reqID, req.TenantID)
		return
	}
	if len(u.TOTPSecret) > 0 && !ValidateTOTP(string(u.TOTPSecret), req.TOTPCode, time.Now().UTC()) {
		_, _ = h.logic.limiter.FailWithPolicy(rlKey, time.Now().UTC(), securityPolicy.MaxFailedAttempts, lockoutWindow)
		writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid mfa code", reqID, req.TenantID)
		return
	}
	perms, err := h.store.GetRolePermissions(r.Context(), req.TenantID, u.Role)
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "role not configured", reqID, req.TenantID)
		return
	}
	tokenPerms := perms
	if u.MustChangePassword {
		tokenPerms = []string{"auth.password.change"}
	}
	token, exp, err := h.logic.IssueJWT(req.TenantID, u.Role, tokenPerms, u.ID, u.MustChangePassword)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "jwt_issue_failed", "failed to issue token", reqID, req.TenantID)
		return
	}
	sHash := tokenHash(token)
	defer pkgcrypto.Zeroize(sHash)
	if err := h.store.CreateSession(r.Context(), Session{ID: NewID("sess"), TenantID: req.TenantID, UserID: u.ID, TokenHash: sHash, IPAddress: clientIP(r), UserAgent: r.UserAgent(), ExpiresAt: exp}); err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to create session", reqID, req.TenantID)
		return
	}
	h.logic.limiter.Reset(rlKey)
	if h.meter != nil {
		_ = h.meter.IncrementOps()
	}
	if err := h.publishAudit(r.Context(), "audit.auth.login", reqID, req.TenantID, map[string]any{"user_id": u.ID}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":         token,
		"token_type":           "Bearer",
		"expires_at":           exp.UTC().Format(time.RFC3339),
		"must_change_password": u.MustChangePassword,
		"security_policy": map[string]any{
			"max_failed_attempts":  securityPolicy.MaxFailedAttempts,
			"lockout_minutes":      securityPolicy.LockoutMinutes,
			"idle_timeout_minutes": securityPolicy.IdleTimeoutMinutes,
		},
		"request_id": reqID,
	})
}

func (h *Handler) handleRefresh(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	token, exp, err := h.logic.IssueJWT(claims.TenantID, claims.Role, claims.Permissions, claims.UserID, claims.MustChangePassword)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "jwt_issue_failed", "failed to refresh token", reqID, claims.TenantID)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.refresh", reqID, claims.TenantID, map[string]any{"user_id": claims.UserID}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, claims.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": token, "expires_at": exp.UTC().Format(time.RFC3339), "request_id": reqID})
}

func (h *Handler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, claims.TenantID)
		return
	}
	user, err := h.store.GetUserByID(r.Context(), claims.TenantID, claims.UserID)
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "user not found", reqID, claims.TenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read user", reqID, claims.TenantID)
		return
	}
	if !VerifyPassword(user.Password, req.CurrentPassword) {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid current password", reqID, claims.TenantID)
		return
	}
	if err := h.enforcePasswordPolicy(r.Context(), claims.TenantID, req.NewPassword, user.Username, user.Email); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, claims.TenantID)
		return
	}
	hash, err := HashPassword(req.NewPassword)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash_error", "failed to hash password", reqID, claims.TenantID)
		return
	}
	defer pkgcrypto.Zeroize(hash)
	if err := h.store.UpdateUserPassword(r.Context(), claims.TenantID, claims.UserID, hash, false); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "store_error", "failed to update password", reqID, claims.TenantID)
		return
	}
	perms, err := h.store.GetRolePermissions(r.Context(), claims.TenantID, user.Role)
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "role not configured", reqID, claims.TenantID)
		return
	}
	token, exp, err := h.logic.IssueJWT(claims.TenantID, user.Role, perms, claims.UserID, false)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "jwt_issue_failed", "failed to issue token", reqID, claims.TenantID)
		return
	}
	sHash := tokenHash(token)
	defer pkgcrypto.Zeroize(sHash)
	if err := h.store.CreateSession(r.Context(), Session{
		ID:        NewID("sess"),
		TenantID:  claims.TenantID,
		UserID:    claims.UserID,
		TokenHash: sHash,
		IPAddress: clientIP(r),
		UserAgent: r.UserAgent(),
		ExpiresAt: exp,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to create session", reqID, claims.TenantID)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.password_changed", reqID, claims.TenantID, map[string]any{"user_id": claims.UserID}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, claims.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":               "ok",
		"access_token":         token,
		"expires_at":           exp.UTC().Format(time.RFC3339),
		"must_change_password": false,
		"request_id":           reqID,
	})
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	var req struct {
		SessionID string `json:"session_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, claims.TenantID)
		return
	}
	if err := h.store.DeleteSession(r.Context(), claims.TenantID, req.SessionID); err != nil && !errors.Is(err, errNotFound) {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to invalidate session", reqID, claims.TenantID)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.logout", reqID, claims.TenantID, map[string]any{"user_id": claims.UserID, "session_id": req.SessionID}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, claims.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id":            claims.TenantID,
		"user_id":              claims.UserID,
		"role":                 claims.Role,
		"permissions":          claims.Permissions,
		"must_change_password": claims.MustChangePassword,
		"request_id":           reqID,
	})
}

func (h *Handler) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	h.tenantWrite(w, r, "create")
}
func (h *Handler) handleUpdateTenant(w http.ResponseWriter, r *http.Request) {
	h.tenantWrite(w, r, "update")
}
func (h *Handler) handleCreateTenantRole(w http.ResponseWriter, r *http.Request) {
	h.roleWrite(w, r, "create")
}
func (h *Handler) handleUpdateTenantRole(w http.ResponseWriter, r *http.Request) {
	h.roleWrite(w, r, "update")
}

func (h *Handler) handleListTenants(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	items, err := h.store.ListTenants(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to list tenants", reqID, "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetTenant(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	t, err := h.store.GetTenant(r.Context(), r.PathValue("id"))
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "tenant not found", reqID, r.PathValue("id"))
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to get tenant", reqID, r.PathValue("id"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant": t, "request_id": reqID})
}

func (h *Handler) tenantWrite(w http.ResponseWriter, r *http.Request, mode string) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	var req struct {
		ID                      string `json:"id"`
		Name                    string `json:"name"`
		Status                  string `json:"status"`
		AdminUsername           string `json:"admin_username"`
		AdminEmail              string `json:"admin_email"`
		AdminPassword           string `json:"admin_password"`
		AdminRole               string `json:"admin_role"`
		AdminStatus             string `json:"admin_status"`
		AdminMustChangePassword *bool  `json:"admin_must_change_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.ID)
		return
	}
	if req.Status == "" {
		req.Status = "active"
	}
	tenantID := req.ID
	if mode == "update" {
		tenantID = r.PathValue("id")
	}
	tenantID = strings.TrimSpace(tenantID)
	req.Name = strings.TrimSpace(req.Name)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant id is required", reqID, tenantID)
		return
	}
	if mode == "create" && req.Name == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant name is required", reqID, tenantID)
		return
	}
	t := Tenant{ID: tenantID, Name: req.Name, Status: req.Status}
	var err error
	createdUserID := ""
	if mode == "create" {
		err = h.store.CreateTenant(r.Context(), t)
		if err == nil {
			err = h.ensureTenantDefaults(r.Context(), tenantID)
		}
		if err == nil && (strings.TrimSpace(req.AdminUsername) != "" || strings.TrimSpace(req.AdminEmail) != "" || strings.TrimSpace(req.AdminPassword) != "") {
			createdUserID, err = h.createTenantAdminUser(
				r.Context(),
				tenantID,
				req.AdminUsername,
				req.AdminEmail,
				req.AdminPassword,
				req.AdminRole,
				req.AdminStatus,
				req.AdminMustChangePassword,
			)
		}
	} else {
		err = h.store.UpdateTenant(r.Context(), t)
	}
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "store_error", "tenant write failed", reqID, tenantID)
		return
	}
	subject := "audit.auth.tenant_created"
	if mode == "update" {
		subject = "audit.auth.tenant_updated"
	}
	if err := h.publishAudit(r.Context(), subject, reqID, tenantID, map[string]any{
		"tenant_id":       tenantID,
		"actor_user_id":   claims.UserID,
		"actor_tenant_id": claims.TenantID,
		"admin_user_id":   createdUserID,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"tenant_id":     tenantID,
		"admin_user_id": createdUserID,
		"request_id":    reqID,
	})
}

func (h *Handler) roleWrite(w http.ResponseWriter, r *http.Request, mode string) {
	reqID := requestID(r)
	var req struct {
		RoleName    string   `json:"role_name"`
		Permissions []string `json:"permissions"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, r.PathValue("id"))
		return
	}
	roleName := r.PathValue("name")
	if roleName == "" {
		roleName = req.RoleName
	}
	role := TenantRole{TenantID: r.PathValue("id"), RoleName: roleName, Permissions: req.Permissions}
	var err error
	if mode == "create" {
		err = h.store.CreateTenantRole(r.Context(), role)
	} else {
		err = h.store.UpdateTenantRole(r.Context(), role)
	}
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "store_error", "role write failed", reqID, role.TenantID)
		return
	}
	subject := "audit.auth.role_created"
	if mode == "update" {
		subject = "audit.auth.role_updated"
	}
	if err := h.publishAudit(r.Context(), subject, reqID, role.TenantID, map[string]any{"role_name": role.RoleName}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, role.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleDeleteTenantRole(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := r.PathValue("id")
	roleName := r.PathValue("name")
	if err := h.store.DeleteTenantRole(r.Context(), tenantID, roleName); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "store_error", "failed to delete role", reqID, tenantID)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.role_deleted", reqID, tenantID, map[string]any{"role_name": roleName}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleListUsers(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.read", r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	items, err := h.store.ListUsers(r.Context(), targetTenant)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to list users", reqID, targetTenant)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	var req struct {
		TenantID           string `json:"tenant_id"`
		Username           string `json:"username"`
		Email              string `json:"email"`
		Password           string `json:"password"`
		Role               string `json:"role"`
		Status             string `json:"status"`
		TOTPSecret         string `json:"totp_secret"`
		MustChangePassword bool   `json:"must_change_password"`
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
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)
	req.Role = strings.TrimSpace(req.Role)
	if req.Username == "" || req.Email == "" || req.Role == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "username, email, role and password are required", reqID, targetTenant)
		return
	}
	if _, err := h.store.GetTenant(r.Context(), targetTenant); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "store_error", "tenant not found", reqID, targetTenant)
		return
	}
	status := normalizeUserStatus(req.Status)
	if err := h.enforcePasswordPolicy(r.Context(), targetTenant, req.Password, req.Username, req.Email); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, targetTenant)
		return
	}
	hash, err := HashPassword(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash_error", "failed to hash password", reqID, targetTenant)
		return
	}
	defer pkgcrypto.Zeroize(hash)
	u := User{
		ID:                 NewID("usr"),
		TenantID:           targetTenant,
		Username:           req.Username,
		Email:              req.Email,
		Password:           hash,
		TOTPSecret:         []byte(req.TOTPSecret),
		Role:               req.Role,
		Status:             status,
		MustChangePassword: req.MustChangePassword,
	}
	if err := h.store.CreateUser(r.Context(), u); err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to create user", reqID, targetTenant)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.user_created", reqID, targetTenant, map[string]any{
		"user_id":        u.ID,
		"actor_user_id":  claims.UserID,
		"actor_tenant":   claims.TenantID,
		"created_tenant": targetTenant,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, targetTenant)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user_id": u.ID, "request_id": reqID})
}

func (h *Handler) handleUpdateUserRole(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.write", r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, targetTenant)
		return
	}
	user, err := h.store.GetUserByID(r.Context(), targetTenant, r.PathValue("id"))
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "user not found", reqID, targetTenant)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read user", reqID, targetTenant)
		return
	}
	req.Role = strings.TrimSpace(req.Role)
	if req.Role == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "role is required", reqID, targetTenant)
		return
	}
	cliUsername := strings.TrimSpace(envOr("AUTH_BOOTSTRAP_CLI_USERNAME", "cli-user"))
	if strings.EqualFold(user.Username, cliUsername) && strings.TrimSpace(strings.ToLower(user.Role)) == "cli-user" && req.Role != user.Role {
		writeErr(w, http.StatusBadRequest, "bad_request", "default CLI user role cannot be changed", reqID, targetTenant)
		return
	}
	if err := h.store.UpdateUserRole(r.Context(), targetTenant, r.PathValue("id"), req.Role); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "store_error", "failed to update user role", reqID, targetTenant)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.user_role_updated", reqID, targetTenant, map[string]any{
		"user_id":        r.PathValue("id"),
		"role":           req.Role,
		"actor_user_id":  claims.UserID,
		"actor_tenant":   claims.TenantID,
		"updated_tenant": targetTenant,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, targetTenant)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleUpdateUserStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.write", r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, targetTenant)
		return
	}
	status := normalizeUserStatus(req.Status)
	if err := h.store.UpdateUserStatus(r.Context(), targetTenant, r.PathValue("id"), status); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "store_error", "failed to update user status", reqID, targetTenant)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.user_status_updated", reqID, targetTenant, map[string]any{
		"user_id":        r.PathValue("id"),
		"status":         status,
		"actor_user_id":  claims.UserID,
		"actor_tenant":   claims.TenantID,
		"updated_tenant": targetTenant,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, targetTenant)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleResetUserPassword(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	targetTenant, err := h.resolveTenantScope(r, claims, "auth.tenant.write", r.URL.Query().Get("tenant_id"))
	if err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", err.Error(), reqID, claims.TenantID)
		return
	}
	var req struct {
		NewPassword        string `json:"new_password"`
		MustChangePassword *bool  `json:"must_change_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, targetTenant)
		return
	}
	if strings.TrimSpace(req.NewPassword) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "new_password is required", reqID, targetTenant)
		return
	}
	targetUser, err := h.store.GetUserByID(r.Context(), targetTenant, r.PathValue("id"))
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "user not found", reqID, targetTenant)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read user", reqID, targetTenant)
		return
	}
	cliUsername := strings.TrimSpace(envOr("AUTH_BOOTSTRAP_CLI_USERNAME", "cli-user"))
	if strings.EqualFold(targetUser.Username, cliUsername) && !isAdminRole(claims.Role) {
		writeErr(w, http.StatusForbidden, "forbidden", "default CLI user password can only be reset by admin", reqID, targetTenant)
		return
	}
	if err := h.enforcePasswordPolicy(r.Context(), targetTenant, req.NewPassword, targetUser.Username, targetUser.Email); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, targetTenant)
		return
	}
	hash, err := HashPassword(req.NewPassword)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash_error", "failed to hash password", reqID, targetTenant)
		return
	}
	defer pkgcrypto.Zeroize(hash)
	mustChange := true
	if req.MustChangePassword != nil {
		mustChange = *req.MustChangePassword
	}
	if err := h.store.UpdateUserPassword(r.Context(), targetTenant, targetUser.ID, hash, mustChange); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "store_error", "failed to reset password", reqID, targetTenant)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.user_password_reset", reqID, targetTenant, map[string]any{
		"user_id":              targetUser.ID,
		"must_change_password": mustChange,
		"actor_user_id":        claims.UserID,
		"actor_tenant":         claims.TenantID,
		"updated_tenant":       targetTenant,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, targetTenant)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleGetPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	policy, err := h.resolvePasswordPolicy(r.Context(), claims.TenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read password policy", reqID, claims.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": policy, "request_id": reqID})
}

func (h *Handler) handleUpdatePasswordPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	existing, err := h.resolvePasswordPolicy(r.Context(), claims.TenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read current password policy", reqID, claims.TenantID)
		return
	}
	var req struct {
		MinLength      *int  `json:"min_length"`
		MaxLength      *int  `json:"max_length"`
		RequireUpper   *bool `json:"require_upper"`
		RequireLower   *bool `json:"require_lower"`
		RequireDigit   *bool `json:"require_digit"`
		RequireSpecial *bool `json:"require_special"`
		RequireNoSpace *bool `json:"require_no_whitespace"`
		DenyUsername   *bool `json:"deny_username"`
		DenyEmailLocal *bool `json:"deny_email_local_part"`
		MinUniqueChars *int  `json:"min_unique_chars"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, claims.TenantID)
		return
	}
	policy := existing
	if req.MinLength != nil {
		policy.MinLength = *req.MinLength
	}
	if req.MaxLength != nil {
		policy.MaxLength = *req.MaxLength
	}
	if req.RequireUpper != nil {
		policy.RequireUpper = *req.RequireUpper
	}
	if req.RequireLower != nil {
		policy.RequireLower = *req.RequireLower
	}
	if req.RequireDigit != nil {
		policy.RequireDigit = *req.RequireDigit
	}
	if req.RequireSpecial != nil {
		policy.RequireSpecial = *req.RequireSpecial
	}
	if req.RequireNoSpace != nil {
		policy.RequireNoSpace = *req.RequireNoSpace
	}
	if req.DenyUsername != nil {
		policy.DenyUsername = *req.DenyUsername
	}
	if req.DenyEmailLocal != nil {
		policy.DenyEmailLocal = *req.DenyEmailLocal
	}
	if req.MinUniqueChars != nil {
		policy.MinUniqueChars = *req.MinUniqueChars
	}
	policy = NormalizePasswordPolicy(policy, claims.TenantID)
	if policy.MinLength < 8 {
		policy.MinLength = 8
	}
	if policy.MaxLength > 256 {
		policy.MaxLength = 256
	}
	if policy.MaxLength < policy.MinLength {
		policy.MaxLength = policy.MinLength
	}
	if policy.MinUniqueChars > policy.MinLength {
		policy.MinUniqueChars = policy.MinLength
	}
	policy.UpdatedBy = claims.UserID

	updated, err := h.store.UpsertPasswordPolicy(r.Context(), policy)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to update password policy", reqID, claims.TenantID)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.password_policy_updated", reqID, claims.TenantID, map[string]any{
		"min_length":       updated.MinLength,
		"max_length":       updated.MaxLength,
		"min_unique_chars": updated.MinUniqueChars,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, claims.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": updated, "request_id": reqID})
}

func (h *Handler) handleGetSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	policy, err := h.resolveSecurityPolicy(r.Context(), claims.TenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read security policy", reqID, claims.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": policy, "request_id": reqID})
}

func (h *Handler) handleUpdateSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	existing, err := h.resolveSecurityPolicy(r.Context(), claims.TenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read current security policy", reqID, claims.TenantID)
		return
	}
	var req struct {
		MaxFailedAttempts  *int `json:"max_failed_attempts"`
		LockoutMinutes     *int `json:"lockout_minutes"`
		IdleTimeoutMinutes *int `json:"idle_timeout_minutes"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, claims.TenantID)
		return
	}
	policy := existing
	if req.MaxFailedAttempts != nil {
		policy.MaxFailedAttempts = *req.MaxFailedAttempts
	}
	if req.LockoutMinutes != nil {
		policy.LockoutMinutes = *req.LockoutMinutes
	}
	if req.IdleTimeoutMinutes != nil {
		policy.IdleTimeoutMinutes = *req.IdleTimeoutMinutes
	}
	policy = NormalizeSecurityPolicy(policy, claims.TenantID)
	policy.UpdatedBy = claims.UserID
	updated, err := h.store.UpsertSecurityPolicy(r.Context(), policy)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to update security policy", reqID, claims.TenantID)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.security_policy_updated", reqID, claims.TenantID, map[string]any{
		"max_failed_attempts":  updated.MaxFailedAttempts,
		"lockout_minutes":      updated.LockoutMinutes,
		"idle_timeout_minutes": updated.IdleTimeoutMinutes,
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, claims.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": updated, "request_id": reqID})
}

func (h *Handler) handleCLIStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	cliUsername := strings.TrimSpace(envOr("AUTH_BOOTSTRAP_CLI_USERNAME", "cli-user"))
	cliHost := strings.TrimSpace(envOr("AUTH_CLI_HOST", "127.0.0.1"))
	cliPort := parseCLIPort()
	enabled := false

	if user, err := h.store.GetUserByUsername(r.Context(), claims.TenantID, cliUsername); err == nil {
		enabled = normalizeUserStatus(user.Status) == "active" && strings.EqualFold(strings.TrimSpace(user.Role), "cli-user")
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":                       enabled,
		"cli_username":                  cliUsername,
		"host":                          cliHost,
		"port":                          cliPort,
		"transport":                     "ssh",
		"requires_additional_auth":      true,
		"default_cli_user_protected":    true,
		"request_id":                    reqID,
		"fips_boundary_aware_transport": true,
	})
}

func (h *Handler) handleCLISession(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	if !isAdminRole(claims.Role) {
		writeErr(w, http.StatusForbidden, "forbidden", "admin role required for CLI launch", reqID, claims.TenantID)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, claims.TenantID)
		return
	}
	cliUsername := strings.TrimSpace(envOr("AUTH_BOOTSTRAP_CLI_USERNAME", "cli-user"))
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "username and password are required", reqID, claims.TenantID)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(req.Username), cliUsername) {
		writeErr(w, http.StatusForbidden, "forbidden", "only the configured CLI user is allowed", reqID, claims.TenantID)
		return
	}
	cliUser, err := h.store.GetUserByUsername(r.Context(), claims.TenantID, cliUsername)
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusBadRequest, "bad_request", "configured CLI user does not exist", reqID, claims.TenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to read CLI user", reqID, claims.TenantID)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(cliUser.Role), "cli-user") {
		writeErr(w, http.StatusBadRequest, "bad_request", "configured CLI user role mismatch", reqID, claims.TenantID)
		return
	}
	if normalizeUserStatus(cliUser.Status) != "active" {
		writeErr(w, http.StatusForbidden, "forbidden", "CLI user is disabled", reqID, claims.TenantID)
		return
	}
	if !VerifyPassword(cliUser.Password, req.Password) {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid CLI credentials", reqID, claims.TenantID)
		return
	}
	host := strings.TrimSpace(envOr("AUTH_CLI_HOST", "127.0.0.1"))
	port := parseCLIPort()
	sshCommand := fmt.Sprintf("ssh %s@%s -p %d", cliUsername, host, port)
	puttyURI := fmt.Sprintf("putty://%s@%s:%d", cliUsername, host, port)
	sessionID := NewID("clisess")
	expiresAt := time.Now().UTC().Add(5 * time.Minute)

	if err := h.publishAudit(r.Context(), "audit.auth.cli_session_opened", reqID, claims.TenantID, map[string]any{
		"initiator_user_id": claims.UserID,
		"cli_username":      cliUsername,
		"cli_session_id":    sessionID,
		"expires_at":        expiresAt.Format(time.RFC3339),
	}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, claims.TenantID)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "ok",
		"cli_session_id":  sessionID,
		"expires_at":      expiresAt.Format(time.RFC3339),
		"putty_uri":       puttyURI,
		"ssh_command":     sshCommand,
		"host":            host,
		"port":            port,
		"username":        cliUsername,
		"request_id":      reqID,
		"additional_auth": true,
	})
}

func (h *Handler) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	var req struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, claims.TenantID)
		return
	}
	rawKey, hash, prefix, err := GenerateAPIKey()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "key_generation_failed", "failed to create api key", reqID, claims.TenantID)
		return
	}
	defer pkgcrypto.Zeroize(hash)
	key := APIKey{
		ID:          NewID("api"),
		TenantID:    claims.TenantID,
		UserID:      claims.UserID,
		KeyHash:     hash,
		KeyPrefix:   prefix,
		Name:        req.Name,
		Permissions: req.Permissions,
	}
	if err := h.store.CreateAPIKey(r.Context(), key); err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to create api key", reqID, claims.TenantID)
		return
	}
	if h.meter != nil {
		_ = h.meter.IncrementOps()
	}
	if err := h.publishAudit(r.Context(), "audit.auth.api_key_created", reqID, claims.TenantID, map[string]any{"api_key_id": key.ID, "api_key_prefix": prefix}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, claims.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"api_key_id": key.ID, "api_key": rawKey, "api_key_prefix": prefix, "request_id": reqID})
}

func (h *Handler) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	if err := h.store.DeleteAPIKey(r.Context(), claims.TenantID, r.PathValue("id")); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "store_error", "failed to delete api key", reqID, claims.TenantID)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.api_key_revoked", reqID, claims.TenantID, map[string]any{"api_key_id": r.PathValue("id")}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, claims.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleListClients(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	items, err := h.store.ListClientRegistrations(r.Context(), claims.TenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to list clients", reqID, claims.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetClient(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	item, err := h.store.GetClientRegistration(r.Context(), claims.TenantID, r.PathValue("id"))
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "client not found", reqID, claims.TenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store_error", "failed to get client", reqID, claims.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"client": item, "request_id": reqID})
}

func (h *Handler) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	var req struct {
		IPWhitelist []string `json:"ip_whitelist"`
		RateLimit   int      `json:"rate_limit"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, claims.TenantID)
		return
	}
	if req.RateLimit <= 0 {
		req.RateLimit = 1000
	}
	if err := h.store.UpdateClientRegistrationSettings(r.Context(), claims.TenantID, r.PathValue("id"), req.IPWhitelist, req.RateLimit); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "store_error", "failed to update client", reqID, claims.TenantID)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.client_updated", reqID, claims.TenantID, map[string]any{"client_id": r.PathValue("id")}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, claims.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleRevokeClient(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	if err := h.store.RevokeClientRegistration(r.Context(), claims.TenantID, r.PathValue("id")); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "store_error", "failed to revoke client", reqID, claims.TenantID)
		return
	}
	if err := h.publishAudit(r.Context(), "audit.auth.client_revoked", reqID, claims.TenantID, map[string]any{"client_id": r.PathValue("id")}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, claims.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleRotateClientKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	claims, _ := pkgauth.ClaimsFromContext(r.Context())
	rawKey, hash, prefix, err := GenerateAPIKey()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "key_generation_failed", "failed to rotate key", reqID, claims.TenantID)
		return
	}
	defer pkgcrypto.Zeroize(hash)
	if err := h.store.RotateClientAPIKey(r.Context(), claims.TenantID, r.PathValue("id"), hash, prefix); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "store_error", "failed to rotate key", reqID, claims.TenantID)
		return
	}
	if h.meter != nil {
		_ = h.meter.IncrementOps()
	}
	if err := h.publishAudit(r.Context(), "audit.auth.client_key_rotated", reqID, claims.TenantID, map[string]any{"client_id": r.PathValue("id"), "api_key_prefix": prefix}); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "event_publish_failed", "failed to publish audit event", reqID, claims.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_key": rawKey, "api_key_prefix": prefix, "request_id": reqID})
}

func (h *Handler) resolveTenantScope(r *http.Request, claims *pkgauth.Claims, crossTenantPerm string, candidates ...string) (string, error) {
	targetTenant := strings.TrimSpace(claims.TenantID)
	for _, c := range candidates {
		if strings.TrimSpace(c) != "" {
			targetTenant = strings.TrimSpace(c)
			break
		}
	}
	if targetTenant == claims.TenantID {
		return targetTenant, nil
	}
	if targetTenant == "" {
		return "", errors.New("tenant_id is required")
	}
	if !h.canCrossTenant(claims, crossTenantPerm) {
		return "", errors.New("cross-tenant operation requires tenant management permission")
	}
	return targetTenant, nil
}

func (h *Handler) canCrossTenant(claims *pkgauth.Claims, perm string) bool {
	if claims == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(claims.Role), "super-admin") {
		return true
	}
	if hasPermission(claims.Permissions, "auth.tenant.write") || hasPermission(claims.Permissions, "auth.tenant.read") {
		return true
	}
	if strings.TrimSpace(perm) != "" && hasPermission(claims.Permissions, strings.TrimSpace(perm)) {
		return true
	}
	return hasPermission(claims.Permissions, "*")
}

func (h *Handler) ensureTenantDefaults(ctx context.Context, tenantID string) error {
	roleCatalog := []TenantRole{
		{TenantID: tenantID, RoleName: "admin", Permissions: []string{"*"}},
		{TenantID: tenantID, RoleName: "tenant-admin", Permissions: []string{"*"}},
		{TenantID: tenantID, RoleName: "backup", Permissions: []string{"auth.self.read", "auth.user.read", "auth.client.read"}},
		{TenantID: tenantID, RoleName: "audit", Permissions: []string{"auth.self.read", "auth.user.read", "auth.client.read"}},
		{TenantID: tenantID, RoleName: "readonly", Permissions: []string{"auth.self.read", "auth.user.read"}},
		{TenantID: tenantID, RoleName: "cli-user", Permissions: []string{"auth.self.read"}},
	}
	for _, role := range roleCatalog {
		if _, err := h.store.GetRolePermissions(ctx, tenantID, role.RoleName); errors.Is(err, errNotFound) {
			if err := h.store.CreateTenantRole(ctx, role); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}

	if _, err := h.store.GetPasswordPolicy(ctx, tenantID); errors.Is(err, errNotFound) {
		policy := NormalizePasswordPolicy(DefaultPasswordPolicy(tenantID), tenantID)
		policy.UpdatedBy = "tenant-bootstrap"
		if _, err := h.store.UpsertPasswordPolicy(ctx, policy); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if _, err := h.store.GetSecurityPolicy(ctx, tenantID); errors.Is(err, errNotFound) {
		policy := NormalizeSecurityPolicy(DefaultSecurityPolicy(tenantID), tenantID)
		policy.UpdatedBy = "tenant-bootstrap"
		if _, err := h.store.UpsertSecurityPolicy(ctx, policy); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}

func (h *Handler) createTenantAdminUser(
	ctx context.Context,
	tenantID string,
	adminUsername string,
	adminEmail string,
	adminPassword string,
	adminRole string,
	adminStatus string,
	adminMustChangePassword *bool,
) (string, error) {
	username := strings.TrimSpace(adminUsername)
	email := strings.TrimSpace(adminEmail)
	password := strings.TrimSpace(adminPassword)
	role := strings.TrimSpace(adminRole)
	if role == "" {
		role = "tenant-admin"
	}
	if username == "" || email == "" || password == "" {
		return "", errors.New("admin_username, admin_email and admin_password are required to create tenant admin")
	}

	if _, err := h.store.GetRolePermissions(ctx, tenantID, role); errors.Is(err, errNotFound) {
		if err := h.store.CreateTenantRole(ctx, TenantRole{
			TenantID:    tenantID,
			RoleName:    role,
			Permissions: []string{"*"},
		}); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}

	if err := h.enforcePasswordPolicy(ctx, tenantID, password, username, email); err != nil {
		return "", err
	}

	hash, err := HashPassword(password)
	if err != nil {
		return "", err
	}
	defer pkgcrypto.Zeroize(hash)

	mustChange := true
	if adminMustChangePassword != nil {
		mustChange = *adminMustChangePassword
	}
	user := User{
		ID:                 NewID("usr"),
		TenantID:           tenantID,
		Username:           username,
		Email:              email,
		Password:           hash,
		Role:               role,
		Status:             normalizeUserStatus(adminStatus),
		MustChangePassword: mustChange,
	}
	if err := h.store.CreateUser(ctx, user); err != nil {
		return "", err
	}
	return user.ID, nil
}

func (h *Handler) publishAudit(ctx context.Context, subject string, requestID string, tenantID string, data map[string]any) error {
	if h.events == nil {
		return nil
	}
	raw, err := json.Marshal(map[string]any{
		"request_id": requestID,
		"tenant_id":  tenantID,
		"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
		"data":       data,
	})
	if err != nil {
		return err
	}
	return h.events.Publish(ctx, subject, raw)
}

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id != "" {
		return id
	}
	return NewID("req")
}

func clientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func hasPermission(perms []string, needed string) bool {
	for _, p := range perms {
		if p == needed || p == "*" {
			return true
		}
	}
	return false
}

func normalizeUserStatus(status string) string {
	switch strings.TrimSpace(strings.ToLower(status)) {
	case "active", "":
		return "active"
	case "inactive", "disabled", "locked", "suspended":
		return "inactive"
	default:
		return "inactive"
	}
}

func isAdminRole(role string) bool {
	r := strings.TrimSpace(strings.ToLower(role))
	return r == "admin" || r == "tenant-admin" || r == "super-admin"
}

func parseCLIPort() int {
	raw := strings.TrimSpace(envOr("AUTH_CLI_PORT", "22"))
	port, err := strconv.Atoi(raw)
	if err != nil || port <= 0 || port > 65535 {
		return 22
	}
	return port
}

func (h *Handler) resolvePasswordPolicy(ctx context.Context, tenantID string) (PasswordPolicy, error) {
	policy, err := h.store.GetPasswordPolicy(ctx, tenantID)
	if errors.Is(err, errNotFound) {
		return NormalizePasswordPolicy(DefaultPasswordPolicy(tenantID), tenantID), nil
	}
	if err != nil {
		return PasswordPolicy{}, err
	}
	return NormalizePasswordPolicy(policy, tenantID), nil
}

func (h *Handler) resolveSecurityPolicy(ctx context.Context, tenantID string) (SecurityPolicy, error) {
	policy, err := h.store.GetSecurityPolicy(ctx, tenantID)
	if errors.Is(err, errNotFound) {
		return NormalizeSecurityPolicy(DefaultSecurityPolicy(tenantID), tenantID), nil
	}
	if err != nil {
		return SecurityPolicy{}, err
	}
	return NormalizeSecurityPolicy(policy, tenantID), nil
}

func (h *Handler) enforcePasswordPolicy(ctx context.Context, tenantID string, password string, username string, email string) error {
	policy, err := h.resolvePasswordPolicy(ctx, tenantID)
	if err != nil {
		return err
	}
	return ValidatePasswordAgainstPolicy(policy, password, username, email)
}

func contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, code string, message string, requestID string, tenantID string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":       code,
			"message":    message,
			"request_id": requestID,
			"tenant_id":  tenantID,
		},
	})
}
