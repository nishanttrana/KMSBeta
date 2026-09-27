package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"vecta-kms/pkg/oidc"
)

var googleCSEProvider = NewGoogleCSEProvider(nil)

// Google signs CSE authorization tokens with per-application service
// accounts (gsuitecse-tokenissuer-<app>@system.gserviceaccount.com) whose
// keys are published at the service-account JWK endpoint. The token must
// verify against them, with audience "cse-authorization".
var (
	kaclsVerifier = oidc.NewVerifier()
	kaclsIssuerRE = regexp.MustCompile(`^gsuitecse-tokenissuer-[a-z0-9-]+@system\.gserviceaccount\.com$`)
	kaclsJWKSURL  = func(issuer string) string {
		return "https://www.googleapis.com/service_accounts/v1/jwk/" + url.PathEscape(issuer)
	}
)

// verifyKACLSAuthorization verifies a Google CSE authorization token and
// returns its claims. Nothing is read from an unverified token.
func verifyKACLSAuthorization(ctx context.Context, token string) (GoogleCSEClaims, error) {
	issuer, err := oidc.UnverifiedIssuer(token)
	if err != nil {
		return GoogleCSEClaims{}, err
	}
	if !kaclsIssuerRE.MatchString(issuer) {
		return GoogleCSEClaims{}, fmt.Errorf("authorization token issuer %q is not a Google CSE token issuer", issuer)
	}
	claims, err := kaclsVerifier.VerifyJWT(ctx, token, kaclsJWKSURL(issuer), issuer, "cse-authorization", time.Now())
	if err != nil {
		return GoogleCSEClaims{}, err
	}
	str := func(k string) string { v, _ := claims[k].(string); return strings.TrimSpace(v) }
	out := GoogleCSEClaims{Email: str("email"), ResourceName: str("resource_name"), KeyURI: str("kacls_url"), Issuer: issuer}
	if out.Email == "" {
		return GoogleCSEClaims{}, fmt.Errorf("authorization token has no email")
	}
	return out, nil
}

const kaclsVersion = "1.0.0"

// ═══════════════════════ MANAGEMENT HANDLERS ═══════════════════════

func (h *Handler) handleCreateGoogleCSEConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateGoogleCSEConfigRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, _, err := tenantFromRequest(r, req.TenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	req.TenantID = tenantID

	if strings.TrimSpace(req.GoogleWorkspaceCustomerID) == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "google_workspace_customer_id is required"), reqID, tenantID)
		return
	}
	if len(req.AllowedDomains) == 0 {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "allowed_domains is required (at least one domain)"), reqID, tenantID)
		return
	}
	req.AuthenticationClientIDs = cleanStrings(req.AuthenticationClientIDs)
	if len(req.AuthenticationClientIDs) == 0 {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "authentication_client_ids is required (the OAuth client ID of your CSE identity provider)"), reqID, tenantID)
		return
	}

	cfg := GoogleCSEConfig{
		ID:                        newID("gcse"),
		TenantID:                  tenantID,
		GoogleWorkspaceCustomerID: strings.TrimSpace(req.GoogleWorkspaceCustomerID),
		ServiceAccountEmail:       strings.TrimSpace(req.ServiceAccountEmail),
		ServiceAccountKeyJSON:     strings.TrimSpace(req.ServiceAccountKeyJSON),
		AllowedDomains:            req.AllowedDomains,
		AuthenticationClientIDs:   req.AuthenticationClientIDs,
		KACLSEndpoint:             strings.TrimSpace(req.KACLSEndpoint),
		Status:                    "active",
		KeyCount:                  0,
	}

	if err := h.svc.store.CreateGoogleCSEConfig(r.Context(), cfg); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	h.publishAuditEvent(r.Context(), tenantID, "google_cse.config.created", cfg.ID)

	// Mask service account key in response
	cfg.ServiceAccountKeyJSON = maskSecret(cfg.ServiceAccountKeyJSON)
	writeJSON(w, http.StatusCreated, map[string]interface{}{"config": cfg, "request_id": reqID})
}

func (h *Handler) handleListGoogleCSEConfigs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	items, err := h.svc.store.ListGoogleCSEConfigs(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	for i := range items {
		items[i].ServiceAccountKeyJSON = maskSecret(items[i].ServiceAccountKeyJSON)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetGoogleCSEConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	cfg, err := h.svc.store.GetGoogleCSEConfig(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	cfg.ServiceAccountKeyJSON = maskSecret(cfg.ServiceAccountKeyJSON)
	writeJSON(w, http.StatusOK, map[string]interface{}{"config": cfg, "request_id": reqID})
}

func (h *Handler) handleUpdateGoogleCSEConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateGoogleCSEConfigRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, _, err := tenantFromRequest(r, req.TenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}

	existing, err := h.svc.store.GetGoogleCSEConfig(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	existing.GoogleWorkspaceCustomerID = coalesceStr(strings.TrimSpace(req.GoogleWorkspaceCustomerID), existing.GoogleWorkspaceCustomerID)
	existing.ServiceAccountEmail = coalesceStr(strings.TrimSpace(req.ServiceAccountEmail), existing.ServiceAccountEmail)
	if strings.TrimSpace(req.ServiceAccountKeyJSON) != "" {
		existing.ServiceAccountKeyJSON = strings.TrimSpace(req.ServiceAccountKeyJSON)
	}
	if len(req.AllowedDomains) > 0 {
		existing.AllowedDomains = req.AllowedDomains
	}
	if ids := cleanStrings(req.AuthenticationClientIDs); len(ids) > 0 {
		existing.AuthenticationClientIDs = ids
	}
	existing.KACLSEndpoint = coalesceStr(strings.TrimSpace(req.KACLSEndpoint), existing.KACLSEndpoint)

	if err := h.svc.store.UpdateGoogleCSEConfig(r.Context(), existing); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	h.publishAuditEvent(r.Context(), tenantID, "google_cse.config.updated", existing.ID)

	existing.ServiceAccountKeyJSON = maskSecret(existing.ServiceAccountKeyJSON)
	writeJSON(w, http.StatusOK, map[string]interface{}{"config": existing, "request_id": reqID})
}

func (h *Handler) handleDeleteGoogleCSEConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	configID := r.PathValue("id")
	if err := h.svc.store.DeleteGoogleCSEConfig(r.Context(), tenantID, configID); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	h.publishAuditEvent(r.Context(), tenantID, "google_cse.config.deleted", configID)
	writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": true, "config_id": configID, "request_id": reqID})
}

func (h *Handler) handleCreateGoogleCSEKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateGoogleCSEKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, _, err := tenantFromRequest(r, req.TenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}

	if strings.TrimSpace(req.ConfigID) == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "config_id is required"), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.KeyName) == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "key_name is required"), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.VectaKeyID) == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "vecta_key_id is required"), reqID, tenantID)
		return
	}

	// Verify the config exists
	cfg, err := h.svc.store.GetGoogleCSEConfig(r.Context(), tenantID, req.ConfigID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	purpose := strings.ToLower(strings.TrimSpace(req.Purpose))
	if purpose == "" {
		purpose = "drive"
	}

	keyID := newID("gkey")

	// The key URI Google calls is under this deployment's own KACLS
	// endpoint; there is no placeholder host to fall back to.
	kaclsEndpoint := strings.TrimRight(cfg.KACLSEndpoint, "/")
	if kaclsEndpoint == "" {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", "the CSE config has no kacls_endpoint; set the public URL Google calls first"), reqID, tenantID)
		return
	}
	googleKeyURI := fmt.Sprintf("%s/keys/%s", kaclsEndpoint, keyID)

	key := GoogleCSEKey{
		ID:           keyID,
		TenantID:     tenantID,
		ConfigID:     strings.TrimSpace(req.ConfigID),
		KeyName:      strings.TrimSpace(req.KeyName),
		VectaKeyID:   strings.TrimSpace(req.VectaKeyID),
		GoogleKeyURI: googleKeyURI,
		Purpose:      purpose,
		Status:       "active",
	}

	if err := h.svc.store.CreateGoogleCSEKey(r.Context(), key); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	// Update config key count
	cfg.KeyCount++
	_ = h.svc.store.UpdateGoogleCSEConfig(r.Context(), cfg)

	h.publishAuditEvent(r.Context(), tenantID, "google_cse.key.created", key.ID)
	writeJSON(w, http.StatusCreated, map[string]interface{}{"key": key, "request_id": reqID})
}

func (h *Handler) handleListGoogleCSEKeys(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	configID := strings.TrimSpace(r.URL.Query().Get("config_id"))
	items, err := h.svc.store.ListGoogleCSEKeys(r.Context(), tenantID, configID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleDeleteGoogleCSEKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	keyID := r.PathValue("id")
	if err := h.svc.store.DeleteGoogleCSEKey(r.Context(), tenantID, keyID); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	h.publishAuditEvent(r.Context(), tenantID, "google_cse.key.deleted", keyID)
	writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": true, "key_id": keyID, "request_id": reqID})
}

// ═══════════════════════ KACLS API HANDLERS ═══════════════════════
// These endpoints are called by Google's CSE infrastructure per the KACLS specification.

func (h *Handler) handleKACLSStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"server_type": "KACLS",
		"vendor":      "Vecta KMS",
		"version":     kaclsVersion,
		"name":        "Vecta KMS KACLS Service",
	})
}

func (h *Handler) handleKACLSWrap(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)

	var req KACLSWrapRequest
	if err := decodeKACLSJSON(r, &req); err != nil {
		writeKACLSError(w, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}

	if strings.TrimSpace(req.Authentication) == "" {
		writeKACLSError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "authentication token is required")
		return
	}
	if strings.TrimSpace(req.Authorization) == "" {
		writeKACLSError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "authorization token is required")
		return
	}
	if strings.TrimSpace(req.Key) == "" {
		writeKACLSError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "key (DEK) is required")
		return
	}

	// Resolve the tenant and config from the authorization JWT
	tenantID, cseKey, authClaims, err := h.resolveKACLSContext(r, req.Authentication, req.Authorization)
	if err != nil {
		writeKACLSError(w, http.StatusForbidden, "PERMISSION_DENIED", err.Error())
		return
	}

	if cseKey.Status != "active" {
		writeKACLSError(w, http.StatusForbidden, "PERMISSION_DENIED", "CSE key is not active")
		return
	}

	// Decode the DEK from base64url
	dekBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(req.Key))
	if err != nil {
		writeKACLSError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "invalid base64url DEK")
		return
	}

	// Wrap the DEK via Vecta KeyCore
	wrappedBytes, err := googleCSEProvider.WrapDEK(r.Context(), cseKey.VectaKeyID, dekBytes, h.svc.keycore, tenantID)
	if err != nil {
		writeKACLSError(w, http.StatusInternalServerError, "INTERNAL", "failed to wrap DEK")
		return
	}

	// Increment usage counter
	_ = h.svc.store.IncrementGoogleCSEKeyUsage(r.Context(), tenantID, cseKey.ID, "wrap")

	h.publishAuditEvent(r.Context(), tenantID, "google_cse.kacls.wrap", cseKey.ID)
	log.Printf("[google-cse] KACLS wrap: key=%s user=%s resource=%s", cseKey.ID, authClaims.Email, authClaims.ResourceName)

	wrappedB64URL := base64.RawURLEncoding.EncodeToString(wrappedBytes)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-ID", reqID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(KACLSWrapResponse{WrappedKey: wrappedB64URL})
}

func (h *Handler) handleKACLSUnwrap(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)

	var req KACLSUnwrapRequest
	if err := decodeKACLSJSON(r, &req); err != nil {
		writeKACLSError(w, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}

	if strings.TrimSpace(req.Authentication) == "" {
		writeKACLSError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "authentication token is required")
		return
	}
	if strings.TrimSpace(req.Authorization) == "" {
		writeKACLSError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "authorization token is required")
		return
	}
	if strings.TrimSpace(req.WrappedKey) == "" {
		writeKACLSError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "wrapped_key is required")
		return
	}

	tenantID, cseKey, authClaims, err := h.resolveKACLSContext(r, req.Authentication, req.Authorization)
	if err != nil {
		writeKACLSError(w, http.StatusForbidden, "PERMISSION_DENIED", err.Error())
		return
	}

	if cseKey.Status != "active" {
		writeKACLSError(w, http.StatusForbidden, "PERMISSION_DENIED", "CSE key is not active")
		return
	}

	// Decode wrapped DEK from base64url
	wrappedBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(req.WrappedKey))
	if err != nil {
		writeKACLSError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "invalid base64url wrapped_key")
		return
	}

	// Unwrap via Vecta KeyCore
	dekBytes, err := googleCSEProvider.UnwrapDEK(r.Context(), cseKey.VectaKeyID, wrappedBytes, h.svc.keycore, tenantID)
	if err != nil {
		writeKACLSError(w, http.StatusInternalServerError, "INTERNAL", "failed to unwrap DEK")
		return
	}

	_ = h.svc.store.IncrementGoogleCSEKeyUsage(r.Context(), tenantID, cseKey.ID, "unwrap")

	h.publishAuditEvent(r.Context(), tenantID, "google_cse.kacls.unwrap", cseKey.ID)
	log.Printf("[google-cse] KACLS unwrap: key=%s user=%s resource=%s", cseKey.ID, authClaims.Email, authClaims.ResourceName)

	dekB64URL := base64.RawURLEncoding.EncodeToString(dekBytes)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-ID", reqID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(KACLSUnwrapResponse{Key: dekB64URL})
}

func (h *Handler) handleKACLSPrivilegedUnwrap(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)

	var req KACLSPrivilegedUnwrapRequest
	if err := decodeKACLSJSON(r, &req); err != nil {
		writeKACLSError(w, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}

	if strings.TrimSpace(req.Authentication) == "" {
		writeKACLSError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "authentication token is required")
		return
	}
	if strings.TrimSpace(req.WrappedKey) == "" {
		writeKACLSError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "wrapped_key is required")
		return
	}

	// Validate privileged reason
	if err := googleCSEProvider.ValidatePrivilegedAccess(req.Reason); err != nil {
		writeKACLSError(w, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}

	// For privileged unwrap, we use the authentication JWT only (no authorization JWT)
	// The authentication JWT identifies the admin/legal user
	tenantID, cseKey, authClaims, err := h.resolveKACLSContextPrivileged(r, req.Authentication)
	if err != nil {
		writeKACLSError(w, http.StatusForbidden, "PERMISSION_DENIED", err.Error())
		return
	}

	wrappedBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(req.WrappedKey))
	if err != nil {
		writeKACLSError(w, http.StatusBadRequest, "INVALID_ARGUMENT", "invalid base64url wrapped_key")
		return
	}

	dekBytes, err := googleCSEProvider.UnwrapDEK(r.Context(), cseKey.VectaKeyID, wrappedBytes, h.svc.keycore, tenantID)
	if err != nil {
		writeKACLSError(w, http.StatusInternalServerError, "INTERNAL", "failed to unwrap DEK")
		return
	}

	_ = h.svc.store.IncrementGoogleCSEKeyUsage(r.Context(), tenantID, cseKey.ID, "unwrap")

	h.publishAuditEvent(r.Context(), tenantID, "google_cse.kacls.privileged_unwrap", cseKey.ID)
	log.Printf("[google-cse] KACLS privileged unwrap: key=%s user=%s reason=%s", cseKey.ID, authClaims.Email, req.Reason)

	dekB64URL := base64.RawURLEncoding.EncodeToString(dekBytes)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-ID", reqID)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(KACLSUnwrapResponse{Key: dekB64URL})
}

// ═══════════════════════ KACLS HELPERS ═══════════════════════

// resolveKACLSContext validates Google JWTs and resolves the tenant, CSE key, and claims.
func (h *Handler) resolveKACLSContext(r *http.Request, authenticationToken, authorizationToken string) (string, GoogleCSEKey, *GoogleCSEClaims, error) {
	// Try to identify tenant from request headers or query params
	tenantID := strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}

	// The authorization token is Google's statement that this user may use
	// this key for this resource: verify it before anything else.
	authzClaims, err := verifyKACLSAuthorization(r.Context(), authorizationToken)
	if err != nil {
		return "", GoogleCSEKey{}, nil, fmt.Errorf("authorization token rejected: %w", err)
	}

	// Find the CSE config and key by scanning all configs for this tenant
	// If tenant not set from header, iterate all configs (single-tenant mode)
	configs, err := h.svc.store.ListGoogleCSEConfigs(r.Context(), tenantID)
	if err != nil {
		return "", GoogleCSEKey{}, nil, fmt.Errorf("list CSE configs: %w", err)
	}

	for _, cfg := range configs {
		// Validate authentication JWT against this config's allowed domains
		authnClaims, validateErr := googleCSEProvider.ValidateGoogleJWT(authenticationToken, cfg.AllowedDomains, cfg.AuthenticationClientIDs)
		if validateErr != nil {
			continue
		}
		// Both tokens must be about the same user (CSE API: authentication
		// and authorization email must match).
		if !strings.EqualFold(authnClaims.Email, authzClaims.Email) {
			continue
		}
		// The key is the one the authorization token names; there is no
		// fallback to some other key.
		if authzClaims.KeyURI == "" {
			continue
		}
		cseKey, keyErr := h.svc.store.GetGoogleCSEKeyByURI(r.Context(), cfg.TenantID, authzClaims.KeyURI)
		if keyErr != nil || cseKey.Status != "active" {
			continue
		}
		authnClaims.ResourceName = authzClaims.ResourceName
		authnClaims.KeyURI = authzClaims.KeyURI
		return cfg.TenantID, cseKey, authnClaims, nil
	}

	return "", GoogleCSEKey{}, nil, fmt.Errorf("no matching CSE config/key found for the provided tokens")
}

// resolveKACLSContextPrivileged resolves context for privileged unwrap (no authorization JWT).
func (h *Handler) resolveKACLSContextPrivileged(r *http.Request, authenticationToken string) (string, GoogleCSEKey, *GoogleCSEClaims, error) {
	tenantID := strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}

	// Extract key reference from query params or headers for privileged unwrap
	keyID := strings.TrimSpace(r.URL.Query().Get("key_id"))

	configs, err := h.svc.store.ListGoogleCSEConfigs(r.Context(), tenantID)
	if err != nil {
		return "", GoogleCSEKey{}, nil, fmt.Errorf("list CSE configs: %w", err)
	}

	for _, cfg := range configs {
		authnClaims, validateErr := googleCSEProvider.ValidateGoogleJWT(authenticationToken, cfg.AllowedDomains, cfg.AuthenticationClientIDs)
		if validateErr != nil {
			continue
		}

		// Privileged unwrap names its key explicitly; no fallback key.
		if keyID == "" {
			continue
		}
		cseKey, keyErr := h.svc.store.GetGoogleCSEKey(r.Context(), cfg.TenantID, keyID)
		if keyErr == nil && cseKey.Status == "active" {
			return cfg.TenantID, cseKey, authnClaims, nil
		}
	}

	return "", GoogleCSEKey{}, nil, fmt.Errorf("no matching CSE config/key found for privileged unwrap")
}

// decodeKACLSJSON decodes JSON from a KACLS request body (more lenient than decodeJSON).
func decodeKACLSJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	return nil
}

// writeKACLSError writes an error response in the format expected by Google CSE.
func writeKACLSError(w http.ResponseWriter, status int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"code":    status,
			"message": message,
			"status":  code,
		},
	})
}
