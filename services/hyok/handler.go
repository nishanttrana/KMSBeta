package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	pkgauth "vecta-kms/pkg/auth"
)

type JWTParser func(token string) (*pkgauth.Claims, error)

type Handler struct {
	svc       *Service
	mux       *http.ServeMux
	jwtParser JWTParser
}

func NewHandler(svc *Service, jwtParser JWTParser) *Handler {
	h := &Handler{svc: svc, jwtParser: jwtParser}
	h.mux = h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/keys/{id}", h.handleMicrosoftDKEGetKey)
	mux.HandleFunc("POST /api/v1/keys/{id}/decrypt", h.handleMicrosoftDKEDecrypt)
	mux.HandleFunc("POST /hyok/dke/v1/keys/{id}/decrypt", h.handleDKEDecrypt)
	mux.HandleFunc("GET /hyok/dke/v1/keys/{id}/publickey", h.handleDKEPublicKey)
	mux.HandleFunc("POST /hyok/salesforce/v1/keys/{id}/wrap", h.handleSalesforceWrap)
	mux.HandleFunc("POST /hyok/salesforce/v1/keys/{id}/unwrap", h.handleSalesforceUnwrap)
	mux.HandleFunc("POST /hyok/google/v1/keys/{id}/wrap", h.handleGoogleWrap)
	mux.HandleFunc("POST /hyok/google/v1/keys/{id}/unwrap", h.handleGoogleUnwrap)
	mux.HandleFunc("POST /hyok/generic/v1/keys/{id}/encrypt", h.handleGenericEncrypt)
	mux.HandleFunc("POST /hyok/generic/v1/keys/{id}/decrypt", h.handleGenericDecrypt)
	mux.HandleFunc("POST /hyok/generic/v1/keys/{id}/wrap", h.handleGenericWrap)
	mux.HandleFunc("POST /hyok/generic/v1/keys/{id}/unwrap", h.handleGenericUnwrap)

	mux.HandleFunc("GET /hyok/v1/endpoints", h.handleListEndpoints)
	mux.HandleFunc("PUT /hyok/v1/endpoints/{protocol}", h.handleConfigureEndpoint)
	mux.HandleFunc("DELETE /hyok/v1/endpoints/{protocol}", h.handleDeleteEndpoint)
	mux.HandleFunc("GET /hyok/v1/requests", h.handleListRequests)
	mux.HandleFunc("GET /hyok/v1/health", h.handleHealth)
	return mux
}

func (h *Handler) handleMicrosoftDKEGetKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	identity, tenantID, ok := h.authenticateAndTenant(r, w, reqID)
	if !ok {
		return
	}
	out, err := h.svc.GetMicrosoftDKEKey(r.Context(), tenantID, r.PathValue("id"), r.URL.Path, r.Host, identity)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"kty":     out.KTY,
		"key_ops": out.KeyOps,
		"n":       out.N,
		"e":       out.E,
		"alg":     out.Alg,
		"kid":     out.KID,
		"use":     out.Use,
	})
}

func (h *Handler) handleMicrosoftDKEDecrypt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	identity, tenantID, ok := h.authenticateAndTenant(r, w, reqID)
	if !ok {
		return
	}
	var req MicrosoftDKEDecryptRequest
	if err := decodeJSONLenient(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	out, err := h.svc.ProcessMicrosoftDKEDecrypt(r.Context(), tenantID, r.PathValue("id"), r.URL.Path, r.Host, identity, req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"value": out.Value})
}

func (h *Handler) handleDKEDecrypt(w http.ResponseWriter, r *http.Request) {
	h.handleCrypto(w, r, ProtocolDKE, "decrypt")
}

func (h *Handler) handleSalesforceWrap(w http.ResponseWriter, r *http.Request) {
	h.handleCrypto(w, r, ProtocolSalesforce, "wrap")
}

func (h *Handler) handleSalesforceUnwrap(w http.ResponseWriter, r *http.Request) {
	h.handleCrypto(w, r, ProtocolSalesforce, "unwrap")
}

func (h *Handler) handleGoogleWrap(w http.ResponseWriter, r *http.Request) {
	h.handleCrypto(w, r, ProtocolGoogleEKM, "wrap")
}

func (h *Handler) handleGoogleUnwrap(w http.ResponseWriter, r *http.Request) {
	h.handleCrypto(w, r, ProtocolGoogleEKM, "unwrap")
}

func (h *Handler) handleGenericEncrypt(w http.ResponseWriter, r *http.Request) {
	h.handleCrypto(w, r, ProtocolGeneric, "encrypt")
}

func (h *Handler) handleGenericDecrypt(w http.ResponseWriter, r *http.Request) {
	h.handleCrypto(w, r, ProtocolGeneric, "decrypt")
}

func (h *Handler) handleGenericWrap(w http.ResponseWriter, r *http.Request) {
	h.handleCrypto(w, r, ProtocolGeneric, "wrap")
}

func (h *Handler) handleGenericUnwrap(w http.ResponseWriter, r *http.Request) {
	h.handleCrypto(w, r, ProtocolGeneric, "unwrap")
}

func (h *Handler) handleCrypto(w http.ResponseWriter, r *http.Request, protocol string, operation string) {
	reqID := requestID(r)
	identity, tenantID, ok := h.authenticateAndTenant(r, w, reqID)
	if !ok {
		return
	}
	var req ProxyCryptoRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	out, err := h.svc.ProcessCrypto(r.Context(), tenantID, protocol, operation, r.PathValue("id"), r.URL.Path, identity, req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	status := http.StatusOK
	if strings.EqualFold(out.Status, "pending_approval") {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleDKEPublicKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	identity, tenantID, ok := h.authenticateAndTenant(r, w, reqID)
	if !ok {
		return
	}
	out, err := h.svc.GetDKEPublicKey(r.Context(), tenantID, r.PathValue("id"), r.URL.Path, identity)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"key": out, "request_id": reqID})
}

func (h *Handler) handleListEndpoints(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListEndpoints(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleConfigureEndpoint(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body struct {
		TenantID           string `json:"tenant_id"`
		Enabled            *bool  `json:"enabled"`
		AuthMode           string `json:"auth_mode"`
		PolicyID           string `json:"policy_id"`
		GovernanceRequired bool   `json:"governance_required"`
		MetadataJSON       string `json:"metadata_json"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	tenantID := strings.TrimSpace(body.TenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	out, err := h.svc.ConfigureEndpoint(r.Context(), EndpointConfig{
		TenantID:           tenantID,
		Protocol:           r.PathValue("protocol"),
		Enabled:            enabled,
		AuthMode:           body.AuthMode,
		PolicyID:           body.PolicyID,
		GovernanceRequired: body.GovernanceRequired,
		MetadataJSON:       body.MetadataJSON,
	})
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"endpoint": out, "request_id": reqID})
}

func (h *Handler) handleDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	if err := h.svc.DeleteEndpoint(r.Context(), tenantID, r.PathValue("protocol")); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "deleted", "request_id": reqID})
}

func (h *Handler) handleListRequests(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	offset, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("offset")))
	items, err := h.svc.ListRequests(r.Context(), tenantID, r.URL.Query().Get("protocol"), limit, offset)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.Health(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"health": out, "request_id": reqID})
}

func (h *Handler) authenticateAndTenant(r *http.Request, w http.ResponseWriter, reqID string) (AuthIdentity, string, bool) {
	hint := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if hint == "" {
		hint = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	identity, err := h.authenticate(r, hint)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized", err.Error(), reqID, hint)
		return AuthIdentity{}, "", false
	}
	tenantID := hint
	if tenantID == "" {
		tenantID = strings.TrimSpace(identity.TenantID)
	}
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return AuthIdentity{}, "", false
	}
	return identity, tenantID, true
}

func (h *Handler) authenticate(r *http.Request, tenantHint string) (AuthIdentity, error) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		id := AuthIdentity{
			Mode:     "mtls",
			Subject:  cert.Subject.String(),
			ClientCN: strings.TrimSpace(cert.Subject.CommonName),
			Issuer:   cert.Issuer.String(),
			RemoteIP: strings.TrimSpace(r.RemoteAddr),
		}
		id.TenantID, id.Role = splitCN(id.ClientCN)
		if tenantHint != "" && id.TenantID != "" && !strings.EqualFold(id.TenantID, tenantHint) {
			return AuthIdentity{}, errors.New("tenant mismatch with client certificate")
		}
		return id, nil
	}
	headerCN := strings.TrimSpace(r.Header.Get("X-Client-CN"))
	headerSub := strings.TrimSpace(r.Header.Get("X-Client-Subject"))
	headerIss := strings.TrimSpace(r.Header.Get("X-Client-Issuer"))
	if headerCN != "" || headerSub != "" || headerIss != "" {
		id := AuthIdentity{
			Mode:     "mtls",
			Subject:  firstNonEmpty(headerSub, headerCN),
			ClientCN: headerCN,
			Issuer:   headerIss,
			RemoteIP: strings.TrimSpace(r.RemoteAddr),
		}
		id.TenantID, id.Role = splitCN(id.ClientCN)
		if tenantHint != "" && id.TenantID != "" && !strings.EqualFold(id.TenantID, tenantHint) {
			return AuthIdentity{}, errors.New("tenant mismatch with client certificate")
		}
		return id, nil
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		if h.jwtParser == nil {
			return AuthIdentity{}, errors.New("jwt parser is not configured")
		}
		token := strings.TrimSpace(authz[7:])
		claims, err := h.jwtParser(token)
		if err != nil {
			return AuthIdentity{}, errors.New("invalid bearer token")
		}
		id := AuthIdentity{
			Mode:      "jwt",
			Subject:   strings.TrimSpace(claims.Subject),
			TenantID:  strings.TrimSpace(firstNonEmpty(claims.TenantID, claims.AzureTenantID)),
			UserID:    strings.TrimSpace(claims.UserID),
			Role:      strings.TrimSpace(claims.Role),
			TokenJTI:  strings.TrimSpace(claims.ID),
			RemoteIP:  strings.TrimSpace(r.RemoteAddr),
			JWTIssuer: strings.TrimSpace(claims.Issuer),
		}
		if len(claims.Audience) > 0 {
			id.JWTAudiences = make([]string, 0, len(claims.Audience))
			for _, aud := range claims.Audience {
				aud = strings.TrimSpace(aud)
				if aud != "" {
					id.JWTAudiences = append(id.JWTAudiences, aud)
				}
			}
		}
		if tenantHint != "" && id.TenantID != "" && !strings.EqualFold(id.TenantID, tenantHint) {
			return AuthIdentity{}, errors.New("tenant mismatch with bearer token")
		}
		return id, nil
	}
	return AuthIdentity{}, errors.New("mTLS client identity or Bearer JWT is required")
}

func splitCN(cn string) (string, string) {
	cn = strings.TrimSpace(cn)
	if cn == "" {
		return "", ""
	}
	parts := strings.SplitN(cn, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return "", ""
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, reqID string, tenantID string) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		writeErr(w, svcErr.HTTPStatus, svcErr.Code, svcErr.Message, reqID, tenantID)
		return
	}
	writeErr(w, http.StatusInternalServerError, "internal_error", err.Error(), reqID, tenantID)
}

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("request body is required")
		}
		return err
	}
	return nil
}

func decodeJSONLenient(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	d := json.NewDecoder(r.Body)
	if err := d.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("request body is required")
		}
		return err
	}
	return nil
}

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id != "" {
		return id
	}
	return newID("req")
}

func mustTenant(r *http.Request, reqID string, w http.ResponseWriter) string {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return ""
	}
	return tenantID
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, code string, message string, requestID string, tenantID string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]interface{}{
			"code":       code,
			"message":    message,
			"request_id": requestID,
			"tenant_id":  tenantID,
		},
	})
}
