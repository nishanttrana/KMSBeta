package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type Handler struct {
	svc *Service
	mux *http.ServeMux
}

func NewHandler(svc *Service) *Handler {
	h := &Handler{svc: svc}
	h.mux = h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ekm/agents/register", h.handleRegisterAgent)
	mux.HandleFunc("GET /ekm/agents", h.handleListAgents)
	mux.HandleFunc("GET /ekm/agents/{id}/status", h.handleAgentStatus)
	mux.HandleFunc("GET /ekm/agents/{id}/health", h.handleAgentHealth)
	mux.HandleFunc("GET /ekm/agents/{id}/logs", h.handleAgentLogs)
	mux.HandleFunc("GET /ekm/agents/{id}/deploy", h.handleAgentDeployPackage)
	mux.HandleFunc("POST /ekm/agents/{id}/rotate", h.handleRotateAgent)
	mux.HandleFunc("DELETE /ekm/agents/{id}", h.handleDeleteAgent)
	mux.HandleFunc("POST /ekm/agents/{id}/heartbeat", h.handleAgentHeartbeat)
	mux.HandleFunc("GET /ekm/sdk/overview", h.handleSDKOverview)
	mux.HandleFunc("GET /ekm/sdk/download", h.handleSDKDownload)

	mux.HandleFunc("POST /ekm/tde/keys", h.handleCreateTDEKey)
	mux.HandleFunc("POST /ekm/tde/keys/{id}/wrap", h.handleWrapDEK)
	mux.HandleFunc("POST /ekm/tde/keys/{id}/unwrap", h.handleUnwrapDEK)
	mux.HandleFunc("POST /ekm/tde/keys/{id}/rotate", h.handleRotateTDEKey)
	mux.HandleFunc("GET /ekm/tde/keys/{id}/public", h.handleGetPublicKey)

	mux.HandleFunc("POST /ekm/databases", h.handleRegisterDatabase)
	mux.HandleFunc("GET /ekm/databases", h.handleListDatabases)
	mux.HandleFunc("GET /ekm/databases/{id}", h.handleGetDatabase)
	return mux
}

func (h *Handler) handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RegisterAgentRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, cn, err := tenantFromRequest(r, req.TenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	req.TenantID = tenantID
	agent, key, err := h.svc.RegisterAgent(r.Context(), req, cn)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"agent":                agent,
		"auto_provisioned_key": key,
		"request_id":           reqID,
	})
}

func (h *Handler) handleListAgents(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	items, err := h.svc.ListAgents(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleAgentStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	out, err := h.svc.GetAgentStatus(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": out, "request_id": reqID})
}

func (h *Handler) handleAgentHealth(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	out, err := h.svc.GetAgentHealth(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"health": out, "request_id": reqID})
}

func (h *Handler) handleAgentLogs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	items, err := h.svc.ListAgentLogs(r.Context(), tenantID, r.PathValue("id"), limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleRotateAgent(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RotateTDEKeyRequest
	if err := decodeJSONOptional(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, _, err := tenantFromRequest(r, req.TenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	out, err := h.svc.RotateAgentAssignedKey(r.Context(), tenantID, r.PathValue("id"), req.Reason)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"rotation": out, "request_id": reqID})
}

func (h *Handler) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req DeleteAgentRequest
	if err := decodeJSONOptional(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, _, err := tenantFromRequest(r, req.TenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	out, err := h.svc.DeleteAgent(r.Context(), tenantID, r.PathValue("id"), req.Reason)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": out, "request_id": reqID})
}

func (h *Handler) handleAgentDeployPackage(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	targetOS := strings.TrimSpace(r.URL.Query().Get("os"))
	out, err := h.svc.BuildAgentDeployPackage(r.Context(), tenantID, r.PathValue("id"), targetOS)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"package": out, "request_id": reqID})
}

func (h *Handler) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req AgentHeartbeatRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, cn, err := tenantFromRequest(r, req.TenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	req.TenantID = tenantID
	out, err := h.svc.AgentHeartbeat(r.Context(), r.PathValue("id"), req, cn)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"agent": out, "request_id": reqID})
}

func (h *Handler) handleSDKOverview(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	out, err := h.svc.GetSDKOverview(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"overview":   out,
		"request_id": reqID,
	})
}

func (h *Handler) handleSDKDownload(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	provider := strings.TrimSpace(r.URL.Query().Get("provider"))
	targetOS := strings.TrimSpace(r.URL.Query().Get("os"))
	out, err := h.svc.BuildSDKArtifact(r.Context(), tenantID, provider, targetOS)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"artifact":   out,
		"request_id": reqID,
	})
}

func (h *Handler) handleCreateTDEKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateTDEKeyRequest
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
	out, err := h.svc.CreateTDEKey(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"key": out, "request_id": reqID})
}

func (h *Handler) handleWrapDEK(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req WrapDEKRequest
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
	out, err := h.svc.WrapDEK(r.Context(), r.PathValue("id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleUnwrapDEK(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req UnwrapDEKRequest
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
	out, err := h.svc.UnwrapDEK(r.Context(), r.PathValue("id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleRotateTDEKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RotateTDEKeyRequest
	if err := decodeJSONOptional(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, _, err := tenantFromRequest(r, req.TenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	req.TenantID = tenantID
	out, err := h.svc.RotateTDEKey(r.Context(), r.PathValue("id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"rotation": out, "request_id": reqID})
}

func (h *Handler) handleGetPublicKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	out, err := h.svc.GetTDEPublicKey(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"public_key": out, "request_id": reqID})
}

func (h *Handler) handleRegisterDatabase(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RegisterDatabaseRequest
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
	dbi, key, err := h.svc.RegisterDatabase(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"database":             dbi,
		"auto_provisioned_key": key,
		"request_id":           reqID,
	})
}

func (h *Handler) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	items, err := h.svc.ListDatabases(r.Context(), tenantID, strings.TrimSpace(r.URL.Query().Get("agent_id")))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetDatabase(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	dbi, err := h.svc.GetDatabase(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"database": dbi, "request_id": reqID})
}

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("request body is required")
		}
		return err
	}
	return nil
}

func decodeJSONOptional(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
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

func tenantFromRequest(r *http.Request, bodyTenant string) (string, string, error) {
	tenantID := strings.TrimSpace(bodyTenant)
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	certTenant, role, cn, err := certPrincipal(r)
	if err != nil {
		return "", "", newServiceError(http.StatusUnauthorized, "invalid_client_cert", err.Error())
	}
	if certTenant != "" {
		if tenantID == "" {
			tenantID = certTenant
		}
		if tenantID != certTenant {
			return "", "", newServiceError(http.StatusForbidden, "tenant_mismatch", "tenant in request does not match mTLS certificate")
		}
		if !isEKMRole(role) {
			return "", "", newServiceError(http.StatusForbidden, "role_not_allowed", "mTLS role is not allowed for EKM")
		}
	}
	if tenantID == "" {
		return "", "", newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required (body/query/header or mTLS CN)")
	}
	return tenantID, cn, nil
}

func certPrincipal(r *http.Request) (string, string, string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", "", "", nil
	}
	cert := r.TLS.PeerCertificates[0]
	return principalFromCert(cert)
}

func principalFromCert(cert *x509.Certificate) (string, string, string, error) {
	if cert == nil {
		return "", "", "", errors.New("certificate is nil")
	}
	cn := strings.TrimSpace(cert.Subject.CommonName)
	if cn == "" {
		return "", "", "", errors.New("client cert CN is required")
	}
	parts := strings.SplitN(cn, ":", 2)
	if len(parts) != 2 {
		return "", "", "", errors.New("client cert CN must be tenant:role")
	}
	tenantID := strings.TrimSpace(parts[0])
	role := strings.TrimSpace(parts[1])
	if tenantID == "" || role == "" {
		return "", "", "", errors.New("invalid tenant:role in CN")
	}
	return tenantID, role, cn, nil
}

func isEKMRole(role string) bool {
	r := strings.ToLower(strings.TrimSpace(role))
	return r == "ekm-agent" || r == "ekm-client" || r == "ekm-admin" || r == "ekm-service"
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, reqID string, tenantID string) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		writeErr(w, svcErr.HTTPStatus, svcErr.Code, svcErr.Message, reqID, tenantID)
		return
	}
	writeErr(w, httpStatusForErr(err), "internal_error", err.Error(), reqID, tenantID)
}

func writeJSON(w http.ResponseWriter, code int, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, code int, errCode string, msg string, requestID string, tenantID string) {
	writeJSON(w, code, map[string]interface{}{
		"error": map[string]interface{}{
			"code":       errCode,
			"message":    msg,
			"request_id": requestID,
			"tenant_id":  tenantID,
		},
	})
}
