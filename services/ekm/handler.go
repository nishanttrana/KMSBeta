package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
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

	mux.HandleFunc("POST /ekm/bitlocker/clients/register", h.handleRegisterBitLockerClient)
	mux.HandleFunc("GET /ekm/bitlocker/clients", h.handleListBitLockerClients)
	mux.HandleFunc("GET /ekm/bitlocker/clients/{id}", h.handleGetBitLockerClient)
	mux.HandleFunc("POST /ekm/bitlocker/clients/{id}/heartbeat", h.handleBitLockerHeartbeat)
	mux.HandleFunc("POST /ekm/bitlocker/clients/{id}/operations", h.handleQueueBitLockerOperation)
	mux.HandleFunc("GET /ekm/bitlocker/clients/{id}/jobs", h.handleListBitLockerJobs)
	mux.HandleFunc("POST /ekm/bitlocker/clients/{id}/jobs/next", h.handlePollBitLockerJob)
	mux.HandleFunc("POST /ekm/bitlocker/clients/{id}/jobs/{job_id}/result", h.handleBitLockerJobResult)
	mux.HandleFunc("GET /ekm/bitlocker/recovery", h.handleListBitLockerRecovery)
	mux.HandleFunc("GET /ekm/bitlocker/clients/{id}/deploy", h.handleBitLockerDeployPackage)

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

func (h *Handler) handleRegisterBitLockerClient(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RegisterBitLockerClientRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, cn, sub, _, authErr := bitLockerTenantFromRequest(r, req.TenantID, false)
	if authErr != nil {
		h.writeServiceError(w, authErr, reqID, req.TenantID)
		return
	}
	req.TenantID = tenantID
	out, err := h.svc.RegisterBitLockerClient(r.Context(), req, cn, sub)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"client": out, "request_id": reqID})
}

func (h *Handler) handleListBitLockerClients(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	limit := 1000
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, convErr := strconv.Atoi(raw); convErr == nil {
			limit = n
		}
	}
	items, svcErr := h.svc.ListBitLockerClients(r.Context(), tenantID, limit)
	if svcErr != nil {
		h.writeServiceError(w, svcErr, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetBitLockerClient(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	item, svcErr := h.svc.GetBitLockerClient(r.Context(), tenantID, r.PathValue("id"))
	if svcErr != nil {
		h.writeServiceError(w, svcErr, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"client": item, "request_id": reqID})
}

func (h *Handler) handleBitLockerHeartbeat(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req BitLockerHeartbeatRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, cn, sub, _, authErr := bitLockerTenantFromRequest(r, req.TenantID, true)
	if authErr != nil {
		h.writeServiceError(w, authErr, reqID, req.TenantID)
		return
	}
	req.TenantID = tenantID
	out, err := h.svc.BitLockerHeartbeat(r.Context(), r.PathValue("id"), req, cn, sub)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"client": out, "request_id": reqID})
}

func (h *Handler) handleQueueBitLockerOperation(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req BitLockerOperationRequest
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
	out, svcErr := h.svc.QueueBitLockerOperation(r.Context(), r.PathValue("id"), req)
	if svcErr != nil {
		h.writeServiceError(w, svcErr, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"job": out, "request_id": reqID})
}

func (h *Handler) handleListBitLockerJobs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, convErr := strconv.Atoi(raw); convErr == nil {
			limit = n
		}
	}
	items, svcErr := h.svc.ListBitLockerJobs(r.Context(), tenantID, r.PathValue("id"), limit)
	if svcErr != nil {
		h.writeServiceError(w, svcErr, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handlePollBitLockerJob(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, _, _, authErr := bitLockerTenantFromRequest(r, "", true)
	if authErr != nil {
		h.writeServiceError(w, authErr, reqID, "")
		return
	}
	out, err := h.svc.PollBitLockerJob(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"job": out, "request_id": reqID})
}

func (h *Handler) handleBitLockerJobResult(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req BitLockerJobResultRequest
	if err := decodeJSON(r, &req); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, "")
		return
	}
	tenantID, _, _, _, authErr := bitLockerTenantFromRequest(r, req.TenantID, true)
	if authErr != nil {
		h.writeServiceError(w, authErr, reqID, req.TenantID)
		return
	}
	req.TenantID = tenantID
	out, err := h.svc.SubmitBitLockerJobResult(r.Context(), r.PathValue("id"), r.PathValue("job_id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"job": out, "request_id": reqID})
}

func (h *Handler) handleListBitLockerRecovery(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, convErr := strconv.Atoi(raw); convErr == nil {
			limit = n
		}
	}
	clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))
	items, svcErr := h.svc.ListBitLockerRecoveryKeys(r.Context(), tenantID, clientID, limit)
	if svcErr != nil {
		h.writeServiceError(w, svcErr, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleBitLockerDeployPackage(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	targetOS := strings.TrimSpace(r.URL.Query().Get("os"))
	out, svcErr := h.svc.BuildBitLockerDeployPackage(r.Context(), tenantID, r.PathValue("id"), targetOS)
	if svcErr != nil {
		h.writeServiceError(w, svcErr, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"package": out, "request_id": reqID})
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

func isBitLockerRole(role string) bool {
	r := strings.ToLower(strings.TrimSpace(role))
	return r == "bitlocker-agent" || r == "bitlocker-client" || r == "bitlocker-service" || r == "ekm-admin"
}

func bitLockerTenantFromRequest(r *http.Request, bodyTenant string, requireAgentAuth bool) (string, string, string, bool, error) {
	tenantID := strings.TrimSpace(bodyTenant)
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}

	certTenant, certRole, certCN, certErr := certPrincipal(r)
	if certErr != nil {
		return "", "", "", false, newServiceError(http.StatusUnauthorized, "invalid_client_cert", certErr.Error())
	}
	if certTenant != "" {
		if tenantID == "" {
			tenantID = certTenant
		}
		if tenantID != certTenant {
			return "", "", "", false, newServiceError(http.StatusForbidden, "tenant_mismatch", "tenant in request does not match mTLS certificate")
		}
		if !isBitLockerRole(certRole) {
			return "", "", "", false, newServiceError(http.StatusForbidden, "role_not_allowed", "mTLS role is not allowed for bitlocker")
		}
		return tenantID, certCN, "", true, nil
	}

	rawToken := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
	if rawToken != "" {
		claims, err := parseBitLockerJWT(rawToken)
		if err == nil {
			if !isBitLockerRole(claims.Role) {
				return "", "", "", false, newServiceError(http.StatusForbidden, "role_not_allowed", "jwt role is not allowed for bitlocker")
			}
			if tenantID == "" {
				tenantID = claims.TenantID
			}
			if tenantID == "" {
				return "", "", "", false, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
			}
			if claims.TenantID != "" && tenantID != claims.TenantID {
				return "", "", "", false, newServiceError(http.StatusForbidden, "tenant_mismatch", "tenant in request does not match jwt token")
			}
			return tenantID, "", claims.Subject, true, nil
		}
		// Dashboard/admin calls include Auth service JWTs, which are not BitLocker-agent JWTs.
		// For non-agent endpoints, keep tenant resolution from request and do not fail on JWT parse.
		if requireAgentAuth {
			return "", "", "", false, newServiceError(http.StatusUnauthorized, "invalid_token", err.Error())
		}
	}

	if requireAgentAuth {
		return "", "", "", false, newServiceError(http.StatusUnauthorized, "unauthorized", "bitlocker agent auth requires mTLS or JWT")
	}
	if tenantID == "" {
		return "", "", "", false, newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	return tenantID, "", "", false, nil
}

type bitLockerJWTClaims struct {
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

var (
	bitLockerJWTOnce sync.Once
	bitLockerJWTErr  error
	bitLockerJWTPub  *rsa.PublicKey
)

func parseBitLockerJWT(rawToken string) (*bitLockerJWTClaims, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, errors.New("missing bearer token")
	}
	bitLockerJWTOnce.Do(func() {
		path := strings.TrimSpace(os.Getenv("JWT_PUBLIC_KEY_PATH"))
		if path == "" {
			path = "certs/jwt_public.pem"
		}
		pemRaw, err := os.ReadFile(path)
		if err != nil {
			bitLockerJWTErr = err
			return
		}
		block, _ := pem.Decode(pemRaw)
		if block == nil {
			bitLockerJWTErr = errors.New("failed to decode jwt public key PEM")
			return
		}
		pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			bitLockerJWTErr = err
			return
		}
		pub, ok := pubAny.(*rsa.PublicKey)
		if !ok {
			bitLockerJWTErr = errors.New("jwt public key is not RSA")
			return
		}
		bitLockerJWTPub = pub
	})
	if bitLockerJWTErr != nil {
		return nil, bitLockerJWTErr
	}
	if bitLockerJWTPub == nil {
		return nil, errors.New("jwt public key is not configured")
	}
	token, err := jwt.ParseWithClaims(rawToken, &bitLockerJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, errors.New("invalid signing method")
		}
		return bitLockerJWTPub, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*bitLockerJWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid claims")
	}
	return claims, nil
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
