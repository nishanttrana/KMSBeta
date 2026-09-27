package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	pkgauth "vecta-kms/pkg/auth"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/tenantcheck"
)

type Handler struct {
	svc       *Service
	mux       *http.ServeMux
	jwtParser func(string) (*pkgauth.Claims, error)
}

// SetJWTParser installs the verifier for auth-service tokens. Every
// tenant-scoped route requires one; see tenantFromRequest.
func (h *Handler) SetJWTParser(p func(string) (*pkgauth.Claims, error)) { h.jwtParser = p }

func NewHandler(svc *Service) *Handler {
	h := &Handler{svc: svc}
	h.mux = h.routes()
	return h
}

// ServeHTTP attaches the caller's verified claims, when the bearer token is
// an auth-service token, so tenantFromRequest can enforce the tenant.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.jwtParser != nil {
		if raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer")); raw != "" {
			if claims, err := h.jwtParser(raw); err == nil && claims != nil {
				r = r.WithContext(pkgauth.ContextWithClaims(r.Context(), claims))
			}
		}
	}
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
	mux.HandleFunc("GET /ekm/bitlocker/clients/{id}/delete-preview", h.handleBitLockerDeletePreview)
	mux.HandleFunc("DELETE /ekm/bitlocker/clients/{id}", h.handleDeleteBitLockerClient)
	mux.HandleFunc("POST /ekm/bitlocker/clients/{id}/heartbeat", h.handleBitLockerHeartbeat)
	mux.HandleFunc("POST /ekm/bitlocker/clients/{id}/operations", h.handleQueueBitLockerOperation)
	mux.HandleFunc("GET /ekm/bitlocker/clients/{id}/jobs", h.handleListBitLockerJobs)
	mux.HandleFunc("POST /ekm/bitlocker/clients/{id}/jobs/next", h.handlePollBitLockerJob)
	mux.HandleFunc("POST /ekm/bitlocker/clients/{id}/jobs/{job_id}/result", h.handleBitLockerJobResult)
	mux.HandleFunc("GET /ekm/bitlocker/recovery", h.handleListBitLockerRecovery)
	mux.HandleFunc("POST /ekm/bitlocker/network/scan", h.handleBitLockerNetworkScan)
	mux.HandleFunc("GET /ekm/bitlocker/clients/{id}/deploy", h.handleBitLockerDeployPackage)

	mux.HandleFunc("POST /ekm/tde/keys", h.handleCreateTDEKey)
	mux.HandleFunc("POST /ekm/tde/keys/{id}/wrap", h.handleWrapDEK)
	mux.HandleFunc("POST /ekm/tde/keys/{id}/unwrap", h.handleUnwrapDEK)
	mux.HandleFunc("POST /ekm/tde/keys/{id}/rotate", h.handleRotateTDEKey)
	mux.HandleFunc("GET /ekm/tde/keys/{id}/public", h.handleGetPublicKey)

	mux.HandleFunc("POST /ekm/tde/keys/{id}/revoke", h.handleRevokeTDEKey)

	mux.HandleFunc("POST /ekm/databases", h.handleRegisterDatabase)
	mux.HandleFunc("GET /ekm/databases", h.handleListDatabases)
	mux.HandleFunc("GET /ekm/databases/{id}", h.handleGetDatabase)
	mux.HandleFunc("POST /ekm/databases/{id}/revoke-tde", h.handleRevokeDatabaseTDE)

	mux.HandleFunc("POST /ekm/agents/{id}/validate-deploy", h.handleValidateDeployment)

	// Azure EKM
	mux.HandleFunc("POST /ekm/azure/configs", h.handleCreateAzureConfig)
	mux.HandleFunc("GET /ekm/azure/configs", h.handleListAzureConfigs)
	mux.HandleFunc("GET /ekm/azure/configs/{id}", h.handleGetAzureConfig)
	mux.HandleFunc("PUT /ekm/azure/configs/{id}", h.handleUpdateAzureConfig)
	mux.HandleFunc("DELETE /ekm/azure/configs/{id}", h.handleDeleteAzureConfig)
	mux.HandleFunc("POST /ekm/azure/configs/{id}/test", h.handleTestAzureConnection)
	mux.HandleFunc("POST /ekm/azure/configs/{id}/sync", h.handleSyncAzureKeys)
	mux.HandleFunc("POST /ekm/azure/mappings", h.handleCreateAzureMapping)
	mux.HandleFunc("GET /ekm/azure/mappings", h.handleListAzureMappings)
	mux.HandleFunc("DELETE /ekm/azure/mappings/{id}", h.handleDeleteAzureMapping)
	mux.HandleFunc("POST /ekm/azure/mappings/{id}/import", h.handleImportKeyToAzure)
	mux.HandleFunc("POST /ekm/azure/mappings/{id}/rotate", h.handleRotateAzureKey)
	mux.HandleFunc("POST /ekm/azure/mappings/{id}/wrap", h.handleAzureWrapKey)
	mux.HandleFunc("POST /ekm/azure/mappings/{id}/unwrap", h.handleAzureUnwrapKey)

	// Google CSE — Management routes (called by Vecta admins)
	mux.HandleFunc("POST /ekm/google-cse/configs", h.handleCreateGoogleCSEConfig)
	mux.HandleFunc("GET /ekm/google-cse/configs", h.handleListGoogleCSEConfigs)
	mux.HandleFunc("GET /ekm/google-cse/configs/{id}", h.handleGetGoogleCSEConfig)
	mux.HandleFunc("PUT /ekm/google-cse/configs/{id}", h.handleUpdateGoogleCSEConfig)
	mux.HandleFunc("DELETE /ekm/google-cse/configs/{id}", h.handleDeleteGoogleCSEConfig)
	mux.HandleFunc("POST /ekm/google-cse/keys", h.handleCreateGoogleCSEKey)
	mux.HandleFunc("GET /ekm/google-cse/keys", h.handleListGoogleCSEKeys)
	mux.HandleFunc("DELETE /ekm/google-cse/keys/{id}", h.handleDeleteGoogleCSEKey)

	// Google CSE — KACLS API routes (called by Google's CSE infrastructure)
	mux.HandleFunc("GET /ekm/kacls/status", h.handleKACLSStatus)
	mux.HandleFunc("POST /ekm/kacls/wrap", h.handleKACLSWrap)
	mux.HandleFunc("POST /ekm/kacls/unwrap", h.handleKACLSUnwrap)
	mux.HandleFunc("POST /ekm/kacls/privilegedunwrap", h.handleKACLSPrivilegedUnwrap)

	return mux
}

func (h *Handler) handleFileEncryptDownload(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	q := r.URL.Query()
	req := FileEncryptDownloadRequest{
		TenantID:     tenantID,
		TargetOS:     strings.TrimSpace(q.Get("os")),
		Distro:       strings.TrimSpace(q.Get("distro")),
		KeyID:        strings.TrimSpace(q.Get("key_id")),
		WatchDirs:    strings.TrimSpace(q.Get("watch_dirs")),
		FilePatterns: strings.TrimSpace(q.Get("file_patterns")),
		RotationDays: intParam(q.Get("rotation_days"), 90),
		APIBaseURL:   strings.TrimSpace(q.Get("api_base_url")),
	}
	out, err := h.svc.BuildFileEncryptAgentPackage(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"package": out, "request_id": reqID})
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

func (h *Handler) handleBitLockerDeletePreview(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, _, err := tenantFromRequest(r, "")
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	out, svcErr := h.svc.GetBitLockerDeletePreview(r.Context(), tenantID, r.PathValue("id"))
	if svcErr != nil {
		h.writeServiceError(w, svcErr, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"preview": out, "request_id": reqID})
}

func (h *Handler) handleDeleteBitLockerClient(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req DeleteBitLockerClientRequest
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
	out, svcErr := h.svc.DeleteBitLockerClient(r.Context(), r.PathValue("id"), req)
	if svcErr != nil {
		h.writeServiceError(w, svcErr, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"deleted": out, "request_id": reqID})
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

func (h *Handler) handleBitLockerNetworkScan(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req BitLockerNetworkScanRequest
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
	out, svcErr := h.svc.ScanBitLockerWindowsEndpoints(r.Context(), req)
	if svcErr != nil {
		h.writeServiceError(w, svcErr, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"scan": out, "request_id": reqID})
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
	status := http.StatusOK
	if strings.EqualFold(out.Status, "pending_approval") {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]interface{}{"result": out, "request_id": reqID})
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
	status := http.StatusOK
	if strings.EqualFold(out.Status, "pending_approval") {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]interface{}{"result": out, "request_id": reqID})
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
	status := http.StatusOK
	if strings.EqualFold(out.Status, "pending_approval") {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]interface{}{"rotation": out, "request_id": reqID})
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

func (h *Handler) handleRevokeTDEKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RevokeTDEKeyRequest
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
	out, err := h.svc.RevokeTDEKey(r.Context(), r.PathValue("id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"revocation": out, "request_id": reqID})
}

func (h *Handler) handleRevokeDatabaseTDE(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RevokeDatabaseTDERequest
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
	out, err := h.svc.RevokeDatabaseTDE(r.Context(), r.PathValue("id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"revocation": out, "request_id": reqID})
}

func (h *Handler) handleValidateDeployment(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ValidateDeploymentRequest
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
	out, err := h.svc.ValidateDeployment(r.Context(), r.PathValue("id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"validation": out, "request_id": reqID})
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

// tenantFromRequest requires a verified auth-service token and returns the
// tenant it may act for. The TLS peer is never an identity: requests arrive
// through Envoy over internal mTLS (the peer is Envoy), and the edge does not
// verify customer client certificates.
func tenantFromRequest(r *http.Request, bodyTenant string) (string, string, error) {
	tenantID := strings.TrimSpace(bodyTenant)
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	claims, ok := pkgauth.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		return "", "", newServiceError(http.StatusUnauthorized, "unauthorized", "a valid bearer token is required")
	}
	if tenantID == "" {
		tenantID = strings.TrimSpace(claims.TenantID)
	}
	if tenantID == "" {
		return "", "", newServiceError(http.StatusBadRequest, "bad_request", "tenant_id is required")
	}
	if err := tenantcheck.Enforce(r, tenantID); err != nil {
		return "", "", newServiceError(http.StatusForbidden, "tenant_mismatch", "tenant_id does not match authenticated token")
	}
	return tenantID, firstNonEmpty(claims.UserID, claims.ClientID, claims.Subject), nil
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

	rawToken := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
	if rawToken != "" {
		claims, err := parseBitLockerJWT(rawToken)
		if err == nil && !isBitLockerRole(claims.Role) && requireAgentAuth {
			return "", "", "", false, newServiceError(http.StatusForbidden, "role_not_allowed", "jwt role is not allowed for bitlocker")
		}
		if err == nil && isBitLockerRole(claims.Role) {
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
		if err != nil && requireAgentAuth {
			return "", "", "", false, newServiceError(http.StatusUnauthorized, "invalid_token", err.Error())
		}
	}
	if requireAgentAuth {
		return "", "", "", false, newServiceError(http.StatusUnauthorized, "unauthorized", "bitlocker agent auth requires a bitlocker-role JWT")
	}
	// Dashboard and admin calls: a verified auth-service token for the tenant.
	tenantID, actor, err := tenantFromRequest(r, tenantID)
	if err != nil {
		return "", "", "", false, err
	}
	return tenantID, "", actor, false, nil
}

type bitLockerJWTClaims struct {
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

var (
	bitLockerJWTOnce   sync.Once
	bitLockerJWTErr    error
	bitLockerJWTVerify func(string) (*bitLockerJWTClaims, error)
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
		pub, err := pkgcrypto.ParseRSAPublicKeyPEM(string(pemRaw))
		if err != nil {
			bitLockerJWTErr = errors.New("jwt public key is not RSA")
			return
		}
		bitLockerJWTVerify = func(raw string) (*bitLockerJWTClaims, error) {
			return pkgauth.ParseRS256WithClaims(raw, &bitLockerJWTClaims{}, pub, pkgauth.ParseOptions{
				Issuer:   strings.TrimSpace(os.Getenv("JWT_ISSUER")),
				Audience: strings.TrimSpace(os.Getenv("JWT_AUDIENCE")),
				Leeway:   30 * time.Second,
			})
		}
	})
	if bitLockerJWTErr != nil {
		return nil, bitLockerJWTErr
	}
	if bitLockerJWTVerify == nil {
		return nil, errors.New("jwt public key is not configured")
	}
	return bitLockerJWTVerify(rawToken)
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, reqID string, tenantID string) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		writeErr(w, svcErr.HTTPStatus, svcErr.Code, svcErr.Message, reqID, tenantID)
		if svcErr.HTTPStatus == http.StatusUnauthorized || svcErr.HTTPStatus == http.StatusForbidden {
			_ = h.svc.publishAudit(context.Background(), "audit.ekm.request_refused", tenantID, map[string]interface{}{
				"code": svcErr.Code, "reason": svcErr.Message, "status": svcErr.HTTPStatus,
				"result": "refused", "severity": "warning", "request_id": reqID,
			})
		}
		return
	}
	// A05: avoid leaking internal error details for 5xx responses
	status := httpStatusForErr(err)
	msg := err.Error()
	if status >= 500 {
		msg = "internal server error"
	}
	writeErr(w, status, "internal_error", msg, reqID, tenantID)
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
