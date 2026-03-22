package main

import (
	"encoding/json"
	"errors"
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
	mux.HandleFunc("GET /signing/settings", h.handleGetSettings)
	mux.HandleFunc("PUT /signing/settings", h.handlePutSettings)
	mux.HandleFunc("GET /signing/summary", h.handleGetSummary)
	mux.HandleFunc("GET /signing/profiles", h.handleListProfiles)
	mux.HandleFunc("POST /signing/profiles", h.handleUpsertProfile)
	mux.HandleFunc("PUT /signing/profiles/{id}", h.handleUpsertProfile)
	mux.HandleFunc("DELETE /signing/profiles/{id}", h.handleDeleteProfile)
	mux.HandleFunc("GET /signing/records", h.handleListRecords)
	mux.HandleFunc("POST /signing/blob", h.handleSignBlob)
	mux.HandleFunc("POST /signing/git", h.handleSignGit)
	mux.HandleFunc("POST /signing/verify", h.handleVerify)
	return mux
}

func tenantFromRequest(r *http.Request) string {
	return strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("tenant_id"), r.Header.Get("X-Tenant-ID")))
}

func requestID(r *http.Request) string {
	return firstNonEmpty(r.Header.Get("X-Request-ID"), newID("req"))
}

func decodeJSON(r *http.Request, out interface{}) error {
	return json.NewDecoder(r.Body).Decode(out)
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
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

func (h *Handler) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	item, err := h.svc.GetSettings(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"settings": item, "request_id": reqID})
}

func (h *Handler) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body SigningSettings
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID, tenantFromRequest(r))
	item, err := h.svc.UpdateSettings(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"settings": item, "request_id": reqID})
}

func (h *Handler) handleGetSummary(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	item, err := h.svc.GetSummary(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"summary": item, "request_id": reqID})
}

func (h *Handler) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	items, err := h.svc.ListProfiles(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleUpsertProfile(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body SigningProfile
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID, tenantFromRequest(r))
	body.ID = firstNonEmpty(r.PathValue("id"), body.ID)
	item, err := h.svc.UpsertProfile(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"profile": item, "request_id": reqID})
}

func (h *Handler) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if err := h.svc.DeleteProfile(r.Context(), tenantID, r.PathValue("id")); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "request_id": reqID})
}

func (h *Handler) handleListRecords(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	items, err := h.svc.ListRecords(r.Context(), tenantID, r.URL.Query().Get("profile_id"), r.URL.Query().Get("artifact_type"), limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleSignBlob(w http.ResponseWriter, r *http.Request) {
	h.handleSign(w, r, "blob")
}

func (h *Handler) handleSignGit(w http.ResponseWriter, r *http.Request) {
	h.handleSign(w, r, "git")
}

func (h *Handler) handleSign(w http.ResponseWriter, r *http.Request, artifactType string) {
	reqID := requestID(r)
	var body SignArtifactInput
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID, tenantFromRequest(r))
	body.ArtifactType = firstNonEmpty(body.ArtifactType, artifactType)
	item, err := h.svc.SignArtifact(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"result": item, "request_id": reqID})
}

func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body VerifyArtifactInput
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID, tenantFromRequest(r))
	item, err := h.svc.VerifyArtifact(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": item, "request_id": reqID})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, reqID string, tenantID string) {
	writeErr(w, httpStatusForErr(err), serviceCode(err), err.Error(), reqID, strings.TrimSpace(tenantID))
}

func serviceCode(err error) string {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		return svcErr.Code
	}
	if errors.Is(err, errNotFound) {
		return "not_found"
	}
	return "internal_error"
}
