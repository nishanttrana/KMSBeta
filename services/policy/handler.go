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
	mux.HandleFunc("POST /policies", h.handleCreatePolicy)
	mux.HandleFunc("GET /policies", h.handleListPolicies)
	mux.HandleFunc("GET /policies/{id}", h.handleGetPolicy)
	mux.HandleFunc("PUT /policies/{id}", h.handleUpdatePolicy)
	mux.HandleFunc("DELETE /policies/{id}", h.handleDeletePolicy)
	mux.HandleFunc("GET /policies/{id}/versions", h.handleListVersions)
	mux.HandleFunc("GET /policies/{id}/versions/{version}", h.handleGetVersion)
	mux.HandleFunc("POST /policy/evaluate", h.handleEvaluate)
	return mux
}

func (h *Handler) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreatePolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	p, err := h.svc.CreatePolicy(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "create_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"policy": p, "request_id": reqID})
}

func (h *Handler) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	limit := atoi(r.URL.Query().Get("limit"))
	offset := atoi(r.URL.Query().Get("offset"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	items, err := h.svc.ListPolicies(r.Context(), tenantID, status, limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	p, err := h.svc.GetPolicy(r.Context(), tenantID, r.PathValue("id"))
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "policy not found", reqID, tenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "read_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": p, "request_id": reqID})
}

func (h *Handler) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req UpdatePolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	req.TenantID = tenantID
	p, err := h.svc.UpdatePolicy(r.Context(), r.PathValue("id"), req)
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "policy not found", reqID, tenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "update_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": p, "request_id": reqID})
}

func (h *Handler) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		Actor         string `json:"actor"`
		CommitMessage string `json:"commit_message"`
	}
	_ = decodeJSON(r, &req)
	if err := h.svc.DeletePolicy(r.Context(), tenantID, r.PathValue("id"), req.Actor, req.CommitMessage); err != nil {
		if errors.Is(err, errNotFound) {
			writeErr(w, http.StatusNotFound, "not_found", "policy not found", reqID, tenantID)
			return
		}
		writeErr(w, http.StatusInternalServerError, "delete_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "request_id": reqID})
}

func (h *Handler) handleListVersions(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListPolicyVersions(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "versions_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetVersion(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	ver := atoi(r.PathValue("version"))
	if ver <= 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "version must be > 0", reqID, tenantID)
		return
	}
	v, err := h.svc.GetPolicyVersion(r.Context(), tenantID, r.PathValue("id"), ver)
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "policy version not found", reqID, tenantID)
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "version_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": v, "request_id": reqID})
}

func (h *Handler) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req EvaluatePolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	resp, err := h.svc.Evaluate(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "evaluate_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"decision":   resp.Decision,
		"reason":     resp.Reason,
		"outcomes":   resp.Outcomes,
		"request_id": reqID,
	})
}

func decodeJSON(r *http.Request, out any) error {
	defer r.Body.Close() //nolint:errcheck
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	return d.Decode(out)
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

func atoi(v string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, code string, message string, reqID string, tenantID string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":       code,
			"message":    message,
			"request_id": reqID,
			"tenant_id":  tenantID,
		},
	})
}
