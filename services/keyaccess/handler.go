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
	mux.HandleFunc("GET /key-access/settings", h.handleGetSettings)
	mux.HandleFunc("PUT /key-access/settings", h.handlePutSettings)
	mux.HandleFunc("GET /key-access/summary", h.handleGetSummary)
	mux.HandleFunc("GET /key-access/codes", h.handleListRules)
	mux.HandleFunc("POST /key-access/codes", h.handleUpsertRule)
	mux.HandleFunc("PUT /key-access/codes/{id}", h.handleUpsertRule)
	mux.HandleFunc("DELETE /key-access/codes/{id}", h.handleDeleteRule)
	mux.HandleFunc("GET /key-access/decisions", h.handleListDecisions)
	mux.HandleFunc("POST /key-access/evaluate", h.handleEvaluate)
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
	var body KeyAccessSettings
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

func (h *Handler) handleListRules(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	items, err := h.svc.ListRules(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleUpsertRule(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body KeyAccessRule
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID, tenantFromRequest(r))
	body.ID = firstNonEmpty(r.PathValue("id"), body.ID)
	item, err := h.svc.UpsertRule(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"rule": item, "request_id": reqID})
}

func (h *Handler) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if err := h.svc.DeleteRule(r.Context(), tenantID, r.PathValue("id")); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "request_id": reqID})
}

func (h *Handler) handleListDecisions(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	items, err := h.svc.ListDecisions(r.Context(), tenantID, r.URL.Query().Get("service"), r.URL.Query().Get("action"), limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body EvaluateKeyAccessInput
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID, tenantFromRequest(r))
	body.RequestID = firstNonEmpty(body.RequestID, reqID)
	item, err := h.svc.Evaluate(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	status := http.StatusOK
	if item.ApprovalRequired {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]interface{}{"result": item, "request_id": reqID})
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
