package main

import (
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
	mux.HandleFunc("GET /workload-identity/settings", h.handleGetSettings)
	mux.HandleFunc("PUT /workload-identity/settings", h.handlePutSettings)
	mux.HandleFunc("GET /workload-identity/summary", h.handleGetSummary)
	mux.HandleFunc("GET /workload-identity/registrations", h.handleListRegistrations)
	mux.HandleFunc("POST /workload-identity/registrations", h.handleUpsertRegistration)
	mux.HandleFunc("PUT /workload-identity/registrations/{id}", h.handleUpsertRegistration)
	mux.HandleFunc("DELETE /workload-identity/registrations/{id}", h.handleDeleteRegistration)
	mux.HandleFunc("GET /workload-identity/federation", h.handleListFederation)
	mux.HandleFunc("POST /workload-identity/federation", h.handleUpsertFederation)
	mux.HandleFunc("PUT /workload-identity/federation/{id}", h.handleUpsertFederation)
	mux.HandleFunc("DELETE /workload-identity/federation/{id}", h.handleDeleteFederation)
	mux.HandleFunc("POST /workload-identity/issue", h.handleIssueSVID)
	mux.HandleFunc("GET /workload-identity/issuances", h.handleListIssuances)
	mux.HandleFunc("POST /workload-identity/token/exchange", h.handleExchangeToken)
	mux.HandleFunc("GET /workload-identity/graph", h.handleGetGraph)
	mux.HandleFunc("GET /workload-identity/usage", h.handleListUsage)
	return mux
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
	var body WorkloadIdentitySettings
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

func (h *Handler) handleListRegistrations(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	items, err := h.svc.ListRegistrations(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleUpsertRegistration(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body WorkloadRegistration
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID, tenantFromRequest(r))
	body.ID = firstNonEmpty(r.PathValue("id"), body.ID)
	item, err := h.svc.UpsertRegistration(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"registration": item, "request_id": reqID})
}

func (h *Handler) handleDeleteRegistration(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if err := h.svc.DeleteRegistration(r.Context(), tenantID, r.PathValue("id")); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "request_id": reqID})
}

func (h *Handler) handleListFederation(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	items, err := h.svc.ListFederationBundles(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleUpsertFederation(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body WorkloadFederationBundle
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID, tenantFromRequest(r))
	body.ID = firstNonEmpty(r.PathValue("id"), body.ID)
	item, err := h.svc.UpsertFederationBundle(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"bundle": item, "request_id": reqID})
}

func (h *Handler) handleDeleteFederation(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if err := h.svc.DeleteFederationBundle(r.Context(), tenantID, r.PathValue("id")); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "request_id": reqID})
}

func (h *Handler) handleIssueSVID(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body IssueSVIDRequest
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID, tenantFromRequest(r))
	item, err := h.svc.IssueSVID(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"issued": item, "request_id": reqID})
}

func (h *Handler) handleListIssuances(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	items, err := h.svc.ListIssuances(r.Context(), tenantID, limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleExchangeToken(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body TokenExchangeRequest
	if err := decodeJSON(r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID, tenantFromRequest(r))
	item, err := h.svc.ExchangeToken(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"exchange": item, "request_id": reqID})
}

func (h *Handler) handleGetGraph(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	item, err := h.svc.GetGraph(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"graph": item, "request_id": reqID})
}

func (h *Handler) handleListUsage(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	items, err := h.svc.ListUsage(r.Context(), tenantID, limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, reqID string, tenantID string) {
	status := httpStatusForErr(err)
	code := "internal_error"
	message := err.Error()
	if svcErr, ok := err.(serviceError); ok {
		code = svcErr.Code
		message = svcErr.Message
	}
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]interface{}{
			"code":       code,
			"message":    message,
			"request_id": reqID,
			"tenant_id":  strings.TrimSpace(tenantID),
		},
	})
}
