package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
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

	mux.HandleFunc("POST /sbom/generate", h.handleGenerateSBOM)
	mux.HandleFunc("GET /sbom/latest", h.handleLatestSBOM)
	mux.HandleFunc("GET /sbom/history", h.handleSBOMHistory)
	mux.HandleFunc("GET /sbom/vulnerabilities", h.handleSBOMVulnerabilities)
	mux.HandleFunc("GET /sbom/diff", h.handleSBOMDiff)
	mux.HandleFunc("GET /sbom/{id}/export", h.handleSBOMExport)
	mux.HandleFunc("GET /sbom/{id}", h.handleSBOMByID)

	mux.HandleFunc("POST /cbom/generate", h.handleGenerateCBOM)
	mux.HandleFunc("GET /cbom/latest", h.handleLatestCBOM)
	mux.HandleFunc("GET /cbom/history", h.handleCBOMHistory)
	mux.HandleFunc("GET /cbom/summary", h.handleCBOMSummary)
	mux.HandleFunc("GET /cbom/pqc-readiness", h.handleCBOMPQCReadiness)
	mux.HandleFunc("GET /cbom/diff", h.handleCBOMDiff)
	mux.HandleFunc("GET /cbom/{id}/export", h.handleCBOMExport)
	mux.HandleFunc("GET /cbom/{id}", h.handleCBOMByID)

	return mux
}

type generateSBOMRequest struct {
	Trigger string `json:"trigger"`
}

func (h *Handler) handleGenerateSBOM(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req generateSBOMRequest
	_ = decodeJSON(r, &req)
	item, err := h.svc.GenerateSBOM(r.Context(), req.Trigger)
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":     "accepted",
		"snapshot":   item,
		"request_id": reqID,
	})
}

func (h *Handler) handleLatestSBOM(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	item, err := h.svc.GetLatestSBOM(r.Context())
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleSBOMHistory(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	items, err := h.svc.ListSBOMHistory(r.Context(), atoi(r.URL.Query().Get("limit")))
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleSBOMByID(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	item, err := h.svc.GetSBOMByID(r.Context(), r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleSBOMExport(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	format := firstNonEmpty(r.URL.Query().Get("format"), "cyclonedx")
	encoding := firstNonEmpty(r.URL.Query().Get("encoding"), "json")
	out, err := h.svc.ExportSBOM(r.Context(), r.PathValue("id"), format, encoding)
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"export": out, "request_id": reqID})
}

func (h *Handler) handleSBOMVulnerabilities(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	items, err := h.svc.SBOMVulnerabilities(r.Context())
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleSBOMDiff(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	diff, err := h.svc.DiffSBOM(r.Context(), strings.TrimSpace(r.URL.Query().Get("from")), strings.TrimSpace(r.URL.Query().Get("to")))
	if err != nil {
		h.writeServiceError(w, err, reqID, "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"diff": diff, "request_id": reqID})
}

type generateCBOMRequest struct {
	TenantID string `json:"tenant_id"`
	Trigger  string `json:"trigger"`
}

func (h *Handler) handleGenerateCBOM(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req generateCBOMRequest
	_ = decodeJSON(r, &req)
	req.TenantID = firstNonEmpty(req.TenantID, tenantFromRequest(r))
	if req.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	item, err := h.svc.GenerateCBOM(r.Context(), req.TenantID, req.Trigger)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":     "accepted",
		"snapshot":   item,
		"request_id": reqID,
	})
}

func (h *Handler) handleLatestCBOM(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	item, err := h.svc.GetLatestCBOM(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleCBOMHistory(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListCBOMHistory(r.Context(), tenantID, atoi(r.URL.Query().Get("limit")))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleCBOMByID(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	item, err := h.svc.GetCBOMByID(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleCBOMExport(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.ExportCBOM(r.Context(), tenantID, r.PathValue("id"), firstNonEmpty(r.URL.Query().Get("format"), "cyclonedx"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"export": out, "request_id": reqID})
}

func (h *Handler) handleCBOMSummary(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.CBOMSummary(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"summary": out, "request_id": reqID})
}

func (h *Handler) handleCBOMPQCReadiness(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	out, err := h.svc.CBOMPQCReadiness(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"pqc_readiness": out, "request_id": reqID})
}

func (h *Handler) handleCBOMDiff(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	diff, err := h.svc.DiffCBOM(r.Context(), tenantID, strings.TrimSpace(r.URL.Query().Get("from")), strings.TrimSpace(r.URL.Query().Get("to")))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"diff": diff, "request_id": reqID})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, reqID string, tenantID string) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		writeErr(w, svcErr.HTTPStatus, svcErr.Code, svcErr.Message, reqID, tenantID)
		return
	}
	writeErr(w, httpStatusForErr(err), "internal_error", err.Error(), reqID, tenantID)
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

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id != "" {
		return id
	}
	return newID("req")
}

func tenantFromRequest(r *http.Request) string {
	return firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("tenant_id")), strings.TrimSpace(r.Header.Get("X-Tenant-ID")))
}

func mustTenant(r *http.Request, reqID string, w http.ResponseWriter) string {
	tenantID := tenantFromRequest(r)
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

func atoi(v string) int {
	n := 0
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return n
		}
		n = n*10 + int(v[i]-'0')
	}
	return n
}
