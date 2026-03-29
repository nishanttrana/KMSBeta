package main

import (
	"net/http"
	"strings"
)

func (h *Handler) handleGetOpsOverview(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	window := strings.TrimSpace(r.URL.Query().Get("window"))
	if window == "" {
		window = "24h"
	}
	ov, err := h.store.GetOpsOverview(r.Context(), tenantID, window)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"overview":   ov,
		"request_id": reqID,
	})
}

func (h *Handler) handleGetOpsTimeSeries(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	window := strings.TrimSpace(r.URL.Query().Get("window"))
	if window == "" {
		window = "24h"
	}
	items, err := h.store.GetOpsTimeSeries(r.Context(), tenantID, window)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"window":     window,
		"request_id": reqID,
	})
}

func (h *Handler) handleGetLatencyPercentiles(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.store.GetLatencyPercentiles(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"request_id": reqID,
	})
}

func (h *Handler) handleGetServiceStats(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.store.GetServiceStats(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"request_id": reqID,
	})
}

func (h *Handler) handleGetErrorBreakdown(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	window := strings.TrimSpace(r.URL.Query().Get("window"))
	if window == "" {
		window = "24h"
	}
	items, err := h.store.GetErrorBreakdown(r.Context(), tenantID, window)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"window":     window,
		"request_id": reqID,
	})
}

func (h *Handler) handleRecordOp(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	var req struct {
		Service   string `json:"service"`
		OpType    string `json:"op_type"`
		LatencyMs int    `json:"latency_ms"`
		IsError   bool   `json:"is_error"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.OpType) == "" {
		writeErr(w, http.StatusBadRequest, "validation_error", "op_type is required", reqID, tenantID)
		return
	}
	if err := h.store.RecordOp(r.Context(), tenantID, req.Service, req.OpType, req.LatencyMs, req.IsError); err != nil {
		writeErr(w, http.StatusInternalServerError, "record_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"recorded":   true,
		"request_id": reqID,
	})
}
