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
	window := opsWindow(r)
	ov, err := h.store.GetOpsOverview(r.Context(), tenantID, window)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", "internal query error", reqID, tenantID)
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
	window := opsWindow(r)
	items, err := h.store.GetOpsTimeSeries(r.Context(), tenantID, window)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", "internal query error", reqID, tenantID)
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
	items, err := h.store.GetLatencyPercentiles(r.Context(), tenantID, opsWindow(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", "internal query error", reqID, tenantID)
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
	items, err := h.store.GetServiceStats(r.Context(), tenantID, opsWindow(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", "internal query error", reqID, tenantID)
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
	window := opsWindow(r)
	items, err := h.store.GetErrorBreakdown(r.Context(), tenantID, window)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", "internal query error", reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"window":     window,
		"request_id": reqID,
	})
}

// opsWindow is the request's window (1h, 6h, 24h, 7d, 30d; default 24h).
func opsWindow(r *http.Request) string {
	if w := strings.TrimSpace(r.URL.Query().Get("window")); w != "" {
		return w
	}
	return "24h"
}
