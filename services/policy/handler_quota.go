package main

import (
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/quota"
	"vecta-kms/pkg/tenantcheck"
)

// handleGetQuota returns the current quota usage view for a tenant.
//
// GET /policy/quota/{tenant_id}
func (h *Handler) handleGetQuota(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	if err := tenantcheck.Enforce(r, tenantID); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "tenant_id does not match authenticated token", reqID, tenantID)
		return
	}
	if h.svc.quota == nil {
		writeErr(w, http.StatusServiceUnavailable, "quota_disabled", "quota tracking is disabled", reqID, tenantID)
		return
	}
	used, b, ok := h.svc.quota.Usage(tenantID)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"tenant_id":   tenantID,
			"has_budget":  false,
			"request_id":  reqID,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id":  tenantID,
		"has_budget": true,
		"used":       used,
		"budget":     b,
		"request_id": reqID,
	})
}

// handleSetQuota installs or updates the budget for a tenant.
//
// PUT /policy/quota/{tenant_id}
func (h *Handler) handleSetQuota(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	if err := tenantcheck.Enforce(r, tenantID); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "tenant_id does not match authenticated token", reqID, tenantID)
		return
	}
	if h.svc.quota == nil {
		writeErr(w, http.StatusServiceUnavailable, "quota_disabled", "quota tracking is disabled", reqID, tenantID)
		return
	}
	var req struct {
		Limit         int64   `json:"limit"`
		WarnAt        float64 `json:"warn_at"`
		WindowSeconds int     `json:"window_seconds"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid request body", reqID, tenantID)
		return
	}
	if req.Limit <= 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "limit must be positive", reqID, tenantID)
		return
	}
	window := time.Duration(req.WindowSeconds) * time.Second
	if window <= 0 {
		window = 24 * time.Hour
	}
	h.svc.quota.SetBudget(quota.Budget{
		TenantID:     tenantID,
		Limit:        req.Limit,
		WarnAt:       req.WarnAt,
		WindowLength: window,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"request_id": reqID,
	})
}
