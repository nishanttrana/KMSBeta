package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

func (h *Handler) handleGetRenewalSummary(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	summary, err := h.svc.GetRenewalSummary(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "renewal_summary_failed", err.Error(), reqID, tenantID)
		return
	}
	_ = h.svc.publishAudit(r.Context(), "audit.cert.renewal_schedule_viewed", tenantID, map[string]interface{}{
		"missed_window_count":      summary.MissedWindowCount,
		"emergency_rotation_count": summary.EmergencyRotationCount,
		"mass_renewal_risk_count":  len(summary.MassRenewalRisks),
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"summary": summary, "request_id": reqID})
}

func (h *Handler) handleGetRenewalInfo(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	item, err := h.svc.GetRenewalInfo(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "renewal_info_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleRefreshRenewalSummary(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	if err := h.svc.RefreshTenantRenewalIntelligence(r.Context(), tenantID); err != nil {
		writeErr(w, http.StatusInternalServerError, "renewal_refresh_failed", err.Error(), reqID, tenantID)
		return
	}
	summary, err := h.svc.GetRenewalSummary(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "renewal_summary_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"summary": summary, "request_id": reqID})
}

func (h *Handler) handleACMERenewalInfo(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	item, err := h.svc.ACMERenewalInfo(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "acme_renewal_info_failed", err.Error(), reqID, tenantID)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	retryAfter := item.RetryAfterSeconds
	if retryAfter <= 0 {
		retryAfter = defaultARIPollHours * 3600
	}
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(item.RFCRenewalInfo())
}
