package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
)

func (h *Handler) handleGetSTARSummary(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	summary, err := h.svc.GetACMESTARSummary(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "star_summary_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"summary": summary, "request_id": reqID})
}

func (h *Handler) handleListSTARSubscriptions(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListACMESTARSubscriptions(r.Context(), tenantID, atoi(r.URL.Query().Get("limit")))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "star_list_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleCreateSTARSubscription(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateACMESTARSubscriptionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	item, err := h.svc.CreateACMESTARSubscription(r.Context(), req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "star_create_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"subscription": item, "request_id": reqID})
}

func (h *Handler) handleRefreshSTARSubscription(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RefreshACMESTARSubscriptionRequest
	_ = decodeJSONAllowEmpty(r, &req)
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	item, err := h.svc.RefreshACMESTARSubscription(r.Context(), req, r.PathValue("id"))
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errStoreNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "star_refresh_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"subscription": item, "request_id": reqID})
}

func (h *Handler) handleDeleteSTARSubscription(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	if err := h.svc.store.DeleteACMESTARSubscription(r.Context(), tenantID, r.PathValue("id")); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "star_delete_failed", err.Error(), reqID, tenantID)
		return
	}
	_ = h.svc.publishAudit(r.Context(), "audit.cert.star_subscription_deleted", tenantID, map[string]interface{}{
		"subscription_id": r.PathValue("id"),
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "deleted", "request_id": reqID})
}

func decodeJSONAllowEmpty(r *http.Request, dst interface{}) error {
	if r == nil || r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	return decodeJSON(r, dst)
}

func tenantFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	for _, value := range []string{
		r.URL.Query().Get("tenant_id"),
		r.Header.Get("X-Tenant-ID"),
		r.Header.Get("X-Tenant"),
	} {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func firstTenant(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func atoi(value string) int {
	out, _ := strconv.Atoi(strings.TrimSpace(value))
	return out
}
