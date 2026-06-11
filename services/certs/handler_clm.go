package main

import "net/http"

func (h *Handler) handleGetCLMPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	policy, err := h.svc.GetCLMPolicy(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "get_clm_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": policy, "request_id": reqID})
}

func (h *Handler) handleUpsertCLMPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	var body struct {
		Mode            string `json:"mode"`
		MaxValidityDays int64  `json:"max_validity_days"`
		ScheduleAware   bool   `json:"schedule_aware"`
		RenewBeforeDays int64  `json:"renew_before_days"`
		UpdatedBy       string `json:"updated_by"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	policy, err := h.svc.UpsertCLMPolicy(r.Context(), CLMPolicy{
		TenantID:        tenantID,
		Mode:            body.Mode,
		MaxValidityDays: body.MaxValidityDays,
		ScheduleAware:   body.ScheduleAware,
		RenewBeforeDays: body.RenewBeforeDays,
		UpdatedBy:       body.UpdatedBy,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "upsert_clm_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": policy, "request_id": reqID})
}

func (h *Handler) handleCLMStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	status, err := h.svc.GetCLMStatus(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "get_clm_status_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": status, "request_id": reqID})
}
