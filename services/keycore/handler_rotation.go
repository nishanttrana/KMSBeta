package main

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// handleListRotationPolicies handles GET /rotation/policies
func (h *Handler) handleListRotationPolicies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListRotationPolicies(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_rotation_policies_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

// handleCreateRotationPolicy handles POST /rotation/policies
func (h *Handler) handleCreateRotationPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req CreateRotationPolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name is required", reqID, tenantID)
		return
	}
	targetType := strings.TrimSpace(req.TargetType)
	if targetType == "" {
		targetType = "key"
	}
	intervalDays := req.IntervalDays
	if intervalDays <= 0 {
		intervalDays = 90
	}
	notifyDays := req.NotifyDaysBefore
	if notifyDays <= 0 {
		notifyDays = 7
	}

	// Compute initial next_rotation_at.
	nextRotation := time.Now().UTC().AddDate(0, 0, intervalDays)

	p := RotationPolicy{
		ID:               newID("rp"),
		TenantID:         tenantID,
		Name:             strings.TrimSpace(req.Name),
		TargetType:       targetType,
		TargetFilter:     req.TargetFilter,
		IntervalDays:     intervalDays,
		CronExpr:         req.CronExpr,
		AutoRotate:       req.AutoRotate,
		NotifyDaysBefore: notifyDays,
		Enabled:          true,
		Status:           "active",
		NextRotationAt:   &nextRotation,
	}

	created, err := h.svc.store.CreateRotationPolicy(r.Context(), p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_rotation_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"policy": created, "request_id": reqID})
}

// handleUpdateRotationPolicy handles PATCH /rotation/policies/{id}
func (h *Handler) handleUpdateRotationPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	policyID := r.PathValue("id")

	// Fetch existing policy first.
	policies, err := h.svc.store.ListRotationPolicies(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "update_rotation_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	var existing *RotationPolicy
	for i := range policies {
		if policies[i].ID == policyID {
			existing = &policies[i]
			break
		}
	}
	if existing == nil {
		writeErr(w, http.StatusNotFound, "not_found", "rotation policy not found", reqID, tenantID)
		return
	}

	var req struct {
		Name             string `json:"name"`
		TargetType       string `json:"target_type"`
		TargetFilter     string `json:"target_filter"`
		IntervalDays     int    `json:"interval_days"`
		CronExpr         string `json:"cron_expr"`
		AutoRotate       *bool  `json:"auto_rotate"`
		NotifyDaysBefore int    `json:"notify_days_before"`
		Enabled          *bool  `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}

	// Apply patch fields over existing.
	updated := *existing
	if strings.TrimSpace(req.Name) != "" {
		updated.Name = strings.TrimSpace(req.Name)
	}
	if strings.TrimSpace(req.TargetType) != "" {
		updated.TargetType = strings.TrimSpace(req.TargetType)
	}
	if req.TargetFilter != "" {
		updated.TargetFilter = req.TargetFilter
	}
	if req.IntervalDays > 0 {
		updated.IntervalDays = req.IntervalDays
		// Recalculate next rotation when interval changes.
		next := time.Now().UTC().AddDate(0, 0, updated.IntervalDays)
		updated.NextRotationAt = &next
	}
	if req.CronExpr != "" {
		updated.CronExpr = req.CronExpr
	}
	if req.AutoRotate != nil {
		updated.AutoRotate = *req.AutoRotate
	}
	if req.NotifyDaysBefore > 0 {
		updated.NotifyDaysBefore = req.NotifyDaysBefore
	}
	if req.Enabled != nil {
		updated.Enabled = *req.Enabled
	}

	result, err := h.svc.store.UpdateRotationPolicy(r.Context(), tenantID, policyID, updated)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "update_rotation_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": result, "request_id": reqID})
}

// handleDeleteRotationPolicy handles DELETE /rotation/policies/{id}
func (h *Handler) handleDeleteRotationPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	if err := h.svc.store.DeleteRotationPolicy(r.Context(), tenantID, r.PathValue("id")); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "delete_rotation_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "request_id": reqID})
}

// handleTriggerRotation handles POST /rotation/policies/{id}/trigger
// It creates an immediate rotation run record for the given policy.
func (h *Handler) handleTriggerRotation(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	policyID := r.PathValue("id")

	// Resolve policy name.
	policies, err := h.svc.store.ListRotationPolicies(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "trigger_rotation_failed", err.Error(), reqID, tenantID)
		return
	}
	var policy *RotationPolicy
	for i := range policies {
		if policies[i].ID == policyID {
			policy = &policies[i]
			break
		}
	}
	if policy == nil {
		writeErr(w, http.StatusNotFound, "not_found", "rotation policy not found", reqID, tenantID)
		return
	}

	actor := accessActorFromContext(r.Context())
	triggeredBy := strings.TrimSpace(actor.UserID)
	if triggeredBy == "" {
		triggeredBy = strings.TrimSpace(actor.Username)
	}
	if triggeredBy == "" {
		triggeredBy = "manual"
	}

	run := RotationRun{
		ID:          newID("rr"),
		TenantID:    tenantID,
		PolicyID:    policyID,
		PolicyName:  policy.Name,
		TargetID:    policy.TargetFilter,
		TargetName:  policy.Name,
		TargetType:  policy.TargetType,
		Status:      "running",
		TriggeredBy: triggeredBy,
		StartedAt:   time.Now().UTC(),
	}

	created, err := h.svc.store.CreateRotationRun(r.Context(), run)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "trigger_rotation_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"run": created, "request_id": reqID})
}

// handleListRotationRuns handles GET /rotation/runs
// Accepts optional ?policy_id= query param to filter by policy.
func (h *Handler) handleListRotationRuns(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	policyID := strings.TrimSpace(r.URL.Query().Get("policy_id"))
	items, err := h.svc.store.ListRotationRuns(r.Context(), tenantID, policyID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_rotation_runs_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

// handleListUpcomingRotations handles GET /rotation/upcoming
func (h *Handler) handleListUpcomingRotations(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListUpcomingRotations(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_upcoming_rotations_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}
