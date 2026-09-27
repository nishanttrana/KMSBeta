package main

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/route"
)

// rotationRouter serves rotation policies through the pkg/route kernel; the
// legacy mux mounts it. A trigger rotates the matching keys now, as the
// caller (rotation_engine.go).
func (h *Handler) rotationRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	r.Handle("GET /rotation/policies", route.Spec{Action: "rotation_policies_listed", Permission: "key.rotation.read", Resource: "rotation_policy"}, h.listRotationPolicies)
	r.Handle("POST /rotation/policies", route.Spec{Action: "rotation_policy_created", Permission: "key.rotation.write", Resource: "rotation_policy"}, h.createRotationPolicy)
	r.Handle("PATCH /rotation/policies/{id}", route.Spec{Action: "rotation_policy_updated", Permission: "key.rotation.write", Resource: "rotation_policy", TargetParam: "id"}, h.updateRotationPolicy)
	r.Handle("DELETE /rotation/policies/{id}", route.Spec{Action: "rotation_policy_deleted", Permission: "key.rotation.write", Resource: "rotation_policy", TargetParam: "id", Severity: "warning"}, h.deleteRotationPolicy)
	r.Handle("POST /rotation/policies/{id}/trigger", route.Spec{Action: "rotation_policy_triggered", Permission: "key.rotation.write", Resource: "rotation_policy", TargetParam: "id", Severity: "warning"}, h.triggerRotationPolicy)
	r.Handle("GET /rotation/runs", route.Spec{Action: "rotation_runs_listed", Permission: "key.rotation.read", Resource: "rotation_policy"}, h.listRotationRuns)
	r.Handle("GET /rotation/upcoming", route.Spec{Action: "rotation_upcoming_listed", Permission: "key.rotation.read", Resource: "rotation_policy"}, h.listUpcomingRotations)
	return r
}

func (h *Handler) listRotationPolicies(c *route.Call) {
	items, err := h.svc.store.ListRotationPolicies(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_rotation_policies_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) createRotationPolicy(c *route.Call) {
	var req CreateRotationPolicyRequest
	if !c.Decode(&req) {
		return
	}
	req.Name, req.TargetFilter = strings.TrimSpace(req.Name), strings.TrimSpace(req.TargetFilter)
	if req.Name == "" {
		c.Error(http.StatusBadRequest, "bad_request", "name is required")
		return
	}
	if t := strings.TrimSpace(req.TargetType); t != "" && t != rotationTargetKey {
		c.Error(http.StatusBadRequest, "unsupported_target_type", errRotationTargetUnsupported.Error())
		return
	}
	if err := validateRotationFilter(req.TargetFilter); err != nil {
		c.Error(http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if req.IntervalDays <= 0 || req.IntervalDays > 3650 {
		c.Error(http.StatusBadRequest, "bad_request", "interval_days must be 1-3650")
		return
	}
	next := time.Now().UTC().AddDate(0, 0, req.IntervalDays)
	created, err := h.svc.store.CreateRotationPolicy(c.R.Context(), RotationPolicy{
		ID: newID("rp"), TenantID: c.Tenant, Name: req.Name, TargetType: rotationTargetKey,
		TargetFilter: req.TargetFilter, IntervalDays: req.IntervalDays, AutoRotate: req.AutoRotate,
		Enabled: true, Status: "active", NextRotationAt: &next,
	})
	if err != nil {
		c.Error(http.StatusInternalServerError, "create_rotation_policy_failed", err.Error())
		return
	}
	c.Target(created.ID)
	c.Detail("target_filter", created.TargetFilter)
	c.Detail("interval_days", created.IntervalDays)
	c.Detail("auto_rotate", created.AutoRotate)
	c.JSON(http.StatusCreated, map[string]interface{}{"policy": created})
}

func (h *Handler) loadRotationPolicy(c *route.Call) (RotationPolicy, bool) {
	p, err := h.svc.store.GetRotationPolicy(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errStoreNotFound) {
		c.Error(http.StatusNotFound, "not_found", "rotation policy not found")
		return p, false
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "rotation_policy_lookup_failed", err.Error())
		return p, false
	}
	return p, true
}

func (h *Handler) updateRotationPolicy(c *route.Call) {
	var req struct {
		TenantID     string  `json:"tenant_id"` // enforced by the kernel
		Name         *string `json:"name"`
		TargetFilter *string `json:"target_filter"`
		IntervalDays *int    `json:"interval_days"`
		AutoRotate   *bool   `json:"auto_rotate"`
		Enabled      *bool   `json:"enabled"`
	}
	if !c.Decode(&req) {
		return
	}
	p, ok := h.loadRotationPolicy(c)
	if !ok {
		return
	}
	if req.Name != nil {
		if n := strings.TrimSpace(*req.Name); n != "" {
			p.Name = n
		}
	}
	if req.TargetFilter != nil {
		f := strings.TrimSpace(*req.TargetFilter)
		if err := validateRotationFilter(f); err != nil {
			c.Error(http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		p.TargetFilter = f
		c.Detail("target_filter", f)
	}
	if req.IntervalDays != nil {
		if *req.IntervalDays <= 0 || *req.IntervalDays > 3650 {
			c.Error(http.StatusBadRequest, "bad_request", "interval_days must be 1-3650")
			return
		}
		p.IntervalDays = *req.IntervalDays
		base := time.Now().UTC()
		if p.LastRotationAt != nil {
			base = *p.LastRotationAt
		}
		next := base.AddDate(0, 0, p.IntervalDays)
		p.NextRotationAt = &next
		c.Detail("interval_days", p.IntervalDays)
	}
	if req.AutoRotate != nil {
		p.AutoRotate = *req.AutoRotate
		c.Detail("auto_rotate", p.AutoRotate)
	}
	if req.Enabled != nil {
		p.Enabled = *req.Enabled
		c.Detail("enabled", p.Enabled)
	}
	updated, err := h.svc.store.UpdateRotationPolicy(c.R.Context(), c.Tenant, p.ID, p)
	if err != nil {
		c.Error(http.StatusInternalServerError, "update_rotation_policy_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"policy": updated})
}

func (h *Handler) deleteRotationPolicy(c *route.Call) {
	err := h.svc.store.DeleteRotationPolicy(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errStoreNotFound) {
		c.Error(http.StatusNotFound, "not_found", "rotation policy not found")
		return
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "delete_rotation_policy_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "deleted"})
}

// triggerRotationPolicy rotates the policy's keys now, as the caller: their
// key grants and the policy service apply to each rotation.
func (h *Handler) triggerRotationPolicy(c *route.Call) {
	p, ok := h.loadRotationPolicy(c)
	if !ok {
		return
	}
	out, err := h.svc.RunRotationPolicy(c.R.Context(), p, "manual:"+c.Actor())
	c.Detail("matched", out.Matched)
	c.Detail("rotated", out.Rotated)
	c.Detail("failed", out.Failed)
	switch {
	case errors.Is(err, errRotationTargetUnsupported):
		c.Error(http.StatusBadRequest, "unsupported_target_type", err.Error())
		return
	case err != nil:
		c.Error(http.StatusUnprocessableEntity, "rotation_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"outcome": out})
}

func (h *Handler) listRotationRuns(c *route.Call) {
	items, err := h.svc.store.ListRotationRuns(c.R.Context(), c.Tenant, strings.TrimSpace(c.R.URL.Query().Get("policy_id")))
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_rotation_runs_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) listUpcomingRotations(c *route.Call) {
	items, err := h.svc.store.ListUpcomingRotations(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_upcoming_rotations_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}
