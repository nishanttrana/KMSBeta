package main

import (
	"errors"
	"log"
	"net/http"

	"vecta-kms/pkg/route"
)

// Handler serves the PQC readiness and migration API. Every route is
// registered through the pkg/route kernel, which authenticates the caller,
// binds the tenant to the verified token, checks the route's permission and
// emits one audit.pqc.<action> event per request, refusals included. Before
// 5.2.0-beta this was a raw mux: the tenant came from the query or body, no
// permission was checked, and the actor recorded for a plan execution came
// from the request body.
type Handler struct {
	svc    *Service
	router *route.Router
}

// Permissions for the pqc domain.
const (
	permRead  = "pqc.read"
	permWrite = "pqc.write" // policy, scans, plans, execution, rollback
)

func NewHandler(svc *Service, audit route.Emitter, logger *log.Logger) *Handler {
	h := &Handler{svc: svc, router: route.New("pqc", audit, logger)}
	h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.router.ServeHTTP(w, r)
}

func (h *Handler) routes() {
	r := h.router
	spec := func(action, perm, resource, target string) route.Spec {
		return route.Spec{Action: action, Permission: perm, Resource: resource, TargetParam: target}
	}
	r.Handle("GET /pqc/policy", spec("policy_read", permRead, "pqc_policy", ""), h.getPolicy)
	r.Handle("PUT /pqc/policy", spec("policy_update_requested", permWrite, "pqc_policy", ""), h.updatePolicy)
	r.Handle("GET /pqc/inventory", spec("inventory_read", permRead, "pqc_inventory", ""), h.getInventory)
	r.Handle("POST /pqc/scan", spec("scan_requested", permWrite, "pqc_scan", ""), h.startScan)
	r.Handle("GET /pqc/scans", spec("scans_listed", permRead, "pqc_scan", ""), h.listScans)
	r.Handle("GET /pqc/scans/{id}", spec("scan_read", permRead, "pqc_scan", "id"), h.getScan)
	r.Handle("GET /pqc/readiness", spec("readiness_read", permRead, "pqc_scan", ""), h.getReadiness)

	r.Handle("GET /pqc/migration/report", spec("migration_report_read", permRead, "pqc_plan", ""), h.getMigrationReport)
	r.Handle("POST /pqc/migration/plans", spec("plan_create_requested", permWrite, "pqc_plan", ""), h.createPlan)
	r.Handle("GET /pqc/migration/plans", spec("plans_listed", permRead, "pqc_plan", ""), h.listPlans)
	r.Handle("GET /pqc/migration/plans/{id}", spec("plan_read", permRead, "pqc_plan", "id"), h.getPlan)
	r.Handle("POST /pqc/migration/plans/{id}/execute", route.Spec{Action: "plan_execute_requested", Permission: permWrite, Resource: "pqc_plan", TargetParam: "id", Severity: "warning"}, h.executePlan)
	r.Handle("POST /pqc/migration/plans/{id}/rollback", route.Spec{Action: "plan_rollback_requested", Permission: permWrite, Resource: "pqc_plan", TargetParam: "id", Severity: "warning"}, h.rollbackPlan)
	r.Handle("GET /pqc/migration/plans/{id}/runs", spec("plan_runs_listed", permRead, "pqc_plan", "id"), h.listRuns)

	r.Handle("GET /pqc/timeline", spec("timeline_read", permRead, "pqc_plan", ""), h.timeline)
	r.Handle("GET /pqc/cbom/export", spec("cbom_exported", permRead, "cbom", ""), h.exportCBOM)
}

func (h *Handler) getPolicy(c *route.Call) {
	item, err := h.svc.GetPolicy(c.R.Context(), c.Tenant)
	if !h.ok(c, err) {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"policy": item})
}

func (h *Handler) updatePolicy(c *route.Call) {
	var req PQCPolicy
	if !c.Decode(&req) {
		return
	}
	req.TenantID, req.UpdatedBy = c.Tenant, c.Actor()
	item, err := h.svc.UpdatePolicy(c.R.Context(), req)
	if !h.ok(c, err) {
		return
	}
	c.Detail("profile_id", item.ProfileID)
	c.JSON(http.StatusOK, map[string]interface{}{"policy": item})
}

func (h *Handler) getInventory(c *route.Call) {
	item, err := h.svc.GetInventory(c.R.Context(), c.Tenant)
	if !h.ok(c, err) {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"inventory": item})
}

func (h *Handler) startScan(c *route.Call) {
	var req ScanRequest
	if !c.Decode(&req) {
		return
	}
	req.TenantID = c.Tenant
	item, err := h.svc.StartReadinessScan(c.R.Context(), req)
	if !h.ok(c, err) {
		return
	}
	c.Target(item.ID)
	c.Detail("total_assets", item.TotalAssets)
	c.JSON(http.StatusAccepted, map[string]interface{}{"scan": item})
}

func (h *Handler) listScans(c *route.Call) {
	q := c.R.URL.Query()
	items, err := h.svc.ListReadinessScans(c.R.Context(), c.Tenant, atoi(q.Get("limit")), atoi(q.Get("offset")))
	if !h.ok(c, err) {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) getScan(c *route.Call) {
	item, err := h.svc.GetReadinessScan(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if !h.ok(c, err) {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"scan": item})
}

func (h *Handler) getReadiness(c *route.Call) {
	item, err := h.svc.GetLatestReadiness(c.R.Context(), c.Tenant)
	if !h.ok(c, err) {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"readiness": item})
}

func (h *Handler) createPlan(c *route.Call) {
	var req PlanRequest
	if !c.Decode(&req) {
		return
	}
	req.TenantID, req.CreatedBy = c.Tenant, c.Actor()
	item, err := h.svc.CreateMigrationPlan(c.R.Context(), req)
	if !h.ok(c, err) {
		return
	}
	c.Target(item.ID)
	c.Detail("steps", len(item.Steps))
	c.JSON(http.StatusCreated, map[string]interface{}{"plan": item})
}

func (h *Handler) getMigrationReport(c *route.Call) {
	item, err := h.svc.GetMigrationReport(c.R.Context(), c.Tenant)
	if !h.ok(c, err) {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"report": item})
}

func (h *Handler) listPlans(c *route.Call) {
	q := c.R.URL.Query()
	items, err := h.svc.ListMigrationPlans(c.R.Context(), c.Tenant, atoi(q.Get("limit")), atoi(q.Get("offset")))
	if !h.ok(c, err) {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) getPlan(c *route.Call) {
	item, err := h.svc.GetMigrationPlan(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if !h.ok(c, err) {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"plan": item})
}

// executePlan records the verified caller as the actor; a body "actor" is
// ignored.
func (h *Handler) executePlan(c *route.Call) {
	var req ExecuteRequest
	if !c.Decode(&req) {
		return
	}
	req.TenantID, req.Actor = c.Tenant, c.Actor()
	run, err := h.svc.ExecuteMigrationPlan(c.R.Context(), c.Tenant, c.R.PathValue("id"), req)
	if !h.ok(c, err) {
		return
	}
	c.Detail("dry_run", req.DryRun)
	c.Detail("run_status", run.Status)
	c.JSON(http.StatusOK, map[string]interface{}{"run": run})
}

func (h *Handler) rollbackPlan(c *route.Call) {
	var req RollbackRequest
	if !c.Decode(&req) {
		return
	}
	item, err := h.svc.RollbackMigrationPlan(c.R.Context(), c.Tenant, c.R.PathValue("id"), c.Actor())
	if !h.ok(c, err) {
		return
	}
	c.Detail("plan_status", item.Status)
	c.JSON(http.StatusOK, map[string]interface{}{"plan": item})
}

func (h *Handler) listRuns(c *route.Call) {
	items, err := h.svc.ListMigrationRuns(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if !h.ok(c, err) {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) timeline(c *route.Call) {
	milestones, readiness, err := h.svc.Timeline(c.R.Context(), c.Tenant)
	if !h.ok(c, err) {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{
		"tenant_id":  c.Tenant,
		"readiness":  map[string]interface{}{"total_assets": readiness.TotalAssets},
		"milestones": milestones,
	})
}

func (h *Handler) exportCBOM(c *route.Call) {
	item, err := h.svc.ExportCBOM(c.R.Context(), c.Tenant)
	if !h.ok(c, err) {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"document": item})
}

// ok writes a service error and reports whether the call may continue.
func (h *Handler) ok(c *route.Call, err error) bool {
	if err == nil {
		return true
	}
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		c.Error(svcErr.HTTPStatus, svcErr.Code, svcErr.Message)
		return false
	}
	status := httpStatusForErr(err)
	msg := err.Error()
	if status >= 500 {
		msg = "internal server error" // A05: no internal detail on 5xx
	}
	c.Error(status, "internal_error", msg)
	return false
}
