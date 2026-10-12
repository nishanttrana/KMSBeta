package main

import (
	"errors"
	"net/http"

	"vecta-kms/pkg/route"
)

// BYOK routes, through the route kernel: authenticated, tenant-checked,
// permission-checked, and audited as audit.cloud.<action>, refusals
// included (docs/API_REFERENCE.md, Cloud BYOK).
func (h *Handler) byokRoutes(rt *route.Router) {
	read := func(action string) route.Spec {
		return route.Spec{Action: action, Permission: "cloud.read", Resource: "cloud_byok_key"}
	}
	write := func(action, severity string) route.Spec {
		return route.Spec{Action: action, Permission: "cloud.write", Resource: "cloud_byok_key", TargetParam: "id", Severity: severity}
	}
	rt.Handle("GET /cloud/byok/providers", read("byok_providers_read"), func(c *route.Call) {
		c.JSON(http.StatusOK, map[string]interface{}{"items": h.svc.BYOKProviders()})
	})
	rt.Handle("GET /cloud/byok/keys", read("byok_keys_listed"), h.listBYOK)
	rt.Handle("GET /cloud/byok/runs", read("byok_runs_listed"), h.listBYOKRuns)
	rt.Handle("GET /cloud/byok/keys/{id}", route.Spec{Action: "byok_key_read", Permission: "cloud.read", Resource: "cloud_byok_key", TargetParam: "id"}, h.getBYOK)
	rt.Handle("POST /cloud/byok/keys", route.Spec{Action: "byok_created", Permission: "cloud.write", Resource: "cloud_byok_key", Severity: "warning"}, h.createBYOK)
	op := func(name string) func(*route.Call) { return func(c *route.Call) { h.runBYOK(c, name) } }
	rt.Handle("POST /cloud/byok/keys/{id}/rotate", write("byok_rotated", "warning"), op(OpRotate))
	rt.Handle("POST /cloud/byok/keys/{id}/reimport", write("byok_reimported", "warning"), op(OpReimport))
	rt.Handle("POST /cloud/byok/keys/{id}/restore", write("byok_restored", "warning"), op(OpRestore))
	rt.Handle("POST /cloud/byok/keys/{id}/verify", write("byok_verified", "info"), op(OpVerify))
	rt.Handle("POST /cloud/byok/keys/{id}/sync", write("byok_synced", "info"), op(OpSync))
	rt.Handle("POST /cloud/byok/keys/{id}/revoke", write("byok_revoked", "critical"), op(OpRevoke))
	rt.Handle("PUT /cloud/byok/keys/{id}/automation", write("byok_automation_updated", "warning"), h.setBYOKAutomation)
}

// byokFail writes err: a refusal as refused with its reason, a failed run
// with its steps.
func (h *Handler) byokFail(c *route.Call, run BYOKRun, key BYOKKey, err error) {
	var ref *byokRefusal
	var kc *keycoreError
	var se serviceError
	if run.ID != "" {
		c.Detail("run_id", run.ID)
	}
	switch {
	case errors.As(err, &ref):
		c.Refuse(ref.status, ref.reason, ref.msg)
	case errors.As(err, &kc) && (kc.Status == http.StatusForbidden || kc.Status == http.StatusConflict):
		// keycore refused the material (access, export policy, FIPS mode,
		// a key not made for cloud import).
		c.Refuse(kc.Status, kc.Code, kc.Message)
	case errors.As(err, &se):
		c.Error(se.status, se.code, se.message)
	case run.ID != "":
		c.Detail("error", run.Error)
		c.JSON(http.StatusBadGateway, map[string]interface{}{
			"error": map[string]interface{}{"code": "byok_run_failed", "message": run.Error, "request_id": c.RequestID},
			"run":   run, "key": key,
		})
	default:
		c.Error(http.StatusBadGateway, "byok_failed", err.Error())
	}
}

func (h *Handler) listBYOK(c *route.Call) {
	items, err := h.svc.ListBYOK(c.R.Context(), c.Tenant)
	if err != nil {
		h.byokFail(c, BYOKRun{}, BYOKKey{}, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) listBYOKRuns(c *route.Call) {
	if err := h.svc.byokReady(); err != nil {
		h.byokFail(c, BYOKRun{}, BYOKKey{}, err)
		return
	}
	runs, err := h.svc.byokStore.ListBYOKRuns(c.R.Context(), c.Tenant, c.R.URL.Query().Get("byok_id"), 200)
	if err != nil {
		h.byokFail(c, BYOKRun{}, BYOKKey{}, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": runs})
}

func (h *Handler) getBYOK(c *route.Call) {
	d, err := h.svc.GetBYOK(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		h.byokFail(c, BYOKRun{}, BYOKKey{}, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"key": d.Key, "materials": d.Materials, "runs": d.Runs})
}

func (h *Handler) createBYOK(c *route.Call) {
	var req CreateBYOKRequest
	if !c.Decode(&req) {
		return
	}
	c.Detail("account_id", req.AccountID)
	c.Detail("key_id", req.KeyID)
	run, key, err := h.svc.CreateBYOK(c.R.Context(), c.Tenant, c.Actor(), req)
	if key.ID != "" {
		c.Target(key.ID)
		c.Detail("provider", key.Provider)
		c.Detail("source", key.Source)
		c.Detail("cloud_key_id", key.CloudKeyID)
	}
	if err != nil {
		h.byokFail(c, run, key, err)
		return
	}
	c.Detail("run_id", run.ID)
	c.Detail("material_id", key.CurrentMatID)
	c.JSON(http.StatusCreated, map[string]interface{}{"key": key, "run": run})
}

func (h *Handler) runBYOK(c *route.Call, op string) {
	var req BYOKOperationRequest
	if c.R.ContentLength != 0 && !c.Decode(&req) {
		return
	}
	run, key, err := h.svc.RunBYOK(c.R.Context(), c.Tenant, c.R.PathValue("id"), op, c.Actor(), req)
	if key.ID != "" {
		c.Detail("provider", key.Provider)
		c.Detail("key_id", key.KeyID)
		c.Detail("cloud_key_id", key.CloudKeyID)
	}
	if err != nil {
		h.byokFail(c, run, key, err)
		return
	}
	c.Detail("run_id", run.ID)
	c.Detail("material_id", key.CurrentMatID)
	c.JSON(http.StatusOK, map[string]interface{}{"key": key, "run": run})
}
