package main

import (
	"net/http"
	"strings"
	"time"

	"vecta-kms/pkg/route"
)

// agilityRouter serves the crypto-agility posture, inventory and migration
// plans through the pkg/route kernel (tenant, permission and audit by
// construction); the legacy mux mounts it. Counts come from the tenant's keys
// table and every status and date from pkg/cryptocatalog, which cites the
// NIST document it was copied from.
func (h *Handler) agilityRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	r.Handle("GET /agility/posture", route.Spec{Action: "agility_posture_read", Permission: "key.agility.read", Resource: "agility"}, h.getAgilityPosture)
	r.Handle("GET /agility/algorithms", route.Spec{Action: "agility_inventory_read", Permission: "key.agility.read", Resource: "agility"}, h.getAlgorithmInventory)
	r.Handle("GET /agility/keys-by-algorithm", route.Spec{Action: "agility_keys_by_algorithm_read", Permission: "key.agility.read", Resource: "agility"}, h.getKeysByAlgorithm)
	r.Handle("GET /agility/migration-plans", route.Spec{Action: "agility_migration_plans_listed", Permission: "key.agility.read", Resource: "migration_plan"}, h.listMigrationPlans)
	r.Handle("POST /agility/migration-plans", route.Spec{Action: "agility_migration_plan_created", Permission: "key.agility.write", Resource: "migration_plan"}, h.createMigrationPlan)
	r.Handle("PATCH /agility/migration-plans/{id}", route.Spec{Action: "agility_migration_plan_updated", Permission: "key.agility.write", Resource: "migration_plan", TargetParam: "id"}, h.updateMigrationPlan)
	return r
}

var migrationPlanStatuses = map[string]bool{"planned": true, "in_progress": true, "paused": true, "completed": true}

func (h *Handler) getAgilityPosture(c *route.Call) {
	algos, err := h.svc.store.GetAlgorithmDistribution(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "agility_posture_failed", err.Error())
		return
	}
	p := computeAgilityPosture(algos, time.Now())
	c.Detail("total_keys", p.TotalKeys)
	c.Detail("quantum_vulnerable_keys", p.QuantumVulnerableKeys)
	c.Detail("not_assessed_keys", p.NotAssessedKeys)
	c.JSON(http.StatusOK, map[string]interface{}{"data": p})
}

func (h *Handler) getAlgorithmInventory(c *route.Call) {
	algos, err := h.svc.store.GetAlgorithmDistribution(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "algorithm_inventory_failed", err.Error())
		return
	}
	p := computeAgilityPosture(algos, time.Now()) // annotates share and NIST status
	c.JSON(http.StatusOK, map[string]interface{}{"data": p.Algorithms, "total_keys": p.TotalKeys})
}

func (h *Handler) getKeysByAlgorithm(c *route.Call) {
	algorithm := strings.TrimSpace(c.R.URL.Query().Get("algorithm"))
	if algorithm == "" {
		c.Error(http.StatusBadRequest, "bad_request", "algorithm query parameter is required")
		return
	}
	c.Detail("algorithm", algorithm)
	keys, err := h.svc.store.ListKeysByAlgorithm(c.R.Context(), c.Tenant, algorithm)
	if err != nil {
		c.Error(http.StatusInternalServerError, "keys_by_algorithm_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": KeysByAlgorithm{Algorithm: algorithm, Keys: keys}})
}

// liveKeyCounts maps algorithm to the tenant's live (not deleted) key count.
func (h *Handler) liveKeyCounts(c *route.Call) (map[string]int, bool) {
	algos, err := h.svc.store.GetAlgorithmDistribution(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "algorithm_inventory_failed", err.Error())
		return nil, false
	}
	out := make(map[string]int, len(algos))
	for _, a := range algos {
		out[a.Algorithm] = a.KeyCount
	}
	return out, true
}

// withProgress derives progress from the keys table: remaining is the live
// key count still on from_algorithm; completed is how far that has fallen
// below the count recorded when the plan was created.
func withProgress(mp MigrationPlan, counts map[string]int) MigrationPlan {
	mp.RemainingKeys = counts[mp.FromAlgorithm]
	mp.CompletedKeys = mp.AffectedKeys - mp.RemainingKeys
	if mp.CompletedKeys < 0 {
		mp.CompletedKeys = 0
	}
	return mp
}

func (h *Handler) listMigrationPlans(c *route.Call) {
	plans, err := h.svc.store.ListMigrationPlans(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_migration_plans_failed", err.Error())
		return
	}
	counts, ok := h.liveKeyCounts(c)
	if !ok {
		return
	}
	for i := range plans {
		plans[i] = withProgress(plans[i], counts)
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": plans})
}

// parsePlanDate accepts a calendar date (the dashboard's date input) or RFC3339.
func parsePlanDate(s string) (*time.Time, bool) {
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t, true
		}
	}
	return nil, false
}

func (h *Handler) createMigrationPlan(c *route.Call) {
	var req struct {
		TenantID      string `json:"tenant_id"` // enforced by the kernel
		Name          string `json:"name"`
		FromAlgorithm string `json:"from_algorithm"`
		ToAlgorithm   string `json:"to_algorithm"`
		TargetDate    string `json:"target_date"`
	}
	if !c.Decode(&req) {
		return
	}
	req.Name, req.FromAlgorithm, req.ToAlgorithm = strings.TrimSpace(req.Name), strings.TrimSpace(req.FromAlgorithm), strings.TrimSpace(req.ToAlgorithm)
	if req.Name == "" || req.FromAlgorithm == "" || req.ToAlgorithm == "" {
		c.Error(http.StatusBadRequest, "bad_request", "name, from_algorithm and to_algorithm are required")
		return
	}
	if req.FromAlgorithm == req.ToAlgorithm {
		c.Error(http.StatusBadRequest, "bad_request", "from_algorithm and to_algorithm must differ")
		return
	}
	var targetDate *time.Time
	if s := strings.TrimSpace(req.TargetDate); s != "" {
		t, ok := parsePlanDate(s)
		if !ok {
			c.Error(http.StatusBadRequest, "bad_request", "target_date must be YYYY-MM-DD or RFC3339")
			return
		}
		targetDate = t
	}
	counts, ok := h.liveKeyCounts(c)
	if !ok {
		return
	}
	created, err := h.svc.store.CreateMigrationPlan(c.R.Context(), MigrationPlan{
		ID:            newID("migplan"),
		TenantID:      c.Tenant,
		Name:          req.Name,
		FromAlgorithm: req.FromAlgorithm,
		ToAlgorithm:   req.ToAlgorithm,
		AffectedKeys:  counts[req.FromAlgorithm],
		Status:        "planned",
		TargetDate:    targetDate,
	})
	if err != nil {
		c.Error(http.StatusInternalServerError, "create_migration_plan_failed", err.Error())
		return
	}
	c.Target(created.ID)
	c.Detail("from_algorithm", created.FromAlgorithm)
	c.Detail("to_algorithm", created.ToAlgorithm)
	c.Detail("affected_keys", created.AffectedKeys)
	c.JSON(http.StatusCreated, map[string]interface{}{"data": withProgress(created, counts)})
}

func (h *Handler) updateMigrationPlan(c *route.Call) {
	var req struct {
		TenantID string `json:"tenant_id"` // enforced by the kernel
		Status   string `json:"status"`
	}
	if !c.Decode(&req) {
		return
	}
	if !migrationPlanStatuses[req.Status] {
		c.Error(http.StatusBadRequest, "bad_request", "status must be planned, in_progress, paused or completed")
		return
	}
	c.Detail("status", req.Status)
	updated, err := h.svc.store.UpdateMigrationPlan(c.R.Context(), c.Tenant, c.R.PathValue("id"), req.Status)
	if err == errStoreNotFound {
		c.Error(http.StatusNotFound, "not_found", "migration plan not found")
		return
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "update_migration_plan_failed", err.Error())
		return
	}
	counts, ok := h.liveKeyCounts(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": withProgress(updated, counts)})
}
