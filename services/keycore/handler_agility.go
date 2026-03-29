package main

import (
	"net/http"
	"strings"
	"time"
)

func (h *Handler) handleGetAgilityScore(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	algos, err := h.svc.store.GetAlgorithmDistribution(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "agility_score_failed", err.Error(), reqID, tenantID)
		return
	}
	score := computeAgilityScore(algos)
	writeJSON(w, http.StatusOK, map[string]any{"data": score})
}

func (h *Handler) handleGetAlgorithmInventory(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	algos, err := h.svc.store.GetAlgorithmDistribution(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "algorithm_inventory_failed", err.Error(), reqID, tenantID)
		return
	}
	// Annotate is_legacy / is_quantum_safe without computing a full score.
	var total int
	for _, a := range algos {
		total += a.KeyCount
	}
	for i := range algos {
		if total > 0 {
			algos[i].Percentage = float64(algos[i].KeyCount) / float64(total) * 100
		}
		algos[i].IsLegacy = legacyAlgorithms[algos[i].Algorithm]
		algos[i].IsQuantumSafe = quantumSafeAlgorithms[algos[i].Algorithm]
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": algos, "total_keys": total})
}

func (h *Handler) handleGetKeysByAlgorithm(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	algorithm := strings.TrimSpace(r.URL.Query().Get("algorithm"))
	if algorithm == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "algorithm query parameter is required", reqID, tenantID)
		return
	}
	keys, err := h.svc.store.ListKeysByAlgorithm(r.Context(), tenantID, algorithm)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "keys_by_algorithm_failed", err.Error(), reqID, tenantID)
		return
	}
	result := KeysByAlgorithm{Algorithm: algorithm, Keys: keys}
	writeJSON(w, http.StatusOK, map[string]any{"data": result})
}

func (h *Handler) handleListMigrationPlans(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	plans, err := h.svc.store.ListMigrationPlans(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_migration_plans_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": plans})
}

func (h *Handler) handleCreateMigrationPlan(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req struct {
		TenantID      string  `json:"tenant_id"`
		Name          string  `json:"name"`
		FromAlgorithm string  `json:"from_algorithm"`
		ToAlgorithm   string  `json:"to_algorithm"`
		AffectedKeys  int     `json:"affected_keys"`
		Status        string  `json:"status"`
		TargetDate    *string `json:"target_date"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = mustTenant(r, reqID, w)
		if tenantID == "" {
			return
		}
	}
	if req.Name == "" || req.FromAlgorithm == "" || req.ToAlgorithm == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name, from_algorithm, and to_algorithm are required", reqID, tenantID)
		return
	}
	status := req.Status
	if status == "" {
		status = "planned"
	}
	var targetDate *time.Time
	if req.TargetDate != nil && *req.TargetDate != "" {
		t, err := time.Parse(time.RFC3339, *req.TargetDate)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "target_date must be RFC3339", reqID, tenantID)
			return
		}
		targetDate = &t
	}
	mp := MigrationPlan{
		ID:            newID("migplan"),
		TenantID:      tenantID,
		Name:          req.Name,
		FromAlgorithm: req.FromAlgorithm,
		ToAlgorithm:   req.ToAlgorithm,
		AffectedKeys:  req.AffectedKeys,
		Status:        status,
		TargetDate:    targetDate,
	}
	created, err := h.svc.store.CreateMigrationPlan(r.Context(), mp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_migration_plan_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": created})
}

func (h *Handler) handleUpdateMigrationPlan(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	planID := strings.TrimSpace(r.PathValue("id"))
	if planID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "plan id is required", reqID, tenantID)
		return
	}
	var req struct {
		Status        string `json:"status"`
		CompletedKeys int    `json:"completed_keys"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if req.Status == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "status is required", reqID, tenantID)
		return
	}
	updated, err := h.svc.store.UpdateMigrationPlan(r.Context(), tenantID, planID, req.Status, req.CompletedKeys)
	if err != nil {
		if err == errStoreNotFound {
			writeErr(w, http.StatusNotFound, "not_found", "migration plan not found", reqID, tenantID)
			return
		}
		writeErr(w, http.StatusInternalServerError, "update_migration_plan_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": updated})
}
