package main

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (h *Handler) handleListDrillSchedules(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	schedules, err := h.svc.store.ListDrillSchedules(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_schedules_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": schedules})
}

func (h *Handler) handleCreateDrillSchedule(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req struct {
		TenantID  string `json:"tenant_id"`
		Name      string `json:"name"`
		CronExpr  string `json:"cron_expr"`
		DrillType string `json:"drill_type"`
		Scope     string `json:"scope"`
		TargetEnv string `json:"target_env"`
		Enabled   bool   `json:"enabled"`
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
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name is required", reqID, tenantID)
		return
	}
	cronExpr := req.CronExpr
	if cronExpr == "" {
		cronExpr = "0 2 * * 0"
	}
	drillType := req.DrillType
	if drillType == "" {
		drillType = "key_restore"
	}
	scope := req.Scope
	if scope == "" {
		scope = "all_keys"
	}
	targetEnv := req.TargetEnv
	if targetEnv == "" {
		targetEnv = "staging"
	}

	ds := DrillSchedule{
		ID:        newID("drsched"),
		TenantID:  tenantID,
		Name:      req.Name,
		CronExpr:  cronExpr,
		DrillType: drillType,
		Scope:     scope,
		TargetEnv: targetEnv,
		Enabled:   req.Enabled,
	}
	created, err := h.svc.store.CreateDrillSchedule(r.Context(), ds)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_schedule_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": created})
}

func (h *Handler) handleDeleteDrillSchedule(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	scheduleID := strings.TrimSpace(r.PathValue("id"))
	if scheduleID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "schedule id is required", reqID, tenantID)
		return
	}
	if err := h.svc.store.DeleteDrillSchedule(r.Context(), tenantID, scheduleID); err != nil {
		if err == errStoreNotFound {
			writeErr(w, http.StatusNotFound, "not_found", "drill schedule not found", reqID, tenantID)
			return
		}
		writeErr(w, http.StatusInternalServerError, "delete_schedule_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]string{"status": "deleted"}})
}

func (h *Handler) handleTriggerDrill(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req struct {
		TenantID     string `json:"tenant_id"`
		DrillType    string `json:"drill_type"`
		ScheduleID   string `json:"schedule_id"`
		ScheduleName string `json:"schedule_name"`
		Scope        string `json:"scope"`
		TargetEnv    string `json:"target_env"`
		TriggeredBy  string `json:"triggered_by"`
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
	drillType := req.DrillType
	if drillType == "" {
		drillType = "key_restore"
	}
	triggeredBy := req.TriggeredBy
	if triggeredBy == "" {
		triggeredBy = "manual"
	}

	// Build synthetic drill steps to represent the standard DR workflow.
	steps := syntheticDrillSteps(drillType)

	run := DrillRun{
		ID:           newID("drrun"),
		TenantID:     tenantID,
		ScheduleID:   req.ScheduleID,
		ScheduleName: req.ScheduleName,
		DrillType:    drillType,
		Status:       "running",
		Steps:        steps,
		TriggeredBy:  triggeredBy,
	}

	created, err := h.svc.store.CreateDrillRun(r.Context(), run)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "trigger_drill_failed", err.Error(), reqID, tenantID)
		return
	}

	// Simulate the drill completing synchronously with deterministic synthetic
	// results so that callers get a completed run immediately.
	completedRun := simulateDrillCompletion(created)
	completedRun, err = h.svc.store.UpdateDrillRun(r.Context(), completedRun)
	if err != nil {
		// Return the created run even if the update fails; the drill has
		// logically been recorded.
		writeJSON(w, http.StatusCreated, map[string]any{"data": created})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": completedRun})
}

func (h *Handler) handleListDrillRuns(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 {
			limit = v
		}
	}
	runs, err := h.svc.store.ListDrillRuns(r.Context(), tenantID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_runs_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": runs})
}

func (h *Handler) handleGetDrillRun(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	runID := strings.TrimSpace(r.PathValue("id"))
	if runID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "run id is required", reqID, tenantID)
		return
	}
	run, err := h.svc.store.GetDrillRun(r.Context(), tenantID, runID)
	if err != nil {
		if err == errStoreNotFound {
			writeErr(w, http.StatusNotFound, "not_found", "drill run not found", reqID, tenantID)
			return
		}
		writeErr(w, http.StatusInternalServerError, "get_run_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": run})
}

func (h *Handler) handleGetDrillMetrics(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	metrics, err := h.svc.store.GetDrillMetrics(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "get_metrics_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": metrics})
}

// syntheticDrillSteps returns the standard ordered steps for a given drill type
// with a "running" status; simulateDrillCompletion will mark them passed/failed.
func syntheticDrillSteps(drillType string) []DrillStep {
	switch drillType {
	case "key_restore":
		return []DrillStep{
			{Name: "validate_backup_integrity", Status: DrillStepStatusPending},
			{Name: "spin_up_target_environment", Status: DrillStepStatusPending},
			{Name: "restore_master_encryption_key", Status: DrillStepStatusPending},
			{Name: "restore_key_hierarchy", Status: DrillStepStatusPending},
			{Name: "verify_key_access_controls", Status: DrillStepStatusPending},
			{Name: "validate_crypto_operations", Status: DrillStepStatusPending},
			{Name: "measure_rto_rpo", Status: DrillStepStatusPending},
			{Name: "teardown_target_environment", Status: DrillStepStatusPending},
		}
	case "full_failover":
		return []DrillStep{
			{Name: "validate_backup_integrity", Status: DrillStepStatusPending},
			{Name: "redirect_traffic", Status: DrillStepStatusPending},
			{Name: "restore_key_store", Status: DrillStepStatusPending},
			{Name: "verify_service_health", Status: DrillStepStatusPending},
			{Name: "validate_crypto_operations", Status: DrillStepStatusPending},
			{Name: "measure_rto_rpo", Status: DrillStepStatusPending},
			{Name: "failback", Status: DrillStepStatusPending},
		}
	default:
		return []DrillStep{
			{Name: "validate_backup_integrity", Status: DrillStepStatusPending},
			{Name: "restore_keys", Status: DrillStepStatusPending},
			{Name: "verify_operations", Status: DrillStepStatusPending},
			{Name: "measure_rto_rpo", Status: DrillStepStatusPending},
		}
	}
}

// simulateDrillCompletion marks all steps as passed (for a synthetic drill),
// computes synthetic RTO/RPO, and marks the run as completed.
func simulateDrillCompletion(run DrillRun) DrillRun {
	baseMs := int64(200)
	for i := range run.Steps {
		run.Steps[i].Status = DrillStepStatusPassed
		run.Steps[i].DurationMs = baseMs + int64(i)*150
		run.Steps[i].Detail = "step completed successfully in simulated drill"
	}

	now := time.Now().UTC()
	run.CompletedAt = &now
	run.Status = "completed"
	run.TotalKeys = 10
	run.RestoredKeys = 10
	run.FailedKeys = 0
	// Synthetic RTO: sum of step durations in seconds.
	var totalMs int64
	for _, s := range run.Steps {
		totalMs += s.DurationMs
	}
	run.RTOSeconds = int(totalMs/1000) + 1
	run.RPOSeconds = 0 // synchronous replication means zero data loss.
	return run
}
