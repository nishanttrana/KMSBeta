package main

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ─── Scheduling Jobs ──────────────────────────────────────────────────────────

func (h *Handler) handleListSchedulingJobs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	jobs, err := h.svc.store.ListSchedulingJobs(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_jobs_failed", err.Error(), reqID, tenantID)
		return
	}
	if jobs == nil {
		jobs = []KeySchedulingJob{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": jobs, "request_id": reqID})
}

func (h *Handler) handleCreateSchedulingJob(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		Name         string    `json:"name"`
		JobType      string    `json:"job_type"`
		CronExpr     string    `json:"cron_expr"`
		TargetFilter string    `json:"target_filter"`
		Payload      KeyLabels `json:"payload"`
		Enabled      *bool     `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name is required", reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.JobType) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "job_type is required", reqID, tenantID)
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	job := KeySchedulingJob{
		ID:           newID("sj"),
		TenantID:     tenantID,
		Name:         strings.TrimSpace(req.Name),
		JobType:      req.JobType,
		CronExpr:     req.CronExpr,
		TargetFilter: req.TargetFilter,
		Payload:      req.Payload,
		Status:       "pending",
		Enabled:      enabled,
		CreatedBy:    accessActorFromContext(r.Context()).UserID,
	}
	created, err := h.svc.store.CreateSchedulingJob(r.Context(), job)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_job_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"job": created, "request_id": reqID})
}

func (h *Handler) handleUpdateSchedulingJob(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	id := r.PathValue("id")
	var req struct {
		Name         string    `json:"name"`
		JobType      string    `json:"job_type"`
		CronExpr     string    `json:"cron_expr"`
		TargetFilter string    `json:"target_filter"`
		Payload      KeyLabels `json:"payload"`
		Enabled      *bool     `json:"enabled"`
		NextRunAt    *string   `json:"next_run_at"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	jobs, _ := h.svc.store.ListSchedulingJobs(r.Context(), tenantID)
	var existing *KeySchedulingJob
	for i := range jobs {
		if jobs[i].ID == id {
			existing = &jobs[i]
			break
		}
	}
	if existing == nil {
		writeErr(w, http.StatusNotFound, "not_found", "scheduling job not found", reqID, tenantID)
		return
	}
	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.JobType != "" {
		existing.JobType = req.JobType
	}
	existing.CronExpr = req.CronExpr
	existing.TargetFilter = req.TargetFilter
	if req.Payload != nil {
		existing.Payload = req.Payload
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.NextRunAt != nil {
		t, err := time.Parse(time.RFC3339, *req.NextRunAt)
		if err == nil {
			existing.NextRunAt = &t
		}
	}
	updated, err := h.svc.store.UpdateSchedulingJob(r.Context(), tenantID, id, *existing)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "update_job_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"job": updated, "request_id": reqID})
}

func (h *Handler) handleDeleteSchedulingJob(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	id := r.PathValue("id")
	if err := h.svc.store.DeleteSchedulingJob(r.Context(), tenantID, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete_job_failed", err.Error(), reqID, tenantID)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── Key Material Verification (enhanced) ─────────────────────────────────────

func (h *Handler) handleVerifyKeyMaterial(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := requireAuthedTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	res, err := h.svc.VerifyKeyIntegrity(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "key not found", reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": res, "request_id": reqID})
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func advParseInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

func advHashContext(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func advPercentile95(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	idx := int(math.Ceil(0.95*float64(len(values)))) - 1
	if idx >= len(values) {
		idx = len(values) - 1
	}
	return values[idx]
}

func coalesceStrSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Store interface additions required by handler_advanced.go
// These are implemented in store_advanced.go.
var _ = (*SQLStore)(nil)
var _ = advParseInt
var _ = advPercentile95
