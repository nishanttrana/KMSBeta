package main

import (
	"context"
	"errors"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func (h *Handler) handleListLeakTargets(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListLeakTargets(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"request_id": reqID,
	})
}

func (h *Handler) handleCreateLeakTarget(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req CreateLeakTargetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "validation_error", "name is required", reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.Type) == "" {
		writeErr(w, http.StatusBadRequest, "validation_error", "type is required", reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.URI) == "" {
		writeErr(w, http.StatusBadRequest, "validation_error", "uri is required", reqID, tenantID)
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	t := LeakScanTarget{
		TenantID: tenantID,
		Name:     strings.TrimSpace(req.Name),
		Type:     strings.TrimSpace(req.Type),
		URI:      strings.TrimSpace(req.URI),
		Enabled:  enabled,
	}
	created, err := h.svc.store.CreateLeakTarget(r.Context(), t)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"target":     created,
		"request_id": reqID,
	})
}

func (h *Handler) handleDeleteLeakTarget(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	id := r.PathValue("id")
	if err := h.svc.store.DeleteLeakTarget(r.Context(), tenantID, id); err != nil {
		if errors.Is(err, errNotFound) {
			writeErr(w, http.StatusNotFound, "not_found", "target not found", reqID, tenantID)
			return
		}
		writeErr(w, http.StatusInternalServerError, "delete_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"deleted":    true,
		"id":         id,
		"request_id": reqID,
	})
}

func (h *Handler) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	id := r.PathValue("id")
	target, err := h.svc.store.GetLeakTarget(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, errNotFound) {
			writeErr(w, http.StatusNotFound, "not_found", "target not found", reqID, tenantID)
			return
		}
		writeErr(w, http.StatusInternalServerError, "store_error", err.Error(), reqID, tenantID)
		return
	}

	job := LeakScanJob{
		TenantID:    tenantID,
		TargetID:    target.ID,
		TargetName:  target.Name,
		TargetType:  target.Type,
		Status:      "queued",
		ProgressPct: 0,
	}
	created, err := h.svc.store.CreateLeakScanJob(r.Context(), job)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_failed", err.Error(), reqID, tenantID)
		return
	}

	// Launch async simulated scan in a goroutine.
	go h.runSimulatedScan(context.Background(), tenantID, target, created)

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"job":        created,
		"request_id": reqID,
	})
}

// runSimulatedScan simulates a background scan by sleeping, generating findings,
// and updating the job status to completed.
func (h *Handler) runSimulatedScan(ctx context.Context, tenantID string, target LeakScanTarget, job LeakScanJob) {
	startedAt := nowUTC()
	_ = h.svc.store.UpdateLeakScanJob(ctx, tenantID, job.ID, "running", 10, 0, &startedAt, nil, "")

	// Simulate scanning duration: 2–5 seconds.
	sleepSec := 2 + rand.Intn(4) //nolint:gosec
	time.Sleep(time.Duration(sleepSec) * time.Second)

	_ = h.svc.store.UpdateLeakScanJob(ctx, tenantID, job.ID, "running", 60, 0, &startedAt, nil, "")

	// Generate synthetic findings based on target type.
	synthetics := syntheticFindingsForTargetType(target.Type)
	var created []LeakFinding
	for _, s := range synthetics {
		f := LeakFinding{
			TenantID:       tenantID,
			JobID:          job.ID,
			TargetID:       target.ID,
			TargetName:     target.Name,
			Severity:       s.severity,
			Type:           s.findingType,
			Description:    s.description,
			Location:       s.location,
			ContextPreview: s.contextPreview,
			Entropy:        s.entropy,
			Status:         "open",
			DetectedAt:     nowUTC(),
		}
		stored, err := h.svc.store.CreateLeakFinding(ctx, f)
		if err == nil {
			created = append(created, stored)
		}
	}

	completedAt := nowUTC()
	findingsCount := len(created)
	_ = h.svc.store.UpdateLeakScanJob(ctx, tenantID, job.ID, "completed", 100, findingsCount, &startedAt, &completedAt, "")
	_ = h.svc.store.IncrementTargetScanCount(ctx, tenantID, target.ID, findingsCount)
}

func (h *Handler) handleListLeakJobs(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	targetID := strings.TrimSpace(r.URL.Query().Get("target_id"))
	limit := atoi(r.URL.Query().Get("limit"), 100, 1, 500)
	items, err := h.svc.store.ListLeakScanJobs(r.Context(), tenantID, targetID, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"request_id": reqID,
	})
}

func (h *Handler) handleListLeakFindings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	severity := strings.TrimSpace(r.URL.Query().Get("severity"))
	limit := atoi(r.URL.Query().Get("limit"), 200, 1, 1000)
	items, err := h.svc.store.ListLeakFindings(r.Context(), tenantID, status, severity, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "query_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"request_id": reqID,
	})
}

func (h *Handler) handleUpdateLeakFinding(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	id := r.PathValue("id")
	var req UpdateLeakFindingRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	status := ""
	resolvedBy := ""
	notes := ""
	if req.Status != nil {
		status = *req.Status
	}
	if req.ResolvedBy != nil {
		resolvedBy = *req.ResolvedBy
	}
	if req.Notes != nil {
		notes = *req.Notes
	}
	if err := h.svc.store.UpdateLeakFinding(r.Context(), tenantID, id, status, resolvedBy, notes); err != nil {
		if errors.Is(err, errNotFound) {
			writeErr(w, http.StatusNotFound, "not_found", "finding not found", reqID, tenantID)
			return
		}
		writeErr(w, http.StatusInternalServerError, "update_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":         true,
		"request_id": reqID,
	})
}
