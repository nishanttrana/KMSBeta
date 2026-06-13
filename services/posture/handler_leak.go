package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
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

	// Optional inline content: scan submitted material directly (e.g. a CI
	// diff or a config blob) without needing filesystem access.
	var body struct {
		Content  string `json:"content"`
		Filename string `json:"filename"`
	}
	if r.Body != nil {
		_ = decodeJSON(r, &body)
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

	// Run the real scan asynchronously. Detach from the request context so it
	// survives the response, but copy the content in first.
	go h.runScan(context.Background(), tenantID, target, created, body.Content, body.Filename)

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"job":        created,
		"request_id": reqID,
	})
}

// runScan performs a real secret scan: it gathers content from the target
// (inline submission or files under the configured scan root), runs the
// detection engine over each item, and persists concrete findings. If no
// content source is available for the target it fails the job with an honest
// error rather than inventing results.
func (h *Handler) runScan(ctx context.Context, tenantID string, target LeakScanTarget, job LeakScanJob, inlineContent, inlineName string) {
	startedAt := nowUTC()
	_ = h.svc.store.UpdateLeakScanJob(ctx, tenantID, job.ID, "running", 10, 0, &startedAt, nil, "")

	items, err := gatherScanContent(target, inlineContent, inlineName)
	if err != nil {
		failedAt := nowUTC()
		_ = h.svc.store.UpdateLeakScanJob(ctx, tenantID, job.ID, "failed", 100, 0, &startedAt, &failedAt, err.Error())
		return
	}
	if len(items) == 0 {
		completedAt := nowUTC()
		_ = h.svc.store.UpdateLeakScanJob(ctx, tenantID, job.ID, "completed", 100, 0, &startedAt, &completedAt, "no content found to scan")
		_ = h.svc.store.IncrementTargetScanCount(ctx, tenantID, target.ID, 0)
		return
	}

	_ = h.svc.store.UpdateLeakScanJob(ctx, tenantID, job.ID, "running", 50, 0, &startedAt, nil, "")

	findingsCount := 0
	for _, item := range items {
		for _, sec := range scanContent(item.path, item.data) {
			f := LeakFinding{
				TenantID:       tenantID,
				JobID:          job.ID,
				TargetID:       target.ID,
				TargetName:     target.Name,
				Severity:       sec.Severity,
				Type:           sec.FindingType,
				Description:    sec.Description,
				Location:          sec.Location,
				ContextPreview:    sec.ContextPreview,
				Entropy:           sec.Entropy,
				SecretFingerprint: sec.Fingerprint,
				Status:            "open",
				DetectedAt:        nowUTC(),
			}
			if _, err := h.svc.store.CreateLeakFinding(ctx, f); err == nil {
				findingsCount++
			}
		}
	}

	completedAt := nowUTC()
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
