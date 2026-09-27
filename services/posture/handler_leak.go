package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/route"
)

var (
	leakTargetTypes     = map[string]bool{"git_repo": true, "container_image": true, "log_stream": true, "s3_bucket": true, "env_file": true}
	leakFindingStatuses = map[string]bool{"open": true, "acknowledged": true, "resolved": true, "false_positive": true}
)

// postureEmitter sends kernel events through posture's audit client,
// resolved per call so it can be wired after the routes are built.
type postureEmitter struct{ h *Handler }

func (e postureEmitter) Emit(ctx context.Context, action string, evt pkgaudit.Event) error {
	if e.h.audit == nil {
		return nil
	}
	return e.h.audit.Emit(ctx, action, evt)
}

// SetAuditClient wires the unified audit client used by kernel routes and
// by scan completion events.
func (h *Handler) SetAuditClient(c *pkgaudit.Client) {
	if c != nil {
		h.audit = c
	}
}

// leakRoutes registers the leak scanner routes.
func (h *Handler) leakRoutes(r *route.Router) {
	r.Handle("GET /leaks/targets", route.Spec{Action: "leak_targets_listed", Permission: "posture.leak.read", Resource: "leak_target"}, h.listLeakTargets)
	r.Handle("POST /leaks/targets", route.Spec{Action: "leak_target_created", Permission: "posture.leak.write", Resource: "leak_target"}, h.createLeakTarget)
	r.Handle("DELETE /leaks/targets/{id}", route.Spec{Action: "leak_target_deleted", Permission: "posture.leak.write", Resource: "leak_target", TargetParam: "id", Severity: "warning"}, h.deleteLeakTarget)
	r.Handle("POST /leaks/targets/{id}/scan", route.Spec{Action: "leak_scan_started", Permission: "posture.leak.write", Resource: "leak_target", TargetParam: "id"}, h.triggerLeakScan)
	r.Handle("GET /leaks/jobs", route.Spec{Action: "leak_jobs_listed", Permission: "posture.leak.read", Resource: "leak_scan"}, h.listLeakJobs)
	r.Handle("GET /leaks/findings", route.Spec{Action: "leak_findings_listed", Permission: "posture.leak.read", Resource: "leak_finding"}, h.listLeakFindings)
	r.Handle("PATCH /leaks/findings/{id}", route.Spec{Action: "leak_finding_updated", Permission: "posture.leak.write", Resource: "leak_finding", TargetParam: "id"}, h.updateLeakFinding)
}

func (h *Handler) listLeakTargets(c *route.Call) {
	items, err := h.svc.store.ListLeakTargets(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) createLeakTarget(c *route.Call) {
	var req CreateLeakTargetRequest
	if !c.Decode(&req) {
		return
	}
	t := LeakScanTarget{
		TenantID: c.Tenant, Name: strings.TrimSpace(req.Name), Type: strings.TrimSpace(req.Type),
		URI: strings.TrimSpace(req.URI), Enabled: req.Enabled == nil || *req.Enabled,
	}
	switch {
	case t.Name == "":
		c.Error(http.StatusBadRequest, "validation_error", "name is required")
		return
	case !leakTargetTypes[t.Type]:
		c.Error(http.StatusBadRequest, "validation_error", "type must be git_repo, container_image, log_stream, s3_bucket or env_file")
		return
	case t.URI == "":
		c.Error(http.StatusBadRequest, "validation_error", "uri is required")
		return
	}
	created, err := h.svc.store.CreateLeakTarget(c.R.Context(), t)
	if err != nil {
		c.Error(http.StatusInternalServerError, "create_failed", err.Error())
		return
	}
	c.Target(created.ID)
	c.Detail("type", created.Type)
	c.Detail("uri", created.URI)
	c.JSON(http.StatusCreated, map[string]interface{}{"target": created})
}

func (h *Handler) deleteLeakTarget(c *route.Call) {
	err := h.svc.store.DeleteLeakTarget(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "target not found")
		return
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"deleted": true, "id": c.R.PathValue("id")})
}

// triggerLeakScan queues a real scan: inline content from the body, or the
// target's files under LEAK_SCAN_ROOT. Completion is audited separately
// (audit.posture.leak_scan_completed).
func (h *Handler) triggerLeakScan(c *route.Call) {
	var body struct {
		TenantID string `json:"tenant_id"` // enforced by the kernel
		Content  string `json:"content"`
		Filename string `json:"filename"`
	}
	if c.R.ContentLength != 0 && !c.Decode(&body) {
		return
	}
	target, err := h.svc.store.GetLeakTarget(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "target not found")
		return
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "store_error", err.Error())
		return
	}
	if !target.Enabled {
		c.Refuse(http.StatusConflict, "target_disabled", "target is disabled")
		return
	}
	created, err := h.svc.store.CreateLeakScanJob(c.R.Context(), LeakScanJob{
		TenantID: c.Tenant, TargetID: target.ID, TargetName: target.Name, TargetType: target.Type, Status: "queued",
	})
	if err != nil {
		c.Error(http.StatusInternalServerError, "create_failed", err.Error())
		return
	}
	c.Detail("job_id", created.ID)
	c.Detail("inline_content", body.Content != "")
	go h.runScan(context.WithoutCancel(c.R.Context()), c.Tenant, target, created, body.Content, body.Filename, c.Actor())
	c.JSON(http.StatusAccepted, map[string]interface{}{"job": created})
}

// runScan performs the scan: it gathers content from the target (inline
// submission or files under LEAK_SCAN_ROOT), runs the detectors over each
// item and persists concrete findings. With no content source it fails the
// job with the reason rather than inventing results. The outcome is audited.
func (h *Handler) runScan(ctx context.Context, tenantID string, target LeakScanTarget, job LeakScanJob, inlineContent, inlineName, actor string) {
	startedAt := nowUTC()
	_ = h.svc.store.UpdateLeakScanJob(ctx, tenantID, job.ID, "running", 10, 0, &startedAt, nil, "")
	finish := func(status string, findings int, errMsg string) {
		done := nowUTC()
		h.emitScanCompleted(ctx, tenantID, target, job, actor, status, findings, errMsg, done.Sub(startedAt))
		if status == "completed" {
			_ = h.svc.store.IncrementTargetScanCount(ctx, tenantID, target.ID, findings)
		}
		_ = h.svc.store.UpdateLeakScanJob(ctx, tenantID, job.ID, status, 100, findings, &startedAt, &done, errMsg)
	}

	items, err := gatherScanContent(target, inlineContent, inlineName)
	if err != nil {
		finish("failed", 0, err.Error())
		return
	}
	if len(items) == 0 {
		finish("completed", 0, "no content found to scan")
		return
	}
	_ = h.svc.store.UpdateLeakScanJob(ctx, tenantID, job.ID, "running", 50, 0, &startedAt, nil, "")

	findingsCount := 0
	for _, item := range items {
		for _, sec := range scanContent(item.path, item.data) {
			f := LeakFinding{
				TenantID:          tenantID,
				JobID:             job.ID,
				TargetID:          target.ID,
				TargetName:        target.Name,
				Severity:          sec.Severity,
				Type:              sec.FindingType,
				Description:       sec.Description,
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
	finish("completed", findingsCount, "")
}

// emitScanCompleted audits a scan's outcome; findings raise the severity.
func (h *Handler) emitScanCompleted(ctx context.Context, tenantID string, target LeakScanTarget, job LeakScanJob, actor, status string, findings int, errMsg string, took time.Duration) {
	if h.audit == nil {
		return
	}
	result, severity := "success", "info"
	switch {
	case status == "failed":
		result, severity = "failure", "warning"
	case findings > 0:
		severity = "warning"
	}
	_ = h.audit.Emit(ctx, "leak_scan_completed", pkgaudit.Event{
		TenantID: tenantID, ActorID: actor, ActorType: "user", TargetType: "leak_target", TargetID: target.ID,
		Result: result, ErrorMessage: errMsg, DurationMS: float64(took.Milliseconds()),
		Details: map[string]interface{}{
			"severity": severity, "job_id": job.ID, "target_type": target.Type,
			"status": status, "findings": findings,
		},
	})
}

func (h *Handler) listLeakJobs(c *route.Call) {
	q := c.R.URL.Query()
	items, err := h.svc.store.ListLeakScanJobs(c.R.Context(), c.Tenant, strings.TrimSpace(q.Get("target_id")), atoi(q.Get("limit"), 100, 1, 500))
	if err != nil {
		c.Error(http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) listLeakFindings(c *route.Call) {
	q := c.R.URL.Query()
	items, err := h.svc.store.ListLeakFindings(c.R.Context(), c.Tenant, strings.TrimSpace(q.Get("status")), strings.TrimSpace(q.Get("severity")), atoi(q.Get("limit"), 200, 1, 1000))
	if err != nil {
		c.Error(http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

// updateLeakFinding changes a finding's status. resolved_by is the verified
// caller, never a value from the request.
func (h *Handler) updateLeakFinding(c *route.Call) {
	var req UpdateLeakFindingRequest
	if !c.Decode(&req) {
		return
	}
	status := strings.TrimSpace(req.Status)
	if !leakFindingStatuses[status] {
		c.Error(http.StatusBadRequest, "validation_error", "status must be open, acknowledged, resolved or false_positive")
		return
	}
	resolvedBy := ""
	if status == "resolved" || status == "false_positive" {
		resolvedBy = c.Actor()
	}
	c.Detail("status", status)
	err := h.svc.store.UpdateLeakFinding(c.R.Context(), c.Tenant, c.R.PathValue("id"), status, resolvedBy, strings.TrimSpace(req.Notes))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "finding not found")
		return
	}
	if err != nil {
		c.Error(http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"ok": true, "status": status, "resolved_by": resolvedBy})
}
