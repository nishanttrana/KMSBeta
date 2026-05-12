package main

import (
	"net/http"
	"strings"

	"vecta-kms/pkg/tenantcheck"
)

// handleLintPolicy returns lint findings for a candidate policy YAML.
// Stateless — useful for IDE/dashboard integration that wants to validate
// before persisting.
//
// POST /policies/lint
func (h *Handler) handleLintPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req struct {
		TenantID string `json:"tenant_id"`
		YAML     string `json:"yaml"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid request body", reqID, "")
		return
	}
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	if err := tenantcheck.Enforce(r, tenantID); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "tenant_id does not match authenticated token", reqID, tenantID)
		return
	}
	doc, _, err := parsePolicyYAML(req.YAML)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"parse_error": err.Error(),
			"findings":    []LintFinding{},
			"request_id":  reqID,
		})
		return
	}
	findings := LintPolicy(doc)
	writeJSON(w, http.StatusOK, map[string]any{
		"findings":   findings,
		"request_id": reqID,
	})
}

// handleDryRunPolicy simulates a candidate policy against the last
// `window_hours` of evaluation records and reports the deltas.
//
// POST /policies/dry-run
func (h *Handler) handleDryRunPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req DryRunRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid request body", reqID, "")
		return
	}
	tenantID := strings.TrimSpace(req.TenantID)
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	if err := tenantcheck.Enforce(r, tenantID); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "tenant_id does not match authenticated token", reqID, tenantID)
		return
	}
	req.TenantID = tenantID
	src, ok := h.svc.store.(DryRunSource)
	if !ok {
		writeErr(w, http.StatusServiceUnavailable, "dryrun_unavailable", "store does not support dry-run", reqID, tenantID)
		return
	}
	report, err := DryRun(r.Context(), src, req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "dryrun_failed", sanitizeMessage(err), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"report":     report,
		"request_id": reqID,
	})
}
