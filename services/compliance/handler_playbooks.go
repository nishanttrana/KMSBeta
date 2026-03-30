package main

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// PlaybookTrigger defines the condition that fires a playbook.
type PlaybookTrigger struct {
	Type      string `json:"type"`
	Threshold int    `json:"threshold"`
	KeyID     string `json:"key_id,omitempty"`
}

// PlaybookAction defines a single response action within a playbook.
type PlaybookAction struct {
	Type         string            `json:"type"`
	Parameters   map[string]string `json:"parameters"`
	DelaySeconds int               `json:"delay_seconds"`
}

// Playbook is an automated KMS response definition.
type Playbook struct {
	ID          string           `json:"id"`
	TenantID    string           `json:"tenant_id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Category    string           `json:"category"`
	Trigger     PlaybookTrigger  `json:"trigger"`
	Actions     []PlaybookAction `json:"actions"`
	Enabled     bool             `json:"enabled"`
	RunCount    int              `json:"run_count"`
	LastRunAt   *time.Time       `json:"last_run_at,omitempty"`
	CreatedAt   time.Time        `json:"created_at"`
}

// ── Supported Playbook Categories ────────────────────────────────────────────
// incident_response, key_lifecycle, certificate_management, compliance,
// access_control, infrastructure, data_protection, operational

// ── Supported Trigger Types ──────────────────────────────────────────────────
//
// Incident Response (original):
//   canary_tripped, risk_score_critical
//
// Key Lifecycle:
//   key_created, key_rotated, key_expired, key_destroyed, key_compromised,
//   key_import_failed, rotation_overdue, key_expiry_imminent
//
// Certificate:
//   cert_expiring_30d, cert_expiring_7d, cert_expired, cert_revoked,
//   ca_rotation_due
//
// Compliance:
//   compliance_drop, compliance_score_drop, fips_violation_detected,
//   policy_violation, audit_gap_detected, framework_assessment_failed
//
// Access & Auth:
//   auth_failure_spike, unauthorized_key_access, privilege_escalation_attempt,
//   api_key_compromised, session_anomaly
//
// Infrastructure:
//   hsm_health_degraded, cluster_node_down, replication_lag_high,
//   backup_failed, storage_threshold_exceeded
//
// Data Protection:
//   encryption_failure, decryption_anomaly, data_leak_detected,
//   dlp_policy_triggered
//
// Operational:
//   rate_limit_exceeded, service_health_degraded, latency_spike,
//   error_rate_high

// validTriggerTypes enumerates all recognised trigger types.
var validTriggerTypes = map[string]bool{
	// Incident Response
	"canary_tripped":      true,
	"risk_score_critical": true,
	// Key Lifecycle
	"key_created":        true,
	"key_rotated":        true,
	"key_expired":        true,
	"key_destroyed":      true,
	"key_compromised":    true,
	"key_import_failed":  true,
	"rotation_overdue":   true,
	"key_expiry_imminent": true,
	// Certificate
	"cert_expiring_30d": true,
	"cert_expiring_7d":  true,
	"cert_expired":      true,
	"cert_revoked":      true,
	"ca_rotation_due":   true,
	// Compliance
	"compliance_drop":            true,
	"compliance_score_drop":      true,
	"fips_violation_detected":    true,
	"policy_violation":           true,
	"audit_gap_detected":         true,
	"framework_assessment_failed": true,
	// Access & Auth
	"auth_failure_spike":            true,
	"unauthorized_key_access":       true,
	"privilege_escalation_attempt":  true,
	"api_key_compromised":           true,
	"session_anomaly":               true,
	// Infrastructure
	"hsm_health_degraded":        true,
	"cluster_node_down":          true,
	"replication_lag_high":       true,
	"backup_failed":              true,
	"storage_threshold_exceeded": true,
	// Data Protection
	"encryption_failure":  true,
	"decryption_anomaly":  true,
	"data_leak_detected":  true,
	"dlp_policy_triggered": true,
	// Operational
	"rate_limit_exceeded":     true,
	"service_health_degraded": true,
	"latency_spike":           true,
	"error_rate_high":         true,
}

// ── Supported Action Types ───────────────────────────────────────────────────
//
// Notification:
//   send_email, send_slack, send_teams, send_webhook, send_pagerduty,
//   create_jira_ticket, create_servicenow_incident
//
// Key Operations:
//   rotate_key, suspend_key, revoke_key, destroy_key,
//   import_replacement_key, enable_key
//
// Certificate:
//   renew_certificate, revoke_certificate, issue_replacement_cert
//
// Access Control:
//   disable_user, revoke_api_key, enforce_mfa, quarantine_tenant,
//   block_ip_range
//
// Compliance:
//   trigger_assessment, generate_evidence_report, enable_fips_strict,
//   snapshot_posture
//
// Infrastructure:
//   failover_cluster, scale_service, flush_cache, restart_service
//
// Remediation:
//   run_custom_script, execute_webhook_action, update_policy, create_backup

// validActionTypes enumerates all recognised action types.
var validActionTypes = map[string]bool{
	// Notification
	"send_email":                true,
	"send_slack":                true,
	"send_teams":                true,
	"send_webhook":              true,
	"send_pagerduty":            true,
	"create_jira_ticket":        true,
	"create_servicenow_incident": true,
	// Legacy / aliases
	"send_alert":         true,
	"create_audit_event": true,
	"disable_access":     true,
	"notify_soc":         true,
	// Key Operations
	"rotate_key":             true,
	"suspend_key":            true,
	"revoke_key":             true,
	"destroy_key":            true,
	"import_replacement_key": true,
	"enable_key":             true,
	// Certificate
	"renew_certificate":      true,
	"revoke_certificate":     true,
	"issue_replacement_cert": true,
	// Access Control
	"disable_user":      true,
	"revoke_api_key":    true,
	"enforce_mfa":       true,
	"quarantine_tenant": true,
	"block_ip_range":    true,
	// Compliance
	"trigger_assessment":       true,
	"generate_evidence_report": true,
	"enable_fips_strict":       true,
	"snapshot_posture":         true,
	// Infrastructure
	"failover_cluster": true,
	"scale_service":    true,
	"flush_cache":      true,
	"restart_service":  true,
	// Remediation
	"run_custom_script":      true,
	"execute_webhook_action": true,
	"update_policy":          true,
	"create_backup":          true,
}

// PlaybookRun represents a single execution of a playbook.
type PlaybookRun struct {
	ID           string     `json:"id"`
	PlaybookID   string     `json:"playbook_id"`
	TenantID     string     `json:"tenant_id"`
	TriggerEvent string     `json:"trigger_event"`
	Status       string     `json:"status"`
	ActionsRun   int        `json:"actions_run"`
	Output       string     `json:"output"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
}

// handleListPlaybooks returns all playbooks for the tenant.
func (h *Handler) handleListPlaybooks(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	playbooks, err := h.svc.store.ListPlaybooks(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": playbooks, "request_id": reqID})
}

// handleCreatePlaybook creates a new playbook.
func (h *Handler) handleCreatePlaybook(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body Playbook
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	body.TenantID = firstNonEmpty(body.TenantID,
		strings.TrimSpace(r.Header.Get("X-Tenant-ID")),
		strings.TrimSpace(r.URL.Query().Get("tenant_id")))
	if body.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	if body.Name == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name is required", reqID, body.TenantID)
		return
	}
	if body.ID == "" {
		body.ID = newID("pb")
	}
	if body.Actions == nil {
		body.Actions = []PlaybookAction{}
	}
	if body.Trigger.Type == "" {
		body.Trigger.Type = "canary_tripped"
	}
	if !validTriggerTypes[body.Trigger.Type] {
		writeErr(w, http.StatusBadRequest, "bad_request",
			fmt.Sprintf("unsupported trigger type: %s", body.Trigger.Type), reqID, body.TenantID)
		return
	}
	for _, a := range body.Actions {
		if !validActionTypes[a.Type] {
			writeErr(w, http.StatusBadRequest, "bad_request",
				fmt.Sprintf("unsupported action type: %s", a.Type), reqID, body.TenantID)
			return
		}
	}
	if body.Category == "" {
		body.Category = "incident_response"
	}
	body.Enabled = true

	created, err := h.svc.store.CreatePlaybook(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": created, "request_id": reqID})
}

// handleGetPlaybook returns a single playbook.
func (h *Handler) handleGetPlaybook(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "playbook id is required", reqID, tenantID)
		return
	}
	pb, err := h.svc.store.GetPlaybook(r.Context(), tenantID, id)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": pb, "request_id": reqID})
}

// handleUpdatePlaybook updates an existing playbook.
func (h *Handler) handleUpdatePlaybook(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "playbook id is required", reqID, tenantID)
		return
	}
	var body Playbook
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	body.TenantID = tenantID
	body.ID = id
	if body.Actions == nil {
		body.Actions = []PlaybookAction{}
	}
	updated, err := h.svc.store.UpdatePlaybook(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": updated, "request_id": reqID})
}

// handleDeletePlaybook deletes a playbook.
func (h *Handler) handleDeletePlaybook(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "playbook id is required", reqID, tenantID)
		return
	}
	if err := h.svc.store.DeletePlaybook(r.Context(), tenantID, id); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": map[string]string{"status": "deleted"}, "request_id": reqID})
}

// handleRunPlaybook manually executes a playbook using the real execution engine.
// The execution runs asynchronously; the handler returns immediately with the run ID.
func (h *Handler) handleRunPlaybook(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "playbook id is required", reqID, tenantID)
		return
	}

	pb, err := h.svc.store.GetPlaybook(r.Context(), tenantID, id)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	if h.executor == nil {
		writeErr(w, http.StatusServiceUnavailable, "unavailable", "playbook executor not initialized", reqID, tenantID)
		return
	}

	// Create the run record synchronously so we can return the ID immediately
	run := PlaybookRun{
		ID:           newID("pbrun"),
		PlaybookID:   pb.ID,
		TenantID:     tenantID,
		TriggerEvent: "manual",
		Status:       "running",
		ActionsRun:   0,
	}
	created, err := h.svc.store.CreatePlaybookRun(r.Context(), run)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	// Execute asynchronously — the goroutine updates the run record on completion
	executor := h.executor
	pbCopy := pb
	runCopy := created
	go func() {
		execCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		runCtx := RunContext{
			PlaybookID:   pbCopy.ID,
			RunID:        runCopy.ID,
			TenantID:     tenantID,
			TriggerEvent: "manual",
		}

		var (
			outputLines []string
			actionsRun  int
			hadFailure  bool
		)
		for i, action := range pbCopy.Actions {
			// Respect DelaySeconds
			if action.DelaySeconds > 0 {
				select {
				case <-time.After(time.Duration(action.DelaySeconds) * time.Second):
				case <-execCtx.Done():
					runCopy.Status = "cancelled"
					runCopy.ActionsRun = actionsRun
					runCopy.Output = strings.Join(outputLines, "\n")
					now := time.Now().UTC()
					runCopy.CompletedAt = &now
					_, _ = executor.store.UpdatePlaybookRun(execCtx, runCopy)
					return
				}
			}

			start := time.Now()
			execErr := executor.executeAction(execCtx, action, runCtx)
			elapsed := time.Since(start)
			actionsRun++

			if execErr != nil {
				hadFailure = true
				outputLines = append(outputLines,
					fmt.Sprintf("[%d] action=%s status=FAILED error=%q elapsed=%s", i+1, action.Type, execErr.Error(), elapsed.Round(time.Millisecond)))
				if action.Parameters["stop_on_failure"] == "true" {
					outputLines = append(outputLines, fmt.Sprintf("[%d] stop_on_failure=true, halting", i+1))
					break
				}
			} else {
				outputLines = append(outputLines,
					fmt.Sprintf("[%d] action=%s status=OK elapsed=%s", i+1, action.Type, elapsed.Round(time.Millisecond)))
			}
		}

		now := time.Now().UTC()
		runCopy.ActionsRun = actionsRun
		runCopy.Output = strings.Join(outputLines, "\n")
		runCopy.CompletedAt = &now
		if hadFailure && actionsRun < len(pbCopy.Actions) {
			runCopy.Status = "failed"
		} else if hadFailure {
			runCopy.Status = "partial_failure"
		} else {
			runCopy.Status = "completed"
		}
		_, _ = executor.store.UpdatePlaybookRun(execCtx, runCopy)
		_ = executor.store.IncrementPlaybookRunCount(execCtx, tenantID, pbCopy.ID, now)
	}()

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"data": map[string]interface{}{
			"run_id":      created.ID,
			"playbook_id": pb.ID,
			"status":      "running",
			"message":     "playbook execution started asynchronously",
		},
		"request_id": reqID,
	})
}

// handleListPlaybookRuns lists the run history for a playbook.
func (h *Handler) handleListPlaybookRuns(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "playbook id is required", reqID, tenantID)
		return
	}
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 {
			limit = v
		}
	}
	runs, err := h.svc.store.ListPlaybookRuns(r.Context(), tenantID, id, limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": runs, "request_id": reqID})
}

// handleGetPlaybookSummary returns a summary of playbook activity.
func (h *Handler) handleGetPlaybookSummary(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	summary, err := h.svc.store.GetPlaybookSummary(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"data": summary, "request_id": reqID})
}
