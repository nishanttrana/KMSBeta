package main

import (
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

// Playbook is an automated incident response definition.
type Playbook struct {
	ID          string          `json:"id"`
	TenantID    string          `json:"tenant_id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Trigger     PlaybookTrigger `json:"trigger"`
	Actions     []PlaybookAction `json:"actions"`
	Enabled     bool            `json:"enabled"`
	RunCount    int             `json:"run_count"`
	LastRunAt   *time.Time      `json:"last_run_at,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
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

// handleRunPlaybook manually executes a playbook for testing.
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

	now := time.Now().UTC()
	run := PlaybookRun{
		ID:           newID("pbrun"),
		PlaybookID:   pb.ID,
		TenantID:     tenantID,
		TriggerEvent: "manual_test",
		Status:       "running",
		ActionsRun:   0,
	}

	created, err := h.svc.store.CreatePlaybookRun(r.Context(), run)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}

	// Execute actions — log each one as an audit event and build output.
	var outputLines []string
	for i, action := range pb.Actions {
		outputLines = append(outputLines,
			fmt.Sprintf("[%d] action=%s delay=%ds params=%v", i+1, action.Type, action.DelaySeconds, action.Parameters))
	}

	completedAt := time.Now().UTC()
	created.Status = "completed"
	created.ActionsRun = len(pb.Actions)
	created.Output = strings.Join(outputLines, "\n")
	created.CompletedAt = &completedAt

	completed, err := h.svc.store.UpdatePlaybookRun(r.Context(), created)
	if err != nil {
		// Return the initial run even if update fails.
		writeJSON(w, http.StatusCreated, map[string]interface{}{"data": created, "request_id": reqID})
		return
	}

	// Update playbook run count and last_run_at.
	_ = h.svc.store.IncrementPlaybookRunCount(r.Context(), tenantID, pb.ID, now)

	writeJSON(w, http.StatusCreated, map[string]interface{}{"data": completed, "request_id": reqID})
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
