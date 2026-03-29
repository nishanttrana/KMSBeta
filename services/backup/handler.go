package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// Handler is the HTTP handler for the backup service.
type Handler struct {
	svc *BackupService
	mux *http.ServeMux
}

// NewHandler creates a new Handler.
func NewHandler(svc *BackupService) *Handler {
	h := &Handler{svc: svc}
	h.mux = h.routes()
	return h
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.handleHealth)

	mux.HandleFunc("GET /backup/policies", h.handleListPolicies)
	mux.HandleFunc("POST /backup/policies", h.handleCreatePolicy)
	mux.HandleFunc("PATCH /backup/policies/{id}", h.handleUpdatePolicy)
	mux.HandleFunc("DELETE /backup/policies/{id}", h.handleDeletePolicy)
	mux.HandleFunc("POST /backup/policies/{id}/trigger", h.handleTriggerBackup)

	mux.HandleFunc("GET /backup/runs", h.handleListRuns)
	mux.HandleFunc("GET /backup/runs/{id}", h.handleGetRun)

	mux.HandleFunc("GET /backup/restore-points", h.handleListRestorePoints)
	mux.HandleFunc("POST /backup/restore-points/{id}/restore", h.handleRestore)

	mux.HandleFunc("GET /backup/metrics", h.handleGetMetrics)
	return mux
}

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok"})
}

func (h *Handler) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListPolicies(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_policies_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreatePolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if strings.TrimSpace(req.TenantID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name is required", reqID, req.TenantID)
		return
	}
	if strings.TrimSpace(req.CronExpr) == "" {
		req.CronExpr = "0 1 * * *"
	}
	if req.RetentionDays <= 0 {
		req.RetentionDays = 90
	}
	if strings.TrimSpace(req.Scope) == "" {
		req.Scope = "all_keys"
	}
	if strings.TrimSpace(req.Destination) == "" {
		req.Destination = "local"
	}

	p := BackupPolicy{
		ID:             newBackupID("bkp"),
		TenantID:       strings.TrimSpace(req.TenantID),
		Name:           strings.TrimSpace(req.Name),
		Description:    strings.TrimSpace(req.Description),
		Scope:          strings.TrimSpace(req.Scope),
		TagFilter:      strings.TrimSpace(req.TagFilter),
		CronExpr:       strings.TrimSpace(req.CronExpr),
		RetentionDays:  req.RetentionDays,
		EncryptBackup:  req.EncryptBackup,
		Compress:       req.Compress,
		Destination:    strings.TrimSpace(req.Destination),
		DestinationURI: strings.TrimSpace(req.DestinationURI),
		Enabled:        true,
		CreatedAt:      time.Now().UTC(),
	}

	saved, err := h.svc.store.CreatePolicy(r.Context(), p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_policy_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"policy": saved, "request_id": reqID})
}

func (h *Handler) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}
	var req UpdatePolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	updated, err := h.svc.store.UpdatePolicy(r.Context(), tenantID, id, req)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "update_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": updated, "request_id": reqID})
}

func (h *Handler) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}
	if err := h.svc.store.DeletePolicy(r.Context(), tenantID, id); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "delete_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "deleted", "request_id": reqID})
}

func (h *Handler) handleTriggerBackup(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}
	var req TriggerBackupRequest
	_ = decodeJSON(r, &req)
	triggeredBy := strings.TrimSpace(req.TriggeredBy)
	if triggeredBy == "" {
		triggeredBy = "manual"
	}

	policy, err := h.svc.store.GetPolicy(r.Context(), tenantID, id)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "get_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	if !policy.Enabled {
		writeErr(w, http.StatusBadRequest, "policy_disabled", "cannot trigger a disabled policy", reqID, tenantID)
		return
	}

	go h.svc.RunBackup(
		r.Context(),
		tenantID, policy.ID, policy.Name,
		policy.Scope, policy.Destination, triggeredBy,
	)

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":     "triggered",
		"policy_id":  policy.ID,
		"request_id": reqID,
	})
}

func (h *Handler) handleListRuns(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListRuns(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_runs_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetRun(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}
	run, err := h.svc.store.GetRun(r.Context(), tenantID, id)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "get_run_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"run": run, "request_id": reqID})
}

func (h *Handler) handleListRestorePoints(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListRestorePoints(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_restore_points_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleRestore(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "id is required", reqID, tenantID)
		return
	}
	if err := h.svc.RestoreFromPoint(r.Context(), tenantID, id); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			status = http.StatusNotFound
		}
		writeErr(w, status, "restore_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"status":     "restoring",
		"point_id":   id,
		"request_id": reqID,
	})
}

func (h *Handler) handleGetMetrics(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	m, err := h.svc.store.GetMetrics(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "get_metrics_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"metrics": m, "request_id": reqID})
}

// --- shared HTTP helpers ---

func requestID(r *http.Request) string {
	id := r.Header.Get("X-Request-ID")
	if strings.TrimSpace(id) == "" {
		id = newBackupID("req")
	}
	return id
}

func mustTenant(r *http.Request, w http.ResponseWriter, reqID string) string {
	tenantID := strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "missing_tenant", "X-Tenant-ID header or tenant_id query param required", reqID, "")
		return ""
	}
	return tenantID
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, code, message, requestID, tenantID string) {
	writeJSON(w, status, map[string]interface{}{
		"error":      code,
		"message":    message,
		"request_id": requestID,
		"tenant_id":  tenantID,
	})
}

func decodeJSON(r *http.Request, out interface{}) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err != nil {
		return err
	}
	return json.NewDecoder(bytes.NewReader(body)).Decode(out)
}
