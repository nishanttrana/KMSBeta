package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type Handler struct {
	svc *Service
	mux *http.ServeMux
}

func NewHandler(svc *Service) *Handler {
	h := &Handler{svc: svc}
	h.mux = h.routes()
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /governance/settings", h.handleGetSettings)
	mux.HandleFunc("PUT /governance/settings", h.handleUpdateSettings)
	mux.HandleFunc("POST /governance/settings/smtp/test", h.handleTestSMTP)
	mux.HandleFunc("POST /governance/settings/webhook/test", h.handleTestWebhook)
	mux.HandleFunc("GET /governance/backups", h.handleListBackups)
	mux.HandleFunc("POST /governance/backups", h.handleCreateBackup)
	mux.HandleFunc("POST /governance/backups/restore", h.handleRestoreBackup)
	mux.HandleFunc("GET /governance/backups/{id}", h.handleGetBackup)
	mux.HandleFunc("GET /governance/backups/{id}/artifact", h.handleDownloadBackupArtifact)
	mux.HandleFunc("GET /governance/backups/{id}/key", h.handleDownloadBackupKey)
	mux.HandleFunc("GET /governance/system/state", h.handleGetSystemState)
	mux.HandleFunc("PUT /governance/system/state", h.handleUpdateSystemState)
	mux.HandleFunc("GET /governance/system/integrity", h.handleSystemIntegrity)

	mux.HandleFunc("GET /governance/policies", h.handleListPolicies)
	mux.HandleFunc("POST /governance/policies", h.handleCreatePolicy)
	mux.HandleFunc("PUT /governance/policies/{id}", h.handleUpdatePolicy)
	mux.HandleFunc("DELETE /governance/policies/{id}", h.handleDeletePolicy)

	mux.HandleFunc("GET /governance/requests", h.handleListRequests)
	mux.HandleFunc("POST /governance/requests", h.handleCreateRequest)
	mux.HandleFunc("GET /governance/requests/{id}", h.handleGetRequest)
	mux.HandleFunc("POST /governance/requests/{id}/cancel", h.handleCancelRequest)
	mux.HandleFunc("GET /governance/requests/pending", h.handlePendingRequests)
	mux.HandleFunc("GET /governance/requests/pending/count", h.handlePendingCount)

	mux.HandleFunc("GET /governance/approve/{id}", h.handleApprovalPage)
	mux.HandleFunc("POST /governance/approve/{id}", h.handleApprovalVote)

	mux.HandleFunc("POST /governance/key-approval", h.handleCreateKeyApproval)
	mux.HandleFunc("GET /governance/key-approval/{id}/status", h.handleGetKeyApprovalStatus)
	return mux
}

func (h *Handler) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	settings, err := h.svc.GetSettings(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "settings_failed", err.Error(), reqID, tenantID)
		return
	}
	settings.SMTPPassword = ""
	writeJSON(w, http.StatusOK, map[string]interface{}{"settings": settings, "request_id": reqID})
}

func (h *Handler) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var settings GovernanceSettings
	if err := decodeJSON(r, &settings); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if settings.TenantID == "" {
		settings.TenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if settings.TenantID == "" {
		settings.TenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	updated, err := h.svc.UpdateSettings(r.Context(), settings)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "settings_update_failed", err.Error(), reqID, settings.TenantID)
		return
	}
	updated.SMTPPassword = ""
	writeJSON(w, http.StatusOK, map[string]interface{}{"settings": updated, "request_id": reqID})
}

func (h *Handler) handleTestSMTP(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body struct {
		TenantID string `json:"tenant_id"`
		To       string `json:"to"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if body.TenantID == "" {
		body.TenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if body.TenantID == "" {
		body.TenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if err := h.svc.TestSMTP(r.Context(), body.TenantID, body.To); err != nil {
		writeErr(w, http.StatusBadRequest, "smtp_test_failed", err.Error(), reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "smtp_ok", "request_id": reqID})
}

func (h *Handler) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body struct {
		TenantID   string `json:"tenant_id"`
		Channel    string `json:"channel"`
		WebhookURL string `json:"webhook_url"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if body.TenantID == "" {
		body.TenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if body.TenantID == "" {
		body.TenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if err := h.svc.TestWebhook(r.Context(), body.TenantID, body.Channel, body.WebhookURL); err != nil {
		writeErr(w, http.StatusBadRequest, "webhook_test_failed", err.Error(), reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "webhook_ok",
		"channel":    strings.ToLower(strings.TrimSpace(body.Channel)),
		"request_id": reqID,
	})
}

func (h *Handler) handleGetSystemState(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	state, err := h.svc.GetSystemState(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "system_state_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"state": state, "request_id": reqID})
}

func (h *Handler) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var in CreateBackupInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if strings.TrimSpace(in.TenantID) == "" {
		in.TenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if strings.TrimSpace(in.TenantID) == "" {
		in.TenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	job, err := h.svc.CreateBackup(r.Context(), in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "backup_create_failed", err.Error(), reqID, in.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"job":        job,
		"request_id": reqID,
	})
}

func (h *Handler) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var in RestoreBackupInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if strings.TrimSpace(in.TenantID) == "" {
		in.TenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if strings.TrimSpace(in.TenantID) == "" {
		in.TenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	out, err := h.svc.RestoreBackup(r.Context(), in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "backup_restore_failed", err.Error(), reqID, in.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"result":     out,
		"request_id": reqID,
	})
}

func (h *Handler) handleListBackups(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	scope := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scope")))
	status := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	limit := parseBackupLimit(r.URL.Query().Get("limit"), 50)
	items, err := h.svc.ListBackups(r.Context(), tenantID, scope, status, limit)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "backup_list_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items":      items,
		"request_id": reqID,
	})
}

func (h *Handler) handleGetBackup(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	item, err := h.svc.GetBackup(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "backup_read_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"job":        item,
		"request_id": reqID,
	})
}

func (h *Handler) handleDownloadBackupArtifact(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	content, err := h.svc.GetBackupArtifactDownload(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "backup_artifact_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"artifact":   content,
		"request_id": reqID,
	})
}

func (h *Handler) handleDownloadBackupKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	content, err := h.svc.GetBackupKeyDownload(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "backup_key_failed", err.Error(), reqID, tenantID)
		return
	}
	fileName := strings.TrimSpace(fmt.Sprintf("%v", content["file_name"]))
	if fileName == "" {
		fileName = fmt.Sprintf("vecta-backup-%s%s", strings.TrimSpace(r.PathValue("id")), backupKeyExtension)
	}
	raw, _ := json.Marshal(content["key_package"])
	content["content_base64"] = base64.StdEncoding.EncodeToString(raw)
	content["file_name"] = fileName
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"artifact":   content,
		"request_id": reqID,
	})
}

func (h *Handler) handleUpdateSystemState(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var state GovernanceSystemState
	if err := decodeJSON(r, &state); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if state.TenantID == "" {
		state.TenantID = strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	}
	if state.TenantID == "" {
		state.TenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	updated, err := h.svc.UpdateSystemState(r.Context(), state)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "system_state_update_failed", err.Error(), reqID, state.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"state": updated, "request_id": reqID})
}

func (h *Handler) handleSystemIntegrity(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	out, err := h.svc.SystemIntegrity(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "system_integrity_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"integrity": out, "request_id": reqID})
}

func (h *Handler) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var p ApprovalPolicy
	if err := decodeJSON(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, err := h.svc.CreatePolicy(r.Context(), p)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "create_failed", err.Error(), reqID, p.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"policy": out, "request_id": reqID})
}

func (h *Handler) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var p ApprovalPolicy
	if err := decodeJSON(r, &p); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	p.ID = r.PathValue("id")
	out, err := h.svc.UpdatePolicy(r.Context(), p)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "update_failed", err.Error(), reqID, p.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": out, "request_id": reqID})
}

func (h *Handler) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	if err := h.svc.DeletePolicy(r.Context(), tenantID, r.PathValue("id")); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "delete_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "deleted", "request_id": reqID})
}

func (h *Handler) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListPolicies(r.Context(), tenantID, r.URL.Query().Get("scope"), r.URL.Query().Get("status"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleListRequests(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListApprovalRequests(r.Context(), tenantID, r.URL.Query().Get("status"), r.URL.Query().Get("target_type"), r.URL.Query().Get("target_id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetRequest(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	out, err := h.svc.GetApprovalRequest(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "read_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"request": out.Request, "votes": out.Votes, "request_id": reqID})
}

func (h *Handler) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var in CreateApprovalRequestInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, err := h.svc.CreateApprovalRequest(r.Context(), in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "approval_request_failed", err.Error(), reqID, in.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"request": out, "request_id": reqID})
}

func (h *Handler) handleCancelRequest(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	var body struct {
		RequesterID string `json:"requester_id"`
	}
	_ = decodeJSON(r, &body)
	if strings.TrimSpace(body.RequesterID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "requester_id is required", reqID, tenantID)
		return
	}
	if err := h.svc.CancelApprovalRequest(r.Context(), tenantID, r.PathValue("id"), body.RequesterID); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "cancel_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "cancelled", "request_id": reqID})
}

func (h *Handler) handlePendingRequests(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	email := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("approver_email")))
	if email == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "approver_email query parameter is required", reqID, tenantID)
		return
	}
	items, err := h.svc.ListPendingByApprover(r.Context(), tenantID, email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "pending_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handlePendingCount(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	email := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("approver_email")))
	if email == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "approver_email query parameter is required", reqID, tenantID)
		return
	}
	count, err := h.svc.CountPendingByApprover(r.Context(), tenantID, email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "pending_count_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"count": count, "request_id": reqID})
}

func (h *Handler) handleApprovalPage(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	html, err := h.svc.ApprovalPageHTML(r.Context(), tenantID, r.PathValue("id"), token)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "approval_page_failed", err.Error(), reqID, tenantID)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

func (h *Handler) handleApprovalVote(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	input := VoteInput{
		RequestID: r.PathValue("id"),
		TenantID:  tenantID,
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		if err := decodeJSON(r, &input); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
		if input.RequestID == "" {
			input.RequestID = r.PathValue("id")
		}
	} else {
		_ = r.ParseForm()
		input.TenantID = firstNonEmpty(input.TenantID, strings.TrimSpace(r.FormValue("tenant_id")))
		input.Token = strings.TrimSpace(r.FormValue("token"))
		input.Vote = strings.TrimSpace(strings.ToLower(r.FormValue("vote")))
		input.Comment = strings.TrimSpace(r.FormValue("comment"))
		input.VoteMethod = "email_link"
	}
	if input.TenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required", reqID, "")
		return
	}
	out, err := h.svc.Vote(r.Context(), input)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "vote_failed", err.Error(), reqID, input.TenantID)
		return
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body><h3>Vote recorded</h3><p>Status: " + htmlEscape(out.Status) + "</p></body></html>"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"request": out, "request_id": reqID})
}

func (h *Handler) handleCreateKeyApproval(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var in CreateKeyApprovalInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, err := h.svc.CreateKeyApproval(r.Context(), in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "key_approval_failed", err.Error(), reqID, in.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"request": out, "request_id": reqID})
}

func (h *Handler) handleGetKeyApprovalStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	status, err := h.svc.GetKeyApprovalStatus(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "status_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": status, "request_id": reqID})
}

func mustTenant(r *http.Request, w http.ResponseWriter, reqID string) string {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return ""
	}
	return tenantID
}

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id != "" {
		return id
	}
	return newID("req")
}

func atoi(v string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}

func writeJSON(w http.ResponseWriter, code int, payload map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, code int, errCode string, msg string, requestID string, tenantID string) {
	writeJSON(w, code, map[string]interface{}{
		"error": map[string]interface{}{
			"code":       errCode,
			"message":    msg,
			"request_id": requestID,
			"tenant_id":  tenantID,
		},
	})
}
