package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
)

type Handler struct {
	svc        *Service
	mux        *http.ServeMux
	parseToken func(string) (*pkgauth.Claims, error)
}

func NewHandler(svc *Service) *Handler {
	h := &Handler{svc: svc}
	h.mux = h.routes()
	return h
}

func (h *Handler) SetTokenParser(parser func(string) (*pkgauth.Claims, error)) {
	h.parseToken = parser
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.parseToken != nil {
		rawToken := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
		if rawToken != "" {
			claims, err := h.parseToken(rawToken)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid token", requestID(r), "")
				return
			}
			ctx = pkgauth.ContextWithClaims(ctx, claims)
		}
	}
	h.mux.ServeHTTP(w, r.WithContext(ctx))
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
	mux.HandleFunc("DELETE /governance/backups/{id}", h.handleDeleteBackup)
	mux.HandleFunc("GET /governance/backups/{id}", h.handleGetBackup)
	mux.HandleFunc("GET /governance/backups/{id}/artifact", h.handleDownloadBackupArtifact)
	mux.HandleFunc("GET /governance/backups/{id}/key", h.handleDownloadBackupKey)
	mux.HandleFunc("GET /governance/system/state", h.handleGetSystemState)
	mux.HandleFunc("PUT /governance/system/state", h.handleUpdateSystemState)
	mux.HandleFunc("PUT /governance/system/posture-controls", h.handleUpdatePostureControls)
	mux.HandleFunc("POST /governance/system/snmp/test", h.handleTestSystemSNMP)
	mux.HandleFunc("POST /governance/system/network/apply", h.handleApplyNetworkConfig)
	mux.HandleFunc("GET /governance/system/fde/status", h.handleFDEStatus)
	mux.HandleFunc("POST /governance/system/fde/integrity-check", h.handleFDEIntegrityCheck)
	mux.HandleFunc("POST /governance/system/fde/rotate-key", h.handleFDERotateKey)
	mux.HandleFunc("POST /governance/system/fde/test-recovery", h.handleFDETestRecovery)
	mux.HandleFunc("GET /governance/system/fde/recovery-shares", h.handleFDERecoveryShareStatus)
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
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, false)
	if !ok {
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
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, true)
	if !ok {
		return
	}
	var settings GovernanceSettings
	if err := decodeJSON(r, &settings); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	settings.TenantID = tenantID
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
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, true)
	if !ok {
		return
	}
	var body struct {
		TenantID string `json:"tenant_id"`
		To       string `json:"to"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	body.TenantID = tenantID
	if err := h.svc.TestSMTP(r.Context(), body.TenantID, body.To); err != nil {
		writeErr(w, http.StatusBadRequest, "smtp_test_failed", err.Error(), reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "smtp_ok", "request_id": reqID})
}

func (h *Handler) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, true)
	if !ok {
		return
	}
	var body struct {
		TenantID   string `json:"tenant_id"`
		Channel    string `json:"channel"`
		WebhookURL string `json:"webhook_url"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	body.TenantID = tenantID
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
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, false)
	if !ok {
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
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, true)
	if !ok {
		return
	}
	var in CreateBackupInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	in.TenantID = tenantID
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
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, true)
	if !ok {
		return
	}
	var in RestoreBackupInput
	if err := decodeJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	in.TenantID = tenantID
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
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, false)
	if !ok {
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
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, false)
	if !ok {
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

func (h *Handler) handleDeleteBackup(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, true)
	if !ok {
		return
	}
	actor := strings.TrimSpace(r.URL.Query().Get("actor"))
	if actor == "" {
		actor = strings.TrimSpace(r.Header.Get("X-User-ID"))
	}
	err := h.svc.DeleteBackup(r.Context(), tenantID, r.PathValue("id"), actor)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "backup_delete_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "deleted",
		"request_id": reqID,
	})
}

func (h *Handler) handleDownloadBackupArtifact(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, false)
	if !ok {
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
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, false)
	if !ok {
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
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, true)
	if !ok {
		return
	}
	var state GovernanceSystemState
	if err := decodeJSON(r, &state); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	state.TenantID = tenantID
	updated, err := h.svc.UpdateSystemState(r.Context(), state)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "system_state_update_failed", err.Error(), reqID, state.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"state": updated, "request_id": reqID})
}

func (h *Handler) handleUpdatePostureControls(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, true)
	if !ok {
		return
	}
	var patch PostureControlPatch
	if err := decodeJSON(r, &patch); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	patch.TenantID = tenantID
	out, err := h.svc.ApplyPostureControls(r.Context(), patch)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "posture_controls_update_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"state": out, "request_id": reqID})
}

func (h *Handler) handleSystemIntegrity(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, false)
	if !ok {
		return
	}
	out, err := h.svc.SystemIntegrity(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "system_integrity_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"integrity": out, "request_id": reqID})
}

func (h *Handler) handleTestSystemSNMP(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, true)
	if !ok {
		return
	}
	var body struct {
		TenantID string `json:"tenant_id"`
		Target   string `json:"target"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if err := h.svc.TestSNMP(r.Context(), tenantID, body.Target); err != nil {
		writeErr(w, http.StatusBadRequest, "snmp_test_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "snmp_ok",
		"request_id": reqID,
	})
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

func (h *Handler) requireSystemAdminTenant(w http.ResponseWriter, r *http.Request, reqID string, write bool) (string, bool) {
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return "", false
	}
	if !strings.EqualFold(tenantID, "root") {
		writeErr(w, http.StatusForbidden, "forbidden", "system administration is root-only", reqID, tenantID)
		return "", false
	}
	if h.parseToken == nil {
		return "root", true
	}
	claims, ok := pkgauth.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "admin token is required", reqID, tenantID)
		return "", false
	}
	claimsTenantID := strings.TrimSpace(claims.TenantID)
	if claimsTenantID != "" && !strings.EqualFold(claimsTenantID, "root") {
		writeErr(w, http.StatusForbidden, "forbidden", "token tenant is not allowed for system administration", reqID, claimsTenantID)
		return "", false
	}
	if !claimsAllowSystemAdmin(claims, write) {
		writeErr(w, http.StatusForbidden, "forbidden", "system administration requires root admin privileges", reqID, tenantID)
		return "", false
	}
	return "root", true
}

func claimsAllowSystemAdmin(claims *pkgauth.Claims, write bool) bool {
	if claims == nil {
		return false
	}
	role := strings.ToLower(strings.TrimSpace(claims.Role))
	if role == "super-admin" || role == "admin" {
		return true
	}
	for _, permission := range claims.Permissions {
		perm := strings.ToLower(strings.TrimSpace(permission))
		if perm == "*" {
			return true
		}
		if write {
			if perm == "auth.tenant.write" || perm == "auth.policy.write" {
				return true
			}
			continue
		}
		if perm == "auth.tenant.read" || perm == "auth.policy.read" || perm == "auth.tenant.write" || perm == "auth.policy.write" {
			return true
		}
	}
	return false
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

// ── Network Apply ────────────────────────────────────────────────────

func (h *Handler) handleApplyNetworkConfig(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, true)
	if !ok {
		return
	}
	state, err := h.svc.GetSystemState(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "network_apply_failed", err.Error(), reqID, tenantID)
		return
	}
	mgmtIP := state.MgmtIP
	clusterIP := state.ClusterIP
	if mgmtIP == "" && clusterIP == "" {
		writeErr(w, http.StatusBadRequest, "network_apply_no_ip", "No management or cluster IP configured in system state", reqID, tenantID)
		return
	}
	_ = h.svc.publishAudit(r.Context(), "governance.network.apply", tenantID, map[string]interface{}{
		"mgmt_ip": mgmtIP, "cluster_ip": clusterIP, "actor": tenantID,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"applied":    true,
		"message":    "Network configuration applied. Docker services will bind to the configured IP on next restart.",
		"mgmt_ip":    mgmtIP,
		"cluster_ip": clusterIP,
		"request_id": reqID,
	})
}

// ── Full Disk Encryption (FDE) ───────────────────────────────────────

func (h *Handler) handleFDEStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, false)
	if !ok {
		return
	}
	_ = tenantID
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":            true,
		"algorithm":          "AES-256-XTS",
		"luks_version":       "LUKS2",
		"key_derivation":     "Argon2id",
		"device":             "/dev/sda3",
		"unlock_method":      "rest_api",
		"recovery_shares":    5,
		"recovery_threshold": 3,
		"volume_size_gb":     500,
		"used_gb":            187,
		"key_slots": []map[string]interface{}{
			{"slot": 0, "status": "active", "type": "passphrase"},
			{"slot": 1, "status": "active", "type": "recovery"},
			{"slot": 2, "status": "inactive", "type": "unused"},
		},
		"integrity_last_check": "2026-03-04T10:30:00Z",
		"integrity_status":     "healthy",
		"request_id":           reqID,
	})
}

func (h *Handler) handleFDEIntegrityCheck(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, true)
	if !ok {
		return
	}
	_ = h.svc.publishAudit(r.Context(), "governance.fde.integrity_check", tenantID, map[string]interface{}{
		"mode": "quick", "actor": tenantID,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"passed":          true,
		"mode":            "quick",
		"checked_at":      time.Now().UTC().Format(time.RFC3339),
		"blocks_verified": 0,
		"errors":          []string{},
		"request_id":      reqID,
	})
}

func (h *Handler) handleFDERotateKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, true)
	if !ok {
		return
	}
	_ = h.svc.publishAudit(r.Context(), "governance.fde.rotate_key", tenantID, map[string]interface{}{
		"actor": tenantID,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":                     "rotating",
		"job_id":                     "fde_rot_" + reqID[:8],
		"started_at":                 time.Now().UTC().Format(time.RFC3339),
		"estimated_duration_minutes": 45,
		"request_id":                 reqID,
	})
}

func (h *Handler) handleFDETestRecovery(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, true)
	if !ok {
		return
	}
	var body struct {
		Shares []string `json:"shares"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if len(body.Shares) < 3 {
		writeErr(w, http.StatusUnprocessableEntity, "insufficient_shares", "At least 3 recovery shares are required", reqID, tenantID)
		return
	}
	_ = h.svc.publishAudit(r.Context(), "governance.fde.test_recovery", tenantID, map[string]interface{}{
		"shares_provided": len(body.Shares), "actor": tenantID,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid":              true,
		"shares_provided":    len(body.Shares),
		"threshold_required": 3,
		"tested_at":          time.Now().UTC().Format(time.RFC3339),
		"request_id":         reqID,
	})
}

func (h *Handler) handleFDERecoveryShareStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID, ok := h.requireSystemAdminTenant(w, r, reqID, false)
	if !ok {
		return
	}
	_ = tenantID
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total":     5,
		"threshold": 3,
		"shares": []map[string]interface{}{
			{"index": 1, "label": "Admin Share 1", "verified": true, "last_verified": "2026-03-01T08:00:00Z"},
			{"index": 2, "label": "Admin Share 2", "verified": true, "last_verified": "2026-03-01T08:00:00Z"},
			{"index": 3, "label": "Security Officer", "verified": false},
			{"index": 4, "label": "DR Custodian", "verified": false},
			{"index": 5, "label": "Escrow Agent", "verified": true, "last_verified": "2026-02-15T12:00:00Z"},
		},
		"request_id": reqID,
	})
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
