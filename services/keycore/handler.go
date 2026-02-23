package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
)

type AuditPublisher interface {
	Publish(ctx context.Context, subject string, payload []byte) error
}

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
		raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
		if raw != "" {
			claims, err := h.parseToken(raw)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid token", requestID(r), "")
				return
			}
			ctx = pkgauth.ContextWithClaims(ctx, claims)
		}
	}
	ctx = contextWithAccessActor(ctx, accessActorFromHTTPRequest(r.WithContext(ctx)))
	h.mux.ServeHTTP(w, r.WithContext(ctx))
}

func (h *Handler) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /keys", h.handleCreateKey)
	mux.HandleFunc("POST /keys/import", h.handleImportKey)
	mux.HandleFunc("POST /keys/form", h.handleFormKey)
	mux.HandleFunc("POST /keys/bulk-import", h.handleBulkImport)
	mux.HandleFunc("GET /keys", h.handleListKeys)
	mux.HandleFunc("GET /keys/{id}", h.handleGetKey)
	mux.HandleFunc("PUT /keys/{id}", h.handleUpdateKey)
	mux.HandleFunc("POST /keys/{id}/rotate", h.handleRotateKey)
	mux.HandleFunc("POST /keys/{id}/activate", h.handleActivateKey)
	mux.HandleFunc("POST /keys/{id}/deactivate", h.handleDeactivateKey)
	mux.HandleFunc("POST /keys/{id}/disable", h.handleDisableKey)
	mux.HandleFunc("POST /keys/{id}/destroy", h.handleDestroyKey)
	mux.HandleFunc("POST /keys/{id}/export", h.handleExportKey)
	mux.HandleFunc("PUT /keys/{id}/export-policy", h.handleSetExportPolicy)
	mux.HandleFunc("GET /keys/{id}/versions", h.handleListVersions)
	mux.HandleFunc("GET /keys/{id}/versions/{ver}", h.handleGetVersion)
	mux.HandleFunc("POST /keys/{id}/versions/{ver}/activate", h.handleActivateVersion)
	mux.HandleFunc("POST /keys/{id}/versions/{ver}/deactivate", h.handleDeactivateVersion)
	mux.HandleFunc("DELETE /keys/{id}/versions/{ver}", h.handleDeleteVersion)
	mux.HandleFunc("GET /keys/{id}/kcv", h.handleGetKCV)

	mux.HandleFunc("GET /keys/{id}/usage", h.handleGetUsage)
	mux.HandleFunc("PUT /keys/{id}/usage/limit", h.handleSetUsageLimit)
	mux.HandleFunc("POST /keys/{id}/usage/reset", h.handleResetUsage)
	mux.HandleFunc("PUT /keys/{id}/approval", h.handleSetApproval)
	mux.HandleFunc("GET /keys/{id}/approval", h.handleGetApproval)
	mux.HandleFunc("GET /keys/{id}/access-policy", h.handleGetKeyAccessPolicy)
	mux.HandleFunc("PUT /keys/{id}/access-policy", h.handleSetKeyAccessPolicy)
	mux.HandleFunc("PUT /keys/{id}/iv-mode", h.handleSetIVMode)
	mux.HandleFunc("GET /keys/{id}/iv-log", h.handleGetIVLog)
	mux.HandleFunc("GET /keys/{id}/iv-log/{ref}", h.handleGetIVByRef)
	mux.HandleFunc("GET /access/groups", h.handleListAccessGroups)
	mux.HandleFunc("POST /access/groups", h.handleCreateAccessGroup)
	mux.HandleFunc("DELETE /access/groups/{id}", h.handleDeleteAccessGroup)
	mux.HandleFunc("PUT /access/groups/{id}/members", h.handleSetAccessGroupMembers)
	mux.HandleFunc("GET /tags", h.handleListTags)
	mux.HandleFunc("POST /tags", h.handleUpsertTag)
	mux.HandleFunc("DELETE /tags/{name}", h.handleDeleteTag)

	mux.HandleFunc("POST /keys/{id}/encrypt", h.handleEncrypt)
	mux.HandleFunc("POST /keys/{id}/decrypt", h.handleDecrypt)
	mux.HandleFunc("POST /keys/{id}/sign", h.handleSign)
	mux.HandleFunc("POST /keys/{id}/verify", h.handleVerify)
	mux.HandleFunc("POST /keys/{id}/wrap", h.handleWrap)
	mux.HandleFunc("POST /keys/{id}/unwrap", h.handleUnwrap)
	mux.HandleFunc("POST /keys/{id}/mac", h.handleMAC)
	mux.HandleFunc("POST /keys/{id}/derive", h.handleDerive)
	mux.HandleFunc("POST /keys/{id}/kem/encapsulate", h.handleKEMEncapsulate)
	mux.HandleFunc("POST /keys/{id}/kem/decapsulate", h.handleKEMDecapsulate)
	mux.HandleFunc("POST /crypto/hash", h.handleHash)
	mux.HandleFunc("POST /crypto/random", h.handleRandom)
	return mux
}

func (h *Handler) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req CreateKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	key, err := h.svc.CreateKey(r.Context(), req)
	if err != nil {
		var denied policyDeniedError
		if errors.As(err, &denied) {
			writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, req.TenantID)
			return
		}
		var fipsDenied fipsModeViolationError
		if errors.As(err, &fipsDenied) {
			writeErr(w, http.StatusForbidden, "fips_mode_violation", fipsDenied.Error(), reqID, req.TenantID)
			return
		}
		writeErr(w, http.StatusBadRequest, "create_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"key_id":     key.ID,
		"tenant_id":  key.TenantID,
		"kcv":        strings.ToUpper(hex.EncodeToString(key.KCV)),
		"request_id": reqID,
	})
}

func (h *Handler) handleImportKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ImportKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	key, err := h.svc.ImportKey(r.Context(), req)
	if err != nil {
		var denied policyDeniedError
		if errors.As(err, &denied) {
			writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, req.TenantID)
			return
		}
		var fipsDenied fipsModeViolationError
		if errors.As(err, &fipsDenied) {
			writeErr(w, http.StatusForbidden, "fips_mode_violation", fipsDenied.Error(), reqID, req.TenantID)
			return
		}
		writeErr(w, http.StatusBadRequest, "import_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"key_id":     key.ID,
		"tenant_id":  key.TenantID,
		"kcv":        strings.ToUpper(hex.EncodeToString(key.KCV)),
		"request_id": reqID,
	})
}

func (h *Handler) handleFormKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req FormKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	key, generatedComponents, err := h.svc.FormKey(r.Context(), req)
	if err != nil {
		var denied policyDeniedError
		if errors.As(err, &denied) {
			writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, req.TenantID)
			return
		}
		var fipsDenied fipsModeViolationError
		if errors.As(err, &fipsDenied) {
			writeErr(w, http.StatusForbidden, "fips_mode_violation", fipsDenied.Error(), reqID, req.TenantID)
			return
		}
		writeErr(w, http.StatusBadRequest, "form_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"key_id":               key.ID,
		"tenant_id":            key.TenantID,
		"kcv":                  strings.ToUpper(hex.EncodeToString(key.KCV)),
		"generated_components": generatedComponents,
		"request_id":           reqID,
	})
}

func (h *Handler) handleBulkImport(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req []ImportKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	type item struct {
		KeyID string `json:"key_id"`
		Error string `json:"error,omitempty"`
	}
	out := make([]item, 0, len(req))
	for _, in := range req {
		k, err := h.svc.ImportKey(r.Context(), in)
		if err != nil {
			out = append(out, item{Error: err.Error()})
			continue
		}
		out = append(out, item{KeyID: k.ID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "request_id": reqID})
}

func (h *Handler) handleListKeys(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id query parameter is required", reqID, "")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	keys, err := h.svc.ListKeys(r.Context(), tenantID, limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": renderKeys(keys), "request_id": reqID})
}

func (h *Handler) handleGetKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	k, err := h.svc.GetKey(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "get_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": renderKey(k), "request_id": reqID})
}

func (h *Handler) handleUpdateKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req UpdateKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if err := h.svc.UpdateKey(r.Context(), tenantID, r.PathValue("id"), req); err != nil {
		writeErr(w, http.StatusInternalServerError, "update_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		Reason           string `json:"reason"`
		OldVersionAction string `json:"old_version_action"`
	}
	_ = decodeJSON(r, &req)
	ver, err := h.svc.RotateKey(r.Context(), tenantID, r.PathValue("id"), req.Reason, req.OldVersionAction)
	if err != nil {
		var denied policyDeniedError
		if errors.As(err, &denied) {
			writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, tenantID)
			return
		}
		writeErr(w, http.StatusBadRequest, "rotate_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"version_id": ver.ID,
		"kcv":        strings.ToUpper(hex.EncodeToString(ver.KCV)),
		"request_id": reqID,
	})
}

func (h *Handler) handleActivateKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		Mode           string     `json:"mode"`
		ActivationDate *time.Time `json:"activation_date"`
	}
	if err := decodeJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	mode := strings.TrimSpace(req.Mode)
	if mode == "" {
		mode = "immediate"
	}
	key, err := h.svc.ConfigureKeyActivation(r.Context(), tenantID, r.PathValue("id"), mode, req.ActivationDate)
	if err != nil {
		var denied policyDeniedError
		if errors.As(err, &denied) {
			writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, tenantID)
			return
		}
		writeErr(w, http.StatusBadRequest, "activation_failed", err.Error(), reqID, tenantID)
		return
	}
	var activationAt any
	if key.ActivationDate != nil {
		activationAt = key.ActivationDate.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          key.Status,
		"activation_date": activationAt,
		"request_id":      reqID,
	})
}
func (h *Handler) handleDeactivateKey(w http.ResponseWriter, r *http.Request) {
	h.keyStatus(w, r, "deactivated")
}
func (h *Handler) handleDisableKey(w http.ResponseWriter, r *http.Request) {
	h.keyStatus(w, r, "disabled")
}
func (h *Handler) handleDestroyKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		Mode             string `json:"mode"`
		DestroyAfterDays int    `json:"destroy_after_days"`
		ConfirmName      string `json:"confirm_name"`
		Justification    string `json:"justification"`
		Checks           struct {
			NoActiveWorkloads bool `json:"no_active_workloads"`
			BackupCompleted   bool `json:"backup_completed"`
			IrreversibleAck   bool `json:"irreversible_ack"`
		} `json:"checks"`
	}
	if err := decodeJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "scheduled"
	}
	if mode != "scheduled" && mode != "immediate" {
		writeErr(w, http.StatusBadRequest, "bad_request", "mode must be scheduled or immediate", reqID, tenantID)
		return
	}
	if !req.Checks.NoActiveWorkloads || !req.Checks.BackupCompleted || !req.Checks.IrreversibleAck {
		writeErr(w, http.StatusBadRequest, "bad_request", "all pre-destroy checks must be acknowledged", reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.Justification) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "justification is required", reqID, tenantID)
		return
	}
	key, err := h.svc.GetKey(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", err.Error(), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.ConfirmName) == "" || strings.TrimSpace(req.ConfirmName) != key.Name {
		writeErr(w, http.StatusBadRequest, "bad_request", "confirm_name must match the exact key name", reqID, tenantID)
		return
	}
	switch mode {
	case "scheduled":
		destroyAt, err := h.svc.ScheduleKeyDestroy(r.Context(), tenantID, r.PathValue("id"), req.DestroyAfterDays, req.Justification)
		if err != nil {
			var denied policyDeniedError
			if errors.As(err, &denied) {
				writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, tenantID)
				return
			}
			writeErr(w, http.StatusBadRequest, "destroy_schedule_failed", err.Error(), reqID, tenantID)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":     "destroy-pending",
			"mode":       "scheduled",
			"destroy_at": destroyAt.UTC().Format(time.RFC3339),
			"request_id": reqID,
		})
	case "immediate":
		if err := h.svc.DestroyKeyImmediately(r.Context(), tenantID, r.PathValue("id"), req.Justification); err != nil {
			var denied policyDeniedError
			if errors.As(err, &denied) {
				writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, tenantID)
				return
			}
			writeErr(w, http.StatusBadRequest, "destroy_failed", err.Error(), reqID, tenantID)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":     "deleted",
			"mode":       "immediate",
			"request_id": reqID,
		})
	}
}

func (h *Handler) keyStatus(w http.ResponseWriter, r *http.Request, status string) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	if err := h.svc.SetKeyStatus(r.Context(), tenantID, r.PathValue("id"), status); err != nil {
		var denied policyDeniedError
		if errors.As(err, &denied) {
			writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, tenantID)
			return
		}
		if errors.Is(err, errStoreNotFound) {
			writeErr(w, http.StatusNotFound, "not_found", err.Error(), reqID, tenantID)
			return
		}
		writeErr(w, http.StatusBadRequest, "status_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": normalizeLifecycleStatus(status), "request_id": reqID})
}

func (h *Handler) handleExportKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		WrappingKeyID string `json:"wrapping_key_id"`
		ExportMode    string `json:"export_mode"`
	}
	if err := decodeJSON(r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.ExportMode))
	if mode == "" {
		mode = "wrapped"
	}
	if mode == "public-plaintext" {
		publicResult, err := h.svc.ExportPublicComponentPlaintext(r.Context(), tenantID, r.PathValue("id"))
		if err != nil {
			var denied policyDeniedError
			if errors.As(err, &denied) {
				writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, tenantID)
				return
			}
			writeErr(w, http.StatusBadRequest, "export_failed", err.Error(), reqID, tenantID)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"key_id":               publicResult.KeyID,
			"kcv":                  publicResult.KCV,
			"wrapped_material":     "",
			"material_iv":          "",
			"wrapped_dek":          "",
			"public_key_plaintext": publicResult.PublicKeyPlaintext,
			"plaintext_encoding":   publicResult.PublicKeyEncoding,
			"component_type":       publicResult.PublicComponentType,
			"export_format":        "public-plaintext",
			"envelope_material":    false,
			"request_id":           reqID,
		})
		return
	}
	result, err := h.svc.ExportCurrentVersionWrapped(r.Context(), tenantID, r.PathValue("id"), req.WrappingKeyID)
	if err != nil {
		var denied policyDeniedError
		if errors.As(err, &denied) {
			writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, tenantID)
			return
		}
		writeErr(w, http.StatusBadRequest, "export_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key_id":            result.KeyID,
		"wrapped_material":  result.WrappedKeyB64,
		"material_iv":       result.MaterialIVB64,
		"wrapped_dek":       "",
		"kcv":               result.KCV,
		"wrapping_key_id":   result.WrappingKeyID,
		"wrapping_key_kcv":  result.WrappingKeyKCV,
		"export_format":     "aes-gcm-wrapped-by-kek",
		"envelope_material": false,
		"request_id":        reqID,
	})
}

func (h *Handler) handleListVersions(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	versions, err := h.svc.ListVersions(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "versions_failed", err.Error(), reqID, tenantID)
		return
	}
	items := make([]map[string]any, 0, len(versions))
	for _, v := range versions {
		items = append(items, map[string]any{"id": v.ID, "version": v.Version, "status": v.Status, "kcv": strings.ToUpper(hex.EncodeToString(v.KCV)), "created_at": v.CreatedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetVersion(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	ver, _ := strconv.Atoi(r.PathValue("ver"))
	v, err := h.svc.GetVersion(r.Context(), tenantID, r.PathValue("id"), ver)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "version_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": map[string]any{"id": v.ID, "version": v.Version, "status": v.Status, "kcv": strings.ToUpper(hex.EncodeToString(v.KCV))}, "request_id": reqID})
}

func (h *Handler) handleActivateVersion(w http.ResponseWriter, r *http.Request) {
	h.versionStatus(w, r, "active")
}
func (h *Handler) handleDeactivateVersion(w http.ResponseWriter, r *http.Request) {
	h.versionStatus(w, r, "deactivated")
}

func (h *Handler) versionStatus(w http.ResponseWriter, r *http.Request, status string) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	ver, _ := strconv.Atoi(r.PathValue("ver"))
	if err := h.svc.store.UpdateVersionStatus(r.Context(), tenantID, r.PathValue("id"), ver, status); err != nil {
		writeErr(w, http.StatusInternalServerError, "version_status_failed", err.Error(), reqID, tenantID)
		return
	}
	_ = h.svc.publishAudit(r.Context(), "audit.key.version_"+status, tenantID, map[string]any{"key_id": r.PathValue("id"), "version": ver})
	writeJSON(w, http.StatusOK, map[string]any{"status": status, "request_id": reqID})
}

func (h *Handler) handleDeleteVersion(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	ver, _ := strconv.Atoi(r.PathValue("ver"))
	if err := h.svc.store.DeleteVersion(r.Context(), tenantID, r.PathValue("id"), ver); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete_failed", err.Error(), reqID, tenantID)
		return
	}
	_ = h.svc.publishAudit(r.Context(), "audit.key.version_deleted", tenantID, map[string]any{"key_id": r.PathValue("id"), "version": ver})
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "request_id": reqID})
}

func (h *Handler) handleGetKCV(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	k, err := h.svc.GetKey(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"kcv": strings.ToUpper(hex.EncodeToString(k.KCV)), "request_id": reqID})
}

func (h *Handler) handleGetUsage(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	usage, err := h.svc.GetUsage(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "usage_failed", err.Error(), reqID, tenantID)
		return
	}
	remaining := int64(0)
	if usage.OpsLimit > 0 {
		remaining = usage.OpsLimit - usage.OpsTotal
		if remaining < 0 {
			remaining = 0
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"usage": usage, "remaining": remaining, "request_id": reqID})
}

func (h *Handler) handleSetUsageLimit(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		OpsLimit int64  `json:"ops_limit"`
		Window   string `json:"window"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if err := h.svc.SetUsageLimit(r.Context(), tenantID, r.PathValue("id"), req.OpsLimit, req.Window); err != nil {
		writeErr(w, http.StatusInternalServerError, "usage_limit_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleSetExportPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		ExportAllowed bool `json:"export_allowed"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if err := h.svc.SetExportAllowed(r.Context(), tenantID, r.PathValue("id"), req.ExportAllowed); err != nil {
		var denied policyDeniedError
		if errors.As(err, &denied) {
			writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, tenantID)
			return
		}
		writeErr(w, http.StatusBadRequest, "export_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"export_allowed": req.ExportAllowed,
		"request_id":     reqID,
	})
}

func (h *Handler) handleResetUsage(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	if err := h.svc.ResetUsage(r.Context(), tenantID, r.PathValue("id")); err != nil {
		writeErr(w, http.StatusInternalServerError, "usage_reset_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleSetApproval(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		Required bool   `json:"required"`
		PolicyID string `json:"policy_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if err := h.svc.SetApproval(r.Context(), tenantID, r.PathValue("id"), req.Required, req.PolicyID); err != nil {
		writeErr(w, http.StatusInternalServerError, "approval_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleGetApproval(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	cfg, err := h.svc.GetApproval(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "approval_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approval": cfg, "request_id": reqID})
}

func (h *Handler) handleGetKeyAccessPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	policy, err := h.svc.GetKeyAccessPolicy(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "key_access_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policy":     policy,
		"request_id": reqID,
	})
}

func (h *Handler) handleSetKeyAccessPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		Grants    []KeyAccessGrant `json:"grants"`
		UpdatedBy string           `json:"updated_by"`
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	defer r.Body.Close() //nolint:errcheck
	if len(strings.TrimSpace(string(body))) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "grants payload is required", reqID, tenantID)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		// Also allow direct array payload.
		if arrErr := json.Unmarshal(body, &req.Grants); arrErr != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
			return
		}
	}

	updatedBy := strings.TrimSpace(req.UpdatedBy)
	if updatedBy == "" {
		actor := accessActorFromContext(r.Context())
		updatedBy = strings.TrimSpace(actor.UserID)
		if updatedBy == "" {
			updatedBy = strings.TrimSpace(actor.Username)
		}
		if updatedBy == "" {
			updatedBy = "api"
		}
	}

	if err := h.svc.ReplaceKeyAccessPolicy(r.Context(), tenantID, r.PathValue("id"), req.Grants, updatedBy); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "key_access_policy_update_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleListAccessGroups(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListAccessGroups(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_access_groups_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

func (h *Handler) handleCreateAccessGroup(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		CreatedBy   string `json:"created_by"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}

	createdBy := strings.TrimSpace(req.CreatedBy)
	if createdBy == "" {
		actor := accessActorFromContext(r.Context())
		createdBy = strings.TrimSpace(actor.UserID)
		if createdBy == "" {
			createdBy = strings.TrimSpace(actor.Username)
		}
		if createdBy == "" {
			createdBy = "api"
		}
	}

	group, err := h.svc.CreateAccessGroup(r.Context(), tenantID, req.Name, req.Description, createdBy)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "create_access_group_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"group": group, "request_id": reqID})
}

func (h *Handler) handleDeleteAccessGroup(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	if err := h.svc.DeleteAccessGroup(r.Context(), tenantID, r.PathValue("id")); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "delete_access_group_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleSetAccessGroupMembers(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		UserIDs []string `json:"user_ids"`
		Members []string `json:"members"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	userIDs := req.UserIDs
	if len(userIDs) == 0 && len(req.Members) > 0 {
		userIDs = req.Members
	}
	if err := h.svc.SetAccessGroupMembers(r.Context(), tenantID, r.PathValue("id"), userIDs); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "set_access_group_members_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleSetIVMode(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		IVMode string `json:"iv_mode"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if err := h.svc.store.UpdateIVMode(r.Context(), tenantID, r.PathValue("id"), defaultIV(req.IVMode)); err != nil {
		writeErr(w, http.StatusInternalServerError, "iv_mode_failed", err.Error(), reqID, tenantID)
		return
	}
	_ = h.svc.publishAudit(r.Context(), "audit.key.iv_mode_updated", tenantID, map[string]any{"key_id": r.PathValue("id"), "iv_mode": defaultIV(req.IVMode)})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleListTags(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListTagCatalog(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "tags_failed", err.Error(), reqID, tenantID)
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, t := range items {
		out = append(out, map[string]any{
			"tenant_id":  t.TenantID,
			"name":       t.Name,
			"color":      t.Color,
			"is_system":  t.IsSystem,
			"created_by": t.CreatedBy,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "request_id": reqID})
}

func (h *Handler) handleUpsertTag(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		Name  string `json:"name"`
		Color string `json:"color"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	tag, err := h.svc.UpsertTag(r.Context(), TagDefinition{
		TenantID:  tenantID,
		Name:      req.Name,
		Color:     req.Color,
		CreatedBy: tenantID,
	})
	if err != nil {
		writeErr(w, http.StatusBadRequest, "upsert_tag_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tag": map[string]any{
			"tenant_id":  tag.TenantID,
			"name":       tag.Name,
			"color":      tag.Color,
			"is_system":  tag.IsSystem,
			"created_by": tag.CreatedBy,
		},
		"request_id": reqID,
	})
}

func (h *Handler) handleDeleteTag(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	if err := h.svc.DeleteTag(r.Context(), tenantID, r.PathValue("name")); err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "delete_tag_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleGetIVLog(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := h.svc.store.GetIVLog(r.Context(), tenantID, r.PathValue("id"), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "iv_log_failed", err.Error(), reqID, tenantID)
		return
	}
	out := make([]map[string]any, 0, len(items))
	for _, it := range items {
		out = append(out, map[string]any{
			"id":           it.ID,
			"key_version":  it.KeyVersion,
			"iv":           base64.StdEncoding.EncodeToString(it.IV),
			"operation":    it.Operation,
			"reference_id": it.Reference,
			"created_at":   it.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "request_id": reqID})
}

func (h *Handler) handleGetIVByRef(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	item, err := h.svc.store.GetIVByReference(r.Context(), tenantID, r.PathValue("id"), r.PathValue("ref"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"iv":           base64.StdEncoding.EncodeToString(item.IV),
		"key_version":  item.KeyVersion,
		"reference_id": item.Reference,
		"request_id":   reqID,
	})
}

func (h *Handler) handleEncryptWithOperation(w http.ResponseWriter, r *http.Request, operation string) {
	reqID := requestID(r)
	var req EncryptRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	if strings.TrimSpace(operation) != "" {
		req.Operation = strings.TrimSpace(operation)
	}
	resp, err := h.svc.Encrypt(r.Context(), r.PathValue("id"), req)
	if err != nil {
		var denied policyDeniedError
		var fipsDenied fipsModeViolationError
		switch {
		case errors.Is(err, errOpsLimit):
			writeErr(w, http.StatusTooManyRequests, "ops_limit_reached", "Operation limit reached for this key", reqID, req.TenantID)
		case errors.As(err, &denied):
			writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, req.TenantID)
		case errors.As(err, &fipsDenied):
			writeErr(w, http.StatusForbidden, "fips_mode_violation", fipsDenied.Error(), reqID, req.TenantID)
		default:
			var approval approvalRequiredError
			if errors.As(err, &approval) {
				writeJSON(w, http.StatusAccepted, map[string]any{"status": "pending_approval", "approval_request_id": approval.RequestID, "request_id": reqID})
				return
			}
			writeErr(w, http.StatusBadRequest, "encrypt_failed", err.Error(), reqID, req.TenantID)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ciphertext": resp.CipherB64, "iv": resp.IVB64, "version": resp.Version, "key_id": resp.KeyID, "kcv": resp.KCV, "request_id": reqID})
}

func (h *Handler) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	h.handleEncryptWithOperation(w, r, "encrypt")
}

func (h *Handler) handleDecryptWithOperation(w http.ResponseWriter, r *http.Request, operation string) {
	reqID := requestID(r)
	var req DecryptRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	if strings.TrimSpace(operation) != "" {
		req.Operation = strings.TrimSpace(operation)
	}
	resp, err := h.svc.Decrypt(r.Context(), r.PathValue("id"), req)
	if err != nil {
		var denied policyDeniedError
		var fipsDenied fipsModeViolationError
		if errors.As(err, &denied) {
			writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, req.TenantID)
			return
		}
		if errors.As(err, &fipsDenied) {
			writeErr(w, http.StatusForbidden, "fips_mode_violation", fipsDenied.Error(), reqID, req.TenantID)
			return
		}
		writeErr(w, http.StatusBadRequest, "decrypt_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plaintext": resp.PlainB64, "version": resp.Version, "key_id": resp.KeyID, "request_id": reqID})
}

func (h *Handler) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	h.handleDecryptWithOperation(w, r, "decrypt")
}

func (h *Handler) handleSignWithOperation(w http.ResponseWriter, r *http.Request, operation string) {
	reqID := requestID(r)
	var req SignRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	if strings.TrimSpace(operation) != "" {
		req.Operation = strings.TrimSpace(operation)
	}
	resp, err := h.svc.Sign(r.Context(), r.PathValue("id"), req)
	if err != nil {
		var denied policyDeniedError
		var fipsDenied fipsModeViolationError
		if errors.As(err, &denied) {
			writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, req.TenantID)
			return
		}
		if errors.As(err, &fipsDenied) {
			writeErr(w, http.StatusForbidden, "fips_mode_violation", fipsDenied.Error(), reqID, req.TenantID)
			return
		}
		writeErr(w, http.StatusBadRequest, "sign_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"signature": resp.SignatureB64, "version": resp.Version, "key_id": resp.KeyID, "request_id": reqID})
}

func (h *Handler) handleSign(w http.ResponseWriter, r *http.Request) {
	h.handleSignWithOperation(w, r, "sign")
}

func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req VerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	resp, err := h.svc.Verify(r.Context(), r.PathValue("id"), req)
	if err != nil {
		var denied policyDeniedError
		var fipsDenied fipsModeViolationError
		if errors.As(err, &denied) {
			writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, req.TenantID)
			return
		}
		if errors.As(err, &fipsDenied) {
			writeErr(w, http.StatusForbidden, "fips_mode_violation", fipsDenied.Error(), reqID, req.TenantID)
			return
		}
		writeErr(w, http.StatusBadRequest, "verify_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verified": resp.Verified, "version": resp.Version, "key_id": resp.KeyID, "request_id": reqID})
}

func (h *Handler) handleWrap(w http.ResponseWriter, r *http.Request) {
	h.handleEncryptWithOperation(w, r, "wrap")
}

func (h *Handler) handleUnwrap(w http.ResponseWriter, r *http.Request) {
	h.handleDecryptWithOperation(w, r, "unwrap")
}

func (h *Handler) handleMAC(w http.ResponseWriter, r *http.Request) {
	h.handleSignWithOperation(w, r, "mac")
}

func (h *Handler) handleDerive(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req DeriveRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	resp, err := h.svc.Derive(r.Context(), r.PathValue("id"), req)
	if err != nil {
		var denied policyDeniedError
		var fipsDenied fipsModeViolationError
		switch {
		case errors.Is(err, errOpsLimit):
			writeErr(w, http.StatusTooManyRequests, "ops_limit_reached", "Operation limit reached for this key", reqID, req.TenantID)
		case errors.As(err, &denied):
			writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, req.TenantID)
		case errors.As(err, &fipsDenied):
			writeErr(w, http.StatusForbidden, "fips_mode_violation", fipsDenied.Error(), reqID, req.TenantID)
		default:
			var approval approvalRequiredError
			if errors.As(err, &approval) {
				writeJSON(w, http.StatusAccepted, map[string]any{"status": "pending_approval", "approval_request_id": approval.RequestID, "request_id": reqID})
				return
			}
			writeErr(w, http.StatusBadRequest, "derive_failed", err.Error(), reqID, req.TenantID)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key_id":      resp.KeyID,
		"version":     resp.Version,
		"algorithm":   resp.Algorithm,
		"length_bits": resp.LengthBits,
		"derived_key": resp.DerivedB64,
		"request_id":  reqID,
	})
}

func (h *Handler) handleKEMEncapsulate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req KEMEncapsulateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	resp, err := h.svc.KEMEncapsulate(r.Context(), r.PathValue("id"), req)
	if err != nil {
		var denied policyDeniedError
		var fipsDenied fipsModeViolationError
		switch {
		case errors.Is(err, errOpsLimit):
			writeErr(w, http.StatusTooManyRequests, "ops_limit_reached", "Operation limit reached for this key", reqID, req.TenantID)
		case errors.As(err, &denied):
			writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, req.TenantID)
		case errors.As(err, &fipsDenied):
			writeErr(w, http.StatusForbidden, "fips_mode_violation", fipsDenied.Error(), reqID, req.TenantID)
		default:
			var approval approvalRequiredError
			if errors.As(err, &approval) {
				writeJSON(w, http.StatusAccepted, map[string]any{"status": "pending_approval", "approval_request_id": approval.RequestID, "request_id": reqID})
				return
			}
			writeErr(w, http.StatusBadRequest, "kem_encapsulate_failed", err.Error(), reqID, req.TenantID)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key_id":           resp.KeyID,
		"version":          resp.Version,
		"algorithm":        resp.Algorithm,
		"shared_secret":    resp.SharedSecretB64,
		"encapsulated_key": resp.EncapsulatedB64,
		"request_id":       reqID,
	})
}

func (h *Handler) handleKEMDecapsulate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req KEMDecapsulateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	resp, err := h.svc.KEMDecapsulate(r.Context(), r.PathValue("id"), req)
	if err != nil {
		var denied policyDeniedError
		var fipsDenied fipsModeViolationError
		switch {
		case errors.Is(err, errOpsLimit):
			writeErr(w, http.StatusTooManyRequests, "ops_limit_reached", "Operation limit reached for this key", reqID, req.TenantID)
		case errors.As(err, &denied):
			writeErr(w, http.StatusForbidden, "policy_denied", denied.Error(), reqID, req.TenantID)
		case errors.As(err, &fipsDenied):
			writeErr(w, http.StatusForbidden, "fips_mode_violation", fipsDenied.Error(), reqID, req.TenantID)
		default:
			var approval approvalRequiredError
			if errors.As(err, &approval) {
				writeJSON(w, http.StatusAccepted, map[string]any{"status": "pending_approval", "approval_request_id": approval.RequestID, "request_id": reqID})
				return
			}
			writeErr(w, http.StatusBadRequest, "kem_decapsulate_failed", err.Error(), reqID, req.TenantID)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"key_id":        resp.KeyID,
		"version":       resp.Version,
		"algorithm":     resp.Algorithm,
		"shared_secret": resp.SharedSecretB64,
		"request_id":    reqID,
	})
}

func (h *Handler) handleHash(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req HashRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	resp, err := h.svc.Hash(r.Context(), req)
	if err != nil {
		var fipsDenied fipsModeViolationError
		if errors.As(err, &fipsDenied) {
			writeErr(w, http.StatusForbidden, "fips_mode_violation", fipsDenied.Error(), reqID, req.TenantID)
			return
		}
		writeErr(w, http.StatusBadRequest, "hash_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"algorithm":  resp.Algorithm,
		"digest":     resp.DigestB64,
		"request_id": reqID,
	})
}

func (h *Handler) handleRandom(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RandomRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	resp, err := h.svc.Random(r.Context(), req)
	if err != nil {
		var fipsDenied fipsModeViolationError
		if errors.As(err, &fipsDenied) {
			writeErr(w, http.StatusForbidden, "fips_mode_violation", fipsDenied.Error(), reqID, req.TenantID)
			return
		}
		writeErr(w, http.StatusBadRequest, "random_failed", err.Error(), reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"bytes":      resp.BytesB64,
		"length":     resp.Length,
		"source":     resp.Source,
		"request_id": reqID,
	})
}

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id != "" {
		return id
	}
	return newID("req")
}

func mustTenant(r *http.Request, reqID string, w http.ResponseWriter) string {
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

func accessActorFromHTTPRequest(r *http.Request) AccessActor {
	ctx := r.Context()
	actor := AccessActor{}
	if claims, ok := pkgauth.ClaimsFromContext(ctx); ok && claims != nil {
		actor.UserID = strings.TrimSpace(claims.UserID)
		actor.Username = strings.TrimSpace(claims.Subject)
		if actor.Username == "" {
			actor.Username = actor.UserID
		}
		actor.Role = strings.TrimSpace(claims.Role)
		actor.Permissions = append([]string{}, claims.Permissions...)
		actor.Authenticated = actor.UserID != "" || actor.Username != ""
	}
	if actor.UserID == "" {
		actor.UserID = strings.TrimSpace(r.Header.Get("X-Actor-User-ID"))
	}
	if actor.Username == "" {
		actor.Username = strings.TrimSpace(r.Header.Get("X-Actor-Username"))
	}
	if actor.Role == "" {
		actor.Role = strings.TrimSpace(r.Header.Get("X-Actor-Role"))
	}
	if len(actor.Permissions) == 0 {
		actor.Permissions = splitCSVHeader(r.Header.Get("X-Actor-Permissions"))
	}
	actor.Groups = splitCSVHeader(r.Header.Get("X-Actor-Groups"))
	if actor.UserID != "" || actor.Username != "" {
		actor.Authenticated = true
	}
	return actor
}

func splitCSVHeader(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, item := range parts {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, code string, message string, requestID string, tenantID string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":       code,
			"message":    message,
			"request_id": requestID,
			"tenant_id":  tenantID,
		},
	})
}

func renderKeys(keys []Key) []map[string]any {
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, renderKey(k))
	}
	return out
}

func renderKey(k Key) map[string]any {
	activationAt := any(nil)
	if k.ActivationDate != nil {
		activationAt = k.ActivationDate.UTC().Format(time.RFC3339)
	}
	expiresAt := any(nil)
	if k.ExpiryDate != nil {
		expiresAt = k.ExpiryDate.UTC().Format(time.RFC3339)
	}
	destroyAt := any(nil)
	if k.DestroyDate != nil {
		destroyAt = k.DestroyDate.UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"id":                 k.ID,
		"tenant_id":          k.TenantID,
		"name":               k.Name,
		"algorithm":          k.Algorithm,
		"key_type":           k.KeyType,
		"purpose":            k.Purpose,
		"status":             normalizeLifecycleStatus(k.Status),
		"activation_date":    activationAt,
		"destroy_date":       destroyAt,
		"tags":               k.Tags,
		"labels":             k.Labels,
		"export_allowed":     k.ExportAllowed,
		"current_version":    k.CurrentVersion,
		"kcv":                strings.ToUpper(hex.EncodeToString(k.KCV)),
		"kcv_algorithm":      k.KCVAlgorithm,
		"iv_mode":            k.IVMode,
		"ops_total":          k.OpsTotal,
		"ops_encrypt":        k.OpsEncrypt,
		"ops_decrypt":        k.OpsDecrypt,
		"ops_sign":           k.OpsSign,
		"ops_limit":          k.OpsLimit,
		"ops_limit_window":   k.OpsLimitWindow,
		"approval_required":  k.ApprovalRequired,
		"approval_policy_id": k.ApprovalPolicyID,
		"created_at":         k.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":         k.UpdatedAt.UTC().Format(time.RFC3339),
		"expires_at":         expiresAt,
	}
}

func publishAuditEvent(ctx context.Context, pub AuditPublisher, subject string, tenantID string, data map[string]any) error {
	raw, err := json.Marshal(map[string]any{
		"tenant_id": tenantID,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"data":      data,
	})
	if err != nil {
		return err
	}
	return pub.Publish(ctx, subject, raw)
}
