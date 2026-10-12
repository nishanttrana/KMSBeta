package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"vecta-kms/pkg/route"

	"vecta-kms/pkg/tenantcheck"
)

type Handler struct {
	svc    *Service
	router *route.Router
}

// NewHandler registers every route through the kernel, which requires a
// verified token, the route's permission and a tenant the caller may act
// in, and audits each call. Until 13.0.0-beta the settings, profile, record
// and summary handlers took the tenant from the request without comparing
// it with the token: any signed-in caller could read another tenant's
// signing records and change its profiles and settings.
func NewHandler(svc *Service, audit route.Emitter, logger *log.Logger) *Handler {
	h := &Handler{svc: svc, router: route.New("signing", audit, logger)}
	read := func(action, resource string) route.Spec {
		return route.Spec{Action: action, Permission: "signing.read", Resource: resource}
	}
	write := func(action, resource, target string) route.Spec {
		return route.Spec{Action: action, Permission: "signing.write", Resource: resource, TargetParam: target}
	}
	use := func(action string) route.Spec {
		return route.Spec{Action: action, Permission: "signing.use", Resource: "signing_artifact"}
	}
	rt := h.router
	rt.Handle("GET /signing/settings", read("settings_read", "signing_settings"), route.Legacy(h.handleGetSettings))
	rt.Handle("PUT /signing/settings", write("settings_update", "signing_settings", ""), route.Legacy(h.handlePutSettings))
	rt.Handle("GET /signing/summary", read("summary_read", "signing"), route.Legacy(h.handleGetSummary))
	rt.Handle("GET /signing/profiles", read("profile_list", "signing_profile"), route.Legacy(h.handleListProfiles))
	rt.Handle("POST /signing/profiles", write("profile_upsert", "signing_profile", ""), route.Legacy(h.handleUpsertProfile))
	rt.Handle("PUT /signing/profiles/{id}", write("profile_upsert", "signing_profile", "id"), route.Legacy(h.handleUpsertProfile))
	rt.Handle("DELETE /signing/profiles/{id}", write("profile_delete", "signing_profile", "id"), route.Legacy(h.handleDeleteProfile))
	rt.Handle("GET /signing/records", read("record_list", "signing_record"), route.Legacy(h.handleListRecords))
	rt.Handle("POST /signing/blob", use("blob_sign"), route.Legacy(h.handleSignBlob))
	rt.Handle("POST /signing/git", use("git_sign"), route.Legacy(h.handleSignGit))
	// Checking a signature is not signing: whoever deploys an artifact
	// verifies it without being able to sign one.
	rt.Handle("POST /signing/verify", route.Spec{Action: "artifact_verify", Permission: "signing.verify", Resource: "signing_artifact"}, route.Legacy(h.handleVerify))
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.router.ServeHTTP(w, r)
}

// tenantFromRequest is the tenant the kernel checked against the caller's
// token (route.Legacy). Nothing else in the request names a tenant.
func tenantFromRequest(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
}

func requestID(r *http.Request) string {
	return firstNonEmpty(r.Header.Get("X-Request-ID"), newID("req"))
}

func decodeJSON(w http.ResponseWriter, r *http.Request, out interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
	return json.NewDecoder(r.Body).Decode(out)
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, code string, message string, requestID string, tenantID string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]interface{}{
			"code":       code,
			"message":    message,
			"request_id": requestID,
			"tenant_id":  tenantID,
		},
	})
}

func (h *Handler) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	item, err := h.svc.GetSettings(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"settings": item, "request_id": reqID})
}

func (h *Handler) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body SigningSettings
	if err := decodeJSON(w, r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = tenantFromRequest(r)
	body.UpdatedBy = tenantcheck.ActingFor(r.Context(), body.UpdatedBy)
	item, err := h.svc.UpdateSettings(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"settings": item, "request_id": reqID})
}

func (h *Handler) handleGetSummary(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	item, err := h.svc.GetSummary(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"summary": item, "request_id": reqID})
}

func (h *Handler) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	items, err := h.svc.ListProfiles(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleUpsertProfile(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body SigningProfile
	if err := decodeJSON(w, r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = tenantFromRequest(r)
	body.UpdatedBy = tenantcheck.ActingFor(r.Context(), body.UpdatedBy)
	body.ID = firstNonEmpty(r.PathValue("id"), body.ID)
	item, err := h.svc.UpsertProfile(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"profile": item, "request_id": reqID})
}

func (h *Handler) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if err := h.svc.DeleteProfile(r.Context(), tenantID, r.PathValue("id")); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "request_id": reqID})
}

func (h *Handler) handleListRecords(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	items, err := h.svc.ListRecords(r.Context(), tenantID, r.URL.Query().Get("profile_id"), r.URL.Query().Get("artifact_type"), limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleSignBlob(w http.ResponseWriter, r *http.Request) {
	h.handleSign(w, r, "blob")
}

func (h *Handler) handleSignGit(w http.ResponseWriter, r *http.Request) {
	h.handleSign(w, r, "git")
}

func (h *Handler) handleSign(w http.ResponseWriter, r *http.Request, artifactType string) {
	reqID := requestID(r)
	var body SignArtifactInput
	if err := decodeJSON(w, r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = tenantFromRequest(r)
	body.RequestedBy = tenantcheck.ActingFor(r.Context(), body.RequestedBy)
	body.ArtifactType = firstNonEmpty(body.ArtifactType, artifactType)
	item, err := h.svc.SignArtifact(r.Context(), body)
	if err != nil {
		if status := httpStatusForErr(err); status < 500 {
			_ = publishAudit(r.Context(), h.svc.events, "audit.signing.sign_refused", body.TenantID, map[string]interface{}{
				"profile_id": body.ProfileID, "identity_mode": body.IdentityMode, "code": serviceCode(err),
				"reason": err.Error(), "result": "refused", "severity": "warning",
			})
		}
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"result": item, "request_id": reqID})
}

func (h *Handler) handleVerify(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body VerifyArtifactInput
	if err := decodeJSON(w, r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = tenantFromRequest(r)
	item, err := h.svc.VerifyArtifact(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": item, "request_id": reqID})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, reqID string, tenantID string) {
	// A05: avoid leaking internal error details for 5xx responses
	status := httpStatusForErr(err)
	msg := err.Error()
	if status >= 500 {
		msg = "internal server error"
	}
	writeErr(w, status, serviceCode(err), msg, reqID, strings.TrimSpace(tenantID))
}

func serviceCode(err error) string {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		return svcErr.Code
	}
	if errors.Is(err, errNotFound) {
		return "not_found"
	}
	return "internal_error"
}
