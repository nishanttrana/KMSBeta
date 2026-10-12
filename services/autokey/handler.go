package main

import (
	"vecta-kms/pkg/tenantcheck"
	"vecta-kms/pkg/route"
	"log"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

)

type Handler struct {
	svc    *Service
	router *route.Router
}

// NewHandler registers every route through the kernel, which requires a
// verified token, the route's permission and a tenant the caller may act
// in, and audits each call. Until 13.0.0-beta the handlers took the tenant
// from the request and never compared it with the token (the helper that
// did was not called), so any signed-in caller could read and change
// another tenant's templates, policies and key requests.
func NewHandler(svc *Service, audit route.Emitter, logger *log.Logger) *Handler {
	h := &Handler{svc: svc, router: route.New("autokey", audit, logger)}
	read := func(action, resource string) route.Spec {
		return route.Spec{Action: action, Permission: "autokey.read", Resource: resource}
	}
	write := func(action, resource, target string) route.Spec {
		return route.Spec{Action: action, Permission: "autokey.write", Resource: resource, TargetParam: target}
	}
	rt := h.router
	rt.Handle("GET /autokey/settings", read("settings_read", "autokey_settings"), route.Legacy(h.handleGetSettings))
	rt.Handle("PUT /autokey/settings", write("settings_update", "autokey_settings", ""), route.Legacy(h.handlePutSettings))
	rt.Handle("GET /autokey/summary", read("summary_read", "autokey"), route.Legacy(h.handleGetSummary))
	rt.Handle("GET /autokey/templates", read("template_list", "autokey_template"), route.Legacy(h.handleListTemplates))
	rt.Handle("POST /autokey/templates", write("template_upsert", "autokey_template", ""), route.Legacy(h.handleUpsertTemplate))
	rt.Handle("PUT /autokey/templates/{id}", write("template_upsert", "autokey_template", "id"), route.Legacy(h.handleUpsertTemplate))
	rt.Handle("DELETE /autokey/templates/{id}", write("template_delete", "autokey_template", "id"), route.Legacy(h.handleDeleteTemplate))
	rt.Handle("GET /autokey/service-policies", read("service_policy_list", "autokey_service_policy"), route.Legacy(h.handleListServicePolicies))
	rt.Handle("POST /autokey/service-policies", write("service_policy_upsert", "autokey_service_policy", ""), route.Legacy(h.handleUpsertServicePolicy))
	rt.Handle("PUT /autokey/service-policies/{service}", write("service_policy_upsert", "autokey_service_policy", "service"), route.Legacy(h.handleUpsertServicePolicy))
	rt.Handle("DELETE /autokey/service-policies/{service}", write("service_policy_delete", "autokey_service_policy", "service"), route.Legacy(h.handleDeleteServicePolicy))
	rt.Handle("GET /autokey/requests", read("request_list", "autokey_request"), route.Legacy(h.handleListRequests))
	// Asking for a key is its own permission: more people ask than administer.
	rt.Handle("POST /autokey/requests", route.Spec{Action: "request_create", Permission: "autokey.use", Resource: "autokey_request"}, route.Legacy(h.handleCreateRequest))
	rt.Handle("GET /autokey/requests/{id}", route.Spec{Action: "request_read", Permission: "autokey.read", Resource: "autokey_request", TargetParam: "id"}, route.Legacy(h.handleGetRequest))
	rt.Handle("GET /autokey/handles", read("handle_list", "autokey_handle"), route.Legacy(h.handleListHandles))
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
	var body AutokeySettings
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

func (h *Handler) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	items, err := h.svc.ListTemplates(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleUpsertTemplate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body AutokeyTemplate
	if err := decodeJSON(w, r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = tenantFromRequest(r)
	body.UpdatedBy = tenantcheck.ActingFor(r.Context(), body.UpdatedBy)
	body.ID = firstNonEmpty(r.PathValue("id"), body.ID)
	item, err := h.svc.UpsertTemplate(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"template": item, "request_id": reqID})
}

func (h *Handler) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if err := h.svc.DeleteTemplate(r.Context(), tenantID, r.PathValue("id")); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "request_id": reqID})
}

func (h *Handler) handleListServicePolicies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	items, err := h.svc.ListServicePolicies(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleUpsertServicePolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body AutokeyServicePolicy
	if err := decodeJSON(w, r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = tenantFromRequest(r)
	body.UpdatedBy = tenantcheck.ActingFor(r.Context(), body.UpdatedBy)
	body.ServiceName = firstNonEmpty(r.PathValue("service"), body.ServiceName)
	item, err := h.svc.UpsertServicePolicy(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": item, "request_id": reqID})
}

func (h *Handler) handleDeleteServicePolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	if err := h.svc.DeleteServicePolicy(r.Context(), tenantID, r.PathValue("service")); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "request_id": reqID})
}

func (h *Handler) handleCreateRequest(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body CreateAutokeyRequestInput
	if err := decodeJSON(w, r, &body); err != nil {
		h.writeServiceError(w, newServiceError(http.StatusBadRequest, "bad_request", err.Error()), reqID, tenantFromRequest(r))
		return
	}
	body.TenantID = tenantFromRequest(r)
	body.RequesterID, body.RequesterEmail, body.RequesterIP = tenantcheck.Requester(r, body.RequesterID, body.RequesterEmail, body.RequesterIP)
	item, err := h.svc.CreateRequest(r.Context(), body)
	if err != nil {
		h.writeServiceError(w, err, reqID, body.TenantID)
		return
	}
	status := http.StatusCreated
	if strings.EqualFold(item.Status, "pending_approval") {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]interface{}{"request": item, "request_id": reqID})
}

func (h *Handler) handleListRequests(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	items, err := h.svc.ListRequests(r.Context(), tenantID, strings.TrimSpace(r.URL.Query().Get("status")), limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetRequest(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	item, err := h.svc.GetRequest(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"request": item, "request_id": reqID})
}

func (h *Handler) handleListHandles(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := tenantFromRequest(r)
	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	items, err := h.svc.ListHandles(r.Context(), tenantID, strings.TrimSpace(r.URL.Query().Get("service_name")), limit)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
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
