package main

import (
	"encoding/json"
	"errors"
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
	mux.HandleFunc("POST /cloud/accounts", h.handleRegisterAccount)
	mux.HandleFunc("GET /cloud/accounts", h.handleListAccounts)
	mux.HandleFunc("DELETE /cloud/accounts/{id}", h.handleDeleteAccount)
	mux.HandleFunc("POST /cloud/region-mappings", h.handleSetRegionMapping)
	mux.HandleFunc("GET /cloud/region-mappings", h.handleListRegionMappings)
	mux.HandleFunc("POST /cloud/import", h.handleImportKey)
	mux.HandleFunc("POST /cloud/bindings/{id}/rotate", h.handleRotateBinding)
	mux.HandleFunc("POST /cloud/sync", h.handleSync)
	mux.HandleFunc("GET /cloud/inventory", h.handleInventory)
	mux.HandleFunc("GET /cloud/bindings", h.handleListBindings)
	mux.HandleFunc("GET /cloud/bindings/{id}", h.handleGetBinding)
	return mux
}

func (h *Handler) handleRegisterAccount(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req RegisterCloudAccountRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, err := h.svc.RegisterAccount(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID, "register_failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"account": out, "request_id": reqID})
}

func (h *Handler) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListAccounts(r.Context(), tenantID, r.URL.Query().Get("provider"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID, "list_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	accountID := strings.TrimSpace(r.PathValue("id"))
	if accountID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "account id is required", reqID, tenantID)
		return
	}
	out, err := h.svc.DeleteAccount(r.Context(), tenantID, accountID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID, "delete_account_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleSetRegionMapping(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req SetRegionMappingRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	out, err := h.svc.SetRegionMapping(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID, "mapping_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"mapping": out, "request_id": reqID})
}

func (h *Handler) handleListRegionMappings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListRegionMappings(r.Context(), tenantID, r.URL.Query().Get("provider"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID, "list_mappings_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleImportKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ImportKeyToCloudRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if strings.TrimSpace(req.RequesterIP) == "" {
		req.RequesterIP = requestIP(r)
	}
	out, err := h.svc.ImportKeyToCloud(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID, "import_failed")
		return
	}
	status := http.StatusCreated
	if strings.EqualFold(out.OperationStatus, "pending_approval") {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]interface{}{"binding": out, "request_id": reqID})
}

func (h *Handler) handleRotateBinding(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	var body struct {
		Reason            string `json:"reason"`
		RequesterID       string `json:"requester_id,omitempty"`
		RequesterEmail    string `json:"requester_email,omitempty"`
		RequesterIP       string `json:"requester_ip,omitempty"`
		JustificationCode string `json:"justification_code,omitempty"`
		JustificationText string `json:"justification_text,omitempty"`
	}
	_ = decodeJSON(r, &body)
	if strings.TrimSpace(body.RequesterIP) == "" {
		body.RequesterIP = requestIP(r)
	}
	out, versionID, err := h.svc.RotateCloudKey(r.Context(), RotateCloudKeyRequest{
		TenantID:          tenantID,
		BindingID:         r.PathValue("id"),
		Reason:            body.Reason,
		RequesterID:       body.RequesterID,
		RequesterEmail:    body.RequesterEmail,
		RequesterIP:       body.RequesterIP,
		JustificationCode: body.JustificationCode,
		JustificationText: body.JustificationText,
	})
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID, "rotate_failed")
		return
	}
	status := http.StatusOK
	if strings.EqualFold(out.OperationStatus, "pending_approval") {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]interface{}{
		"binding":    out,
		"version_id": versionID,
		"request_id": reqID,
	})
}

func (h *Handler) handleSync(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req SyncCloudKeysRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	if strings.TrimSpace(req.RequesterIP) == "" {
		req.RequesterIP = requestIP(r)
	}
	out, err := h.svc.SyncCloudKeys(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID, "sync_failed")
		return
	}
	status := http.StatusOK
	if strings.EqualFold(out.Status, "pending_approval") {
		status = http.StatusAccepted
	}
	writeJSON(w, status, map[string]interface{}{"job": out, "request_id": reqID})
}

func (h *Handler) handleInventory(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	items, err := h.svc.DiscoverInventory(r.Context(), DiscoverInventoryRequest{
		TenantID:    tenantID,
		Provider:    r.URL.Query().Get("provider"),
		AccountID:   r.URL.Query().Get("account_id"),
		CloudRegion: r.URL.Query().Get("cloud_region"),
	})
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID, "inventory_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleListBindings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	limit, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit")))
	offset, _ := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("offset")))
	items, err := h.svc.ListBindings(r.Context(), tenantID, r.URL.Query().Get("provider"), r.URL.Query().Get("account_id"), r.URL.Query().Get("key_id"), limit, offset)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID, "list_bindings_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleGetBinding(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, w, reqID)
	if tenantID == "" {
		return
	}
	out, err := h.svc.GetBinding(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID, "get_binding_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"binding": out, "request_id": reqID})
}

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func mustTenant(r *http.Request, w http.ResponseWriter, requestID string) string {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	}
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", requestID, "")
		return ""
	}
	return tenantID
}

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id != "" {
		return id
	}
	return newID("req")
}

func requestIP(r *http.Request) string {
	raw := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if raw != "" {
		parts := strings.Split(raw, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	return strings.TrimSpace(r.Header.Get("X-Real-IP"))
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

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, requestID string, tenantID string, fallbackCode string) {
	code := httpStatusForErr(err)
	if errors.Is(err, errNotFound) {
		code = http.StatusNotFound
	}
	writeErr(w, code, serviceCode(err, fallbackCode), err.Error(), requestID, tenantID)
}
