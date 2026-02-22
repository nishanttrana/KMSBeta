package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
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

	mux.HandleFunc("POST /mpc/dkg/initiate", h.handleDKGInitiate)
	mux.HandleFunc("GET /mpc/dkg/{id}/status", h.handleDKGStatus)
	mux.HandleFunc("POST /mpc/dkg/{id}/contribute", h.handleDKGContribute)
	mux.HandleFunc("GET /mpc/dkg/{id}/result", h.handleDKGResult)

	mux.HandleFunc("POST /mpc/sign/initiate", h.handleSignInitiate)
	mux.HandleFunc("POST /mpc/sign/{id}/contribute", h.handleSignContribute)
	mux.HandleFunc("GET /mpc/sign/{id}/result", h.handleSignResult)

	mux.HandleFunc("POST /mpc/decrypt/initiate", h.handleDecryptInitiate)
	mux.HandleFunc("POST /mpc/decrypt/{id}/contribute", h.handleDecryptContribute)
	mux.HandleFunc("GET /mpc/decrypt/{id}/result", h.handleDecryptResult)

	mux.HandleFunc("GET /mpc/shares", h.handleShares)
	mux.HandleFunc("GET /mpc/shares/{key_id}", h.handleShareMetadata)
	mux.HandleFunc("POST /mpc/shares/{key_id}/refresh", h.handleShareRefresh)
	mux.HandleFunc("POST /mpc/shares/backup", h.handleShareBackup)

	mux.HandleFunc("GET /mpc/keys", h.handleKeys)
	mux.HandleFunc("GET /mpc/keys/{id}", h.handleKey)
	mux.HandleFunc("POST /mpc/keys/{id}/rotate", h.handleKeyRotate)

	return mux
}

func (h *Handler) handleDKGInitiate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req DKGInitiateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	item, err := h.svc.InitiateDKG(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"ceremony": item, "request_id": reqID})
}

func (h *Handler) handleDKGStatus(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	item, err := h.svc.GetCeremony(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ceremony": item, "request_id": reqID})
}

func (h *Handler) handleDKGContribute(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req DKGContributeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	item, err := h.svc.ContributeDKG(r.Context(), r.PathValue("id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ceremony": item, "request_id": reqID})
}

func (h *Handler) handleDKGResult(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	result, err := h.svc.GetCeremonyResult(r.Context(), tenantID, r.PathValue("id"), "dkg")
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": result, "request_id": reqID})
}

func (h *Handler) handleSignInitiate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req SignInitiateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	item, err := h.svc.InitiateSign(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"ceremony": item, "request_id": reqID})
}

func (h *Handler) handleSignContribute(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req SignContributeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	item, err := h.svc.ContributeSign(r.Context(), r.PathValue("id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ceremony": item, "request_id": reqID})
}

func (h *Handler) handleSignResult(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	result, err := h.svc.GetCeremonyResult(r.Context(), tenantID, r.PathValue("id"), "sign")
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": result, "request_id": reqID})
}

func (h *Handler) handleDecryptInitiate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req DecryptInitiateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	item, err := h.svc.InitiateDecrypt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]interface{}{"ceremony": item, "request_id": reqID})
}

func (h *Handler) handleDecryptContribute(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req DecryptContributeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	item, err := h.svc.ContributeDecrypt(r.Context(), r.PathValue("id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ceremony": item, "request_id": reqID})
}

func (h *Handler) handleDecryptResult(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	result, err := h.svc.GetCeremonyResult(r.Context(), tenantID, r.PathValue("id"), "decrypt")
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": result, "request_id": reqID})
}

func (h *Handler) handleShares(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListShares(r.Context(), tenantID, strings.TrimSpace(r.URL.Query().Get("node_id")), atoi(r.URL.Query().Get("limit")))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleShareMetadata(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.GetShareMetadata(r.Context(), tenantID, r.PathValue("key_id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleShareRefresh(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req ShareRefreshRequest
	_ = decodeJSONAllowEmpty(r, &req)
	req.TenantID = tenantID
	key, err := h.svc.RefreshShares(r.Context(), r.PathValue("key_id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"key": key, "request_id": reqID})
}

func (h *Handler) handleShareBackup(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req ShareBackupRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.BackupShare(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleKeys(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListMPCKeys(r.Context(), tenantID, atoi(r.URL.Query().Get("limit")), atoi(r.URL.Query().Get("offset")))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	item, err := h.svc.GetMPCKey(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleKeyRotate(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req KeyRotateRequest
	_ = decodeJSONAllowEmpty(r, &req)
	req.TenantID = tenantID
	item, err := h.svc.RotateMPCKey(r.Context(), r.PathValue("id"), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, err error, reqID string, tenantID string) {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		writeErr(w, svcErr.HTTPStatus, svcErr.Code, svcErr.Message, reqID, tenantID)
		return
	}
	writeErr(w, httpStatusForErr(err), "internal_error", err.Error(), reqID, tenantID)
}

func decodeJSON(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("request body is required")
		}
		return err
	}
	return nil
}

func decodeJSONAllowEmpty(r *http.Request, out interface{}) error {
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id != "" {
		return id
	}
	return newID("req")
}

func tenantFromRequest(r *http.Request) string {
	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	if tenantID != "" {
		return tenantID
	}
	return strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
}

func firstTenant(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func mustTenant(r *http.Request, reqID string, w http.ResponseWriter) string {
	tenantID := tenantFromRequest(r)
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id is required (query or X-Tenant-ID)", reqID, "")
		return ""
	}
	return tenantID
}

func writeJSON(w http.ResponseWriter, status int, payload map[string]interface{}) {
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
