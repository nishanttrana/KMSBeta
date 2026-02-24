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

	mux.HandleFunc("POST /tokenize", h.handleTokenize)
	mux.HandleFunc("POST /detokenize", h.handleDetokenize)
	mux.HandleFunc("POST /tokenize/batch", h.handleTokenize)
	mux.HandleFunc("POST /detokenize/batch", h.handleDetokenize)
	mux.HandleFunc("GET /token-vaults", h.handleListTokenVaults)
	mux.HandleFunc("POST /token-vaults", h.handleCreateTokenVault)
	mux.HandleFunc("GET /token-vaults/{id}", h.handleGetTokenVault)
	mux.HandleFunc("DELETE /token-vaults/{id}", h.handleDeleteTokenVault)

	mux.HandleFunc("POST /fpe/encrypt", h.handleFPEEncrypt)
	mux.HandleFunc("POST /fpe/decrypt", h.handleFPEDecrypt)

	mux.HandleFunc("POST /mask", h.handleMask)
	mux.HandleFunc("POST /mask/preview", h.handleMaskPreview)
	mux.HandleFunc("GET /masking-policies", h.handleListMaskingPolicies)
	mux.HandleFunc("POST /masking-policies", h.handleCreateMaskingPolicy)
	mux.HandleFunc("PUT /masking-policies/{id}", h.handleUpdateMaskingPolicy)
	mux.HandleFunc("DELETE /masking-policies/{id}", h.handleDeleteMaskingPolicy)

	mux.HandleFunc("POST /redact", h.handleRedact)
	mux.HandleFunc("POST /redact/detect", h.handleRedactDetect)
	mux.HandleFunc("GET /redaction-policies", h.handleListRedactionPolicies)
	mux.HandleFunc("POST /redaction-policies", h.handleCreateRedactionPolicy)

	mux.HandleFunc("POST /app/encrypt-fields", h.handleAppEncryptFields)
	mux.HandleFunc("POST /app/decrypt-fields", h.handleAppDecryptFields)
	mux.HandleFunc("POST /app/envelope-encrypt", h.handleAppEnvelopeEncrypt)
	mux.HandleFunc("POST /app/envelope-decrypt", h.handleAppEnvelopeDecrypt)
	mux.HandleFunc("POST /app/searchable-encrypt", h.handleAppSearchableEncrypt)
	mux.HandleFunc("POST /app/searchable-decrypt", h.handleAppSearchableDecrypt)

	mux.HandleFunc("GET /policy", h.handleGetDataProtectionPolicy)
	mux.HandleFunc("PUT /policy", h.handleSetDataProtectionPolicy)

	return mux
}

func (h *Handler) handleTokenize(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req TokenizeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	items, err := h.svc.Tokenize(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleDetokenize(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req DetokenizeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	items, err := h.svc.Detokenize(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleListTokenVaults(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListTokenVaults(r.Context(), tenantID, atoi(r.URL.Query().Get("limit")), atoi(r.URL.Query().Get("offset")))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleCreateTokenVault(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body TokenVault
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	tenantID := firstTenant(body.TenantID, tenantFromRequest(r))
	item, err := h.svc.CreateTokenVault(r.Context(), tenantID, body)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"vault": item, "request_id": reqID})
}

func (h *Handler) handleGetTokenVault(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	item, err := h.svc.GetTokenVault(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleDeleteTokenVault(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	approved := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("governance_approved")), "true") ||
		strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Governance-Approved")), "true")
	if err := h.svc.DeleteTokenVault(r.Context(), tenantID, r.PathValue("id"), approved); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleFPEEncrypt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req FPERequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.FPEEncrypt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleFPEDecrypt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req FPERequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.FPEDecrypt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleMask(w http.ResponseWriter, r *http.Request) {
	h.handleMaskWithMode(w, r, false)
}

func (h *Handler) handleMaskPreview(w http.ResponseWriter, r *http.Request) {
	h.handleMaskWithMode(w, r, true)
}

func (h *Handler) handleMaskWithMode(w http.ResponseWriter, r *http.Request, preview bool) {
	reqID := requestID(r)
	var req MaskRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.Preview = preview
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.ApplyMask(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"masked": out, "request_id": reqID})
}

func (h *Handler) handleListMaskingPolicies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListMaskingPolicies(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleCreateMaskingPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body MaskingPolicy
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	tenantID := firstTenant(body.TenantID, tenantFromRequest(r))
	item, err := h.svc.CreateMaskingPolicy(r.Context(), tenantID, body)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleUpdateMaskingPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var body MaskingPolicy
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if err := h.svc.UpdateMaskingPolicy(r.Context(), tenantID, r.PathValue("id"), body); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleDeleteMaskingPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	if err := h.svc.DeleteMaskingPolicy(r.Context(), tenantID, r.PathValue("id")); err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "request_id": reqID})
}

func (h *Handler) handleRedact(w http.ResponseWriter, r *http.Request) {
	h.handleRedactWithMode(w, r, false)
}

func (h *Handler) handleRedactDetect(w http.ResponseWriter, r *http.Request) {
	h.handleRedactWithMode(w, r, true)
}

func (h *Handler) handleRedactWithMode(w http.ResponseWriter, r *http.Request, detect bool) {
	reqID := requestID(r)
	var req RedactRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.DetectOnly = detect
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.Redact(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleListRedactionPolicies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.ListRedactionPolicies(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "request_id": reqID})
}

func (h *Handler) handleCreateRedactionPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var body RedactionPolicy
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	tenantID := firstTenant(body.TenantID, tenantFromRequest(r))
	item, err := h.svc.CreateRedactionPolicy(r.Context(), tenantID, body)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{"item": item, "request_id": reqID})
}

func (h *Handler) handleAppEncryptFields(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req AppFieldRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.EncryptFields(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleAppDecryptFields(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req AppFieldRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.DecryptFields(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleAppEnvelopeEncrypt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req EnvelopeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.EnvelopeEncrypt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleAppEnvelopeDecrypt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req EnvelopeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.EnvelopeDecrypt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleAppSearchableEncrypt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req SearchableRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.SearchableEncrypt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleAppSearchableDecrypt(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req SearchableRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantFromRequest(r))
	out, err := h.svc.SearchableDecrypt(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, req.TenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"result": out, "request_id": reqID})
}

func (h *Handler) handleGetDataProtectionPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	item, err := h.svc.GetDataProtectionPolicy(r.Context(), tenantID)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": item, "request_id": reqID})
}

func (h *Handler) handleSetDataProtectionPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req DataProtectionPolicy
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	req.TenantID = firstTenant(req.TenantID, tenantID)
	if req.TenantID != tenantID {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant mismatch between request and session context", reqID, tenantID)
		return
	}
	item, err := h.svc.UpdateDataProtectionPolicy(r.Context(), req)
	if err != nil {
		h.writeServiceError(w, err, reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"policy": item, "request_id": reqID})
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

func requestID(r *http.Request) string {
	id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if id != "" {
		return id
	}
	return newID("req")
}

func tenantFromRequest(r *http.Request) string {
	if v := strings.TrimSpace(r.URL.Query().Get("tenant_id")); v != "" {
		return v
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
