package main

import (
	"errors"
	"net/http"
	"strings"
)

// handleCreateCredentialBinding registers an external credential as protected
// by a key. The caller supplies either the raw credential value (hashed
// server-side, never stored) or a precomputed fingerprint.
func (h *Handler) handleCreateCredentialBinding(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := requireAuthedTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	keyID := r.PathValue("id")
	if _, err := h.svc.GetKey(r.Context(), tenantID, keyID); err != nil {
		writeErr(w, http.StatusNotFound, "key_not_found", "key not found", reqID, tenantID)
		return
	}
	var req struct {
		Value          string `json:"value"`
		Fingerprint    string `json:"fingerprint"`
		CredentialType string `json:"credential_type"`
		Label          string `json:"label"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	fingerprint := strings.TrimSpace(req.Fingerprint)
	if v := strings.TrimSpace(req.Value); v != "" {
		fingerprint = credentialFingerprint(v)
	}
	if fingerprint == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "either value or fingerprint is required", reqID, tenantID)
		return
	}
	binding, err := h.svc.store.UpsertCredentialBinding(r.Context(), CredentialBinding{
		TenantID:       tenantID,
		Fingerprint:    fingerprint,
		CredentialType: strings.TrimSpace(req.CredentialType),
		KeyID:          keyID,
		Label:          strings.TrimSpace(req.Label),
		CreatedBy:      accessActorFromContext(r.Context()).UserID,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_binding_failed", err.Error(), reqID, tenantID)
		return
	}
	_ = h.svc.publishAudit(r.Context(), "audit.key.credential_binding_created", tenantID, map[string]any{
		"key_id":          keyID,
		"binding_id":      binding.ID,
		"credential_type": binding.CredentialType,
	})
	writeJSON(w, http.StatusCreated, map[string]any{"binding": binding, "request_id": reqID})
}

func (h *Handler) handleListCredentialBindings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := requireAuthedTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	bindings, err := h.svc.store.ListCredentialBindingsByKey(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_bindings_failed", err.Error(), reqID, tenantID)
		return
	}
	if bindings == nil {
		bindings = []CredentialBinding{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"bindings": bindings, "request_id": reqID})
}

func (h *Handler) handleDeleteCredentialBinding(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := requireAuthedTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	id := r.PathValue("binding_id")
	if err := h.svc.store.DeleteCredentialBinding(r.Context(), tenantID, id); err != nil {
		if errors.Is(err, errStoreNotFound) {
			writeErr(w, http.StatusNotFound, "not_found", "binding not found", reqID, tenantID)
			return
		}
		writeErr(w, http.StatusInternalServerError, "delete_binding_failed", err.Error(), reqID, tenantID)
		return
	}
	_ = h.svc.publishAudit(r.Context(), "audit.key.credential_binding_deleted", tenantID, map[string]any{"binding_id": id})
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "request_id": reqID})
}

// handleResolveCredentialBindings maps a batch of credential fingerprints to
// the keys that protect them. Used by the unified console to turn leaked
// credentials into correlatable key references.
func (h *Handler) handleResolveCredentialBindings(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := requireAuthedTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req struct {
		Fingerprints []string `json:"fingerprints"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if len(req.Fingerprints) > 1000 {
		writeErr(w, http.StatusBadRequest, "too_many", "at most 1000 fingerprints per request", reqID, tenantID)
		return
	}
	bindings, err := h.svc.store.ResolveCredentialBindings(r.Context(), tenantID, req.Fingerprints)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "resolve_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bindings": bindings, "request_id": reqID})
}
