package main

import "net/http"

func (h *Handler) handleAttestKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := requireAuthedTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	att, err := h.svc.AttestKey(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "key not found", reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"attestation": att, "request_id": reqID})
}

func (h *Handler) handleAttestationPublicKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := requireAuthedTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	pem, fp, err := h.svc.attestationPublicKeyPEM()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "attestation_key_error", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"public_key_pem":         pem,
		"public_key_fingerprint": fp,
		"request_id":             reqID,
	})
}
