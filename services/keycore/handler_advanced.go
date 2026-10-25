package main

import (
	"net/http"
)

// ─── Key Material Verification (enhanced) ─────────────────────────────────────

func (h *Handler) handleVerifyKeyMaterial(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := requireAuthedTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	res, err := h.svc.VerifyKeyIntegrity(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "key not found", reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"result": res, "request_id": reqID})
}
