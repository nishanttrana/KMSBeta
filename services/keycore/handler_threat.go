package main

import (
	"errors"
	"net/http"
)

func (h *Handler) handleListThreatSignals(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := requireAuthedTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	h.svc.sweepThreatSignals(r.Context(), tenantID)
	signals, err := h.svc.store.ListThreatSignals(r.Context(), tenantID, 200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_signals_failed", err.Error(), reqID, tenantID)
		return
	}
	if signals == nil {
		signals = []ThreatSignal{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"signals": signals, "request_id": reqID})
}

func (h *Handler) handleAckThreatSignal(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := requireAuthedTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	id := r.PathValue("id")
	actor := accessActorFromContext(r.Context())
	ackedBy := firstNonEmpty(actor.UserID, actor.Username, actor.SubjectID, "unknown")
	if err := h.svc.store.AckThreatSignal(r.Context(), tenantID, id, ackedBy); err != nil {
		if errors.Is(err, errStoreNotFound) {
			writeErr(w, http.StatusNotFound, "not_found", "signal not found or already acknowledged", reqID, tenantID)
			return
		}
		writeErr(w, http.StatusInternalServerError, "ack_failed", err.Error(), reqID, tenantID)
		return
	}
	_ = h.svc.publishAudit(r.Context(), "audit.threat.signal_acknowledged", tenantID, map[string]any{
		"signal_id": id,
		"acked_by":  ackedBy,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "acknowledged", "request_id": reqID})
}

func (h *Handler) handleThreatDashboard(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := requireAuthedTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	dash, err := h.svc.GetThreatDashboard(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "dashboard_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"dashboard": dash, "request_id": reqID})
}
