package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Ensure json import remains used (decode path).
var _ = json.NewDecoder

// handleDecommissionCandidates returns the list of KMIP clients the
// reconciler should act on this tick. The reconciler doesn't decide
// which clients to move — the KMIP service does, by running each
// candidate through EvaluateDecommission against the policy.
//
// GET /kmip/clients/decommission-candidates
func (h *Handler) handleDecommissionCandidates(w http.ResponseWriter, r *http.Request) {
	clients, err := h.store.ListAllKMIPClients(r.Context())
	if err != nil {
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	policy := DefaultDecommissionPolicy()
	now := time.Now().UTC()
	type item struct {
		ClientID string `json:"client_id"`
		TenantID string `json:"tenant_id"`
		Action   string `json:"action"`
		Reason   string `json:"reason"`
	}
	out := make([]item, 0)
	for _, c := range clients {
		act := EvaluateDecommission(ClientActivity{
			ID:         c.ID,
			TenantID:   c.TenantID,
			Status:     c.Status,
			LastSeenAt: c.UpdatedAt,
			CreatedAt:  c.CreatedAt,
		}, now, policy)
		if act == DecommissionNone {
			continue
		}
		out = append(out, item{
			ClientID: c.ID,
			TenantID: c.TenantID,
			Action:   string(act),
			Reason:   DescribeAction(act),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": out,
	})
}

// handleDecommission applies the action the reconciler decided to take
// against one client. The endpoint accepts the action verbatim from the
// candidates list so the KMIP service stays the source of truth for the
// per-client status; the reconciler is purely a trigger.
//
// POST /kmip/clients/{id}/decommission
func (h *Handler) handleDecommission(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "client id is required", http.StatusBadRequest)
		return
	}
	var req struct {
		Action   string `json:"action"`
		Reason   string `json:"reason"`
		Actor    string `json:"actor"`
		TenantID string `json:"tenant_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	newStatus := ""
	switch DecommissionAction(req.Action) {
	case DecommissionDormant:
		newStatus = "dormant"
	case DecommissionRevoke:
		newStatus = "revoked"
	default:
		http.Error(w, "unsupported action", http.StatusBadRequest)
		return
	}
	if err := h.store.UpdateKMIPClientStatus(r.Context(), req.TenantID, id, newStatus); err != nil {
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	_ = h.publishAudit(r.Context(), "audit.kmip.client_"+newStatus, req.TenantID, map[string]any{
		"client_id": id,
		"actor":     req.Actor,
		"reason":    req.Reason,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"client_id":  id,
		"new_status": newStatus,
	})
}
