package main

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// handleListGuardians handles GET /ceremony/guardians
func (h *Handler) handleListGuardians(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListCeremonyGuardians(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_guardians_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

// handleCreateGuardian handles POST /ceremony/guardians
func (h *Handler) handleCreateGuardian(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req CreateGuardianRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name is required", reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.Email) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "email is required", reqID, tenantID)
		return
	}
	role := strings.TrimSpace(req.Role)
	if role == "" {
		role = "guardian"
	}
	g := CeremonyGuardian{
		ID:       newID("cg"),
		TenantID: tenantID,
		Name:     strings.TrimSpace(req.Name),
		Email:    strings.TrimSpace(req.Email),
		Role:     role,
		Status:   "active",
	}
	created, err := h.svc.store.CreateCeremonyGuardian(r.Context(), g)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_guardian_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"guardian": created, "request_id": reqID})
}

// handleDeleteGuardian handles DELETE /ceremony/guardians/{id}
func (h *Handler) handleDeleteGuardian(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	if err := h.svc.store.DeleteCeremonyGuardian(r.Context(), tenantID, r.PathValue("id")); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "delete_guardian_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "request_id": reqID})
}

// handleListCeremonies handles GET /ceremony
func (h *Handler) handleListCeremonies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	items, err := h.svc.store.ListCeremonies(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_ceremonies_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "request_id": reqID})
}

// handleGetCeremony handles GET /ceremony/{id}
func (h *Handler) handleGetCeremony(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	c, err := h.svc.store.GetCeremony(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "get_ceremony_failed", err.Error(), reqID, tenantID)
		return
	}

	// Compute quorum info.
	submitted := 0
	for _, sh := range c.Shares {
		if sh.Status == "submitted" || sh.Status == "verified" {
			submitted++
		}
	}
	quorumReached := submitted >= c.Threshold

	writeJSON(w, http.StatusOK, map[string]any{
		"ceremony":       c,
		"quorum_reached": quorumReached,
		"shares_submitted": submitted,
		"request_id":     reqID,
	})
}

// handleCreateCeremony handles POST /ceremony
func (h *Handler) handleCreateCeremony(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	var req CreateCeremonyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name is required", reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.Type) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "type is required", reqID, tenantID)
		return
	}
	if req.Threshold <= 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "threshold must be > 0", reqID, tenantID)
		return
	}
	if req.TotalShares <= 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "total_shares must be > 0", reqID, tenantID)
		return
	}
	if req.Threshold > req.TotalShares {
		writeErr(w, http.StatusBadRequest, "bad_request", "threshold cannot exceed total_shares", reqID, tenantID)
		return
	}

	// Resolve guardian names.
	var guardians []CeremonyGuardian
	if len(req.GuardianIDs) > 0 {
		all, err := h.svc.store.ListCeremonyGuardians(r.Context(), tenantID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "create_ceremony_failed", err.Error(), reqID, tenantID)
			return
		}
		guardians = all
	}

	// Resolve createdBy from actor context.
	actor := accessActorFromContext(r.Context())
	createdBy := strings.TrimSpace(actor.UserID)
	if createdBy == "" {
		createdBy = strings.TrimSpace(actor.Username)
	}
	if createdBy == "" {
		createdBy = "api"
	}

	c := Ceremony{
		ID:          newID("cer"),
		TenantID:    tenantID,
		Name:        strings.TrimSpace(req.Name),
		Type:        strings.TrimSpace(req.Type),
		Threshold:   req.Threshold,
		TotalShares: req.TotalShares,
		Status:      "draft",
		KeyID:       strings.TrimSpace(req.KeyID),
		Notes:       req.Notes,
		CreatedBy:   createdBy,
	}

	created, err := h.svc.store.CreateCeremony(r.Context(), c, req.GuardianIDs, guardians)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_ceremony_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ceremony": created, "request_id": reqID})
}

// handleSubmitShare handles POST /ceremony/{id}/shares
func (h *Handler) handleSubmitShare(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	ceremonyID := r.PathValue("id")

	var req SubmitShareRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if strings.TrimSpace(req.GuardianID) == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "guardian_id is required", reqID, tenantID)
		return
	}

	if err := h.svc.store.SubmitCeremonyShare(r.Context(), tenantID, ceremonyID, req.GuardianID); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "submit_share_failed", err.Error(), reqID, tenantID)
		return
	}

	// Re-fetch ceremony to report quorum status.
	c, err := h.svc.store.GetCeremony(r.Context(), tenantID, ceremonyID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "submitted", "request_id": reqID})
		return
	}
	submitted := 0
	for _, sh := range c.Shares {
		if sh.Status == "submitted" || sh.Status == "verified" {
			submitted++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "submitted",
		"quorum_reached":   submitted >= c.Threshold,
		"shares_submitted": submitted,
		"threshold":        c.Threshold,
		"request_id":       reqID,
	})
}

// handleCompleteCeremony handles POST /ceremony/{id}/complete
func (h *Handler) handleCompleteCeremony(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	ceremonyID := r.PathValue("id")

	// Verify quorum before completing.
	c, err := h.svc.store.GetCeremony(r.Context(), tenantID, ceremonyID)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "complete_ceremony_failed", err.Error(), reqID, tenantID)
		return
	}

	submitted := 0
	for _, sh := range c.Shares {
		if sh.Status == "submitted" || sh.Status == "verified" {
			submitted++
		}
	}
	if submitted < c.Threshold {
		writeErr(w, http.StatusConflict, "quorum_not_reached",
			"insufficient shares submitted to meet threshold", reqID, tenantID)
		return
	}

	now := time.Now().UTC()
	if err := h.svc.store.UpdateCeremonyStatus(r.Context(), tenantID, ceremonyID, "completed", &now); err != nil {
		writeErr(w, http.StatusInternalServerError, "complete_ceremony_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "completed", "request_id": reqID})
}

// handleAbortCeremony handles POST /ceremony/{id}/abort
func (h *Handler) handleAbortCeremony(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	ceremonyID := r.PathValue("id")

	now := time.Now().UTC()
	if err := h.svc.store.UpdateCeremonyStatus(r.Context(), tenantID, ceremonyID, "aborted", &now); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, errStoreNotFound) {
			code = http.StatusNotFound
		}
		writeErr(w, code, "abort_ceremony_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "aborted", "request_id": reqID})
}
