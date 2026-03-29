package main

import (
	"net/http"
	"strings"
	"time"
)

func (h *Handler) handleListEscrowGuardians(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	guardians, err := h.svc.store.ListEscrowGuardians(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_guardians_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": guardians})
}

func (h *Handler) handleAddEscrowGuardian(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req struct {
		TenantID             string `json:"tenant_id"`
		Name                 string `json:"name"`
		Email                string `json:"email"`
		Organization         string `json:"organization"`
		NotaryCertFingerprint string `json:"notary_cert_fingerprint"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = mustTenant(r, reqID, w)
		if tenantID == "" {
			return
		}
	}
	if req.Name == "" || req.Email == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name and email are required", reqID, tenantID)
		return
	}
	g := EscrowGuardian{
		ID:                    newID("eguard"),
		TenantID:              tenantID,
		Name:                  req.Name,
		Email:                 req.Email,
		Organization:          req.Organization,
		NotaryCertFingerprint: req.NotaryCertFingerprint,
		Status:                "active",
	}
	created, err := h.svc.store.AddEscrowGuardian(r.Context(), g)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "add_guardian_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": created})
}

func (h *Handler) handleListEscrowPolicies(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	policies, err := h.svc.store.ListEscrowPolicies(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_policies_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": policies})
}

func (h *Handler) handleCreateEscrowPolicy(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req struct {
		TenantID    string   `json:"tenant_id"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		KeyFilter   string   `json:"key_filter"`
		Threshold   int      `json:"threshold"`
		GuardianIDs []string `json:"guardian_ids"`
		LegalHold   bool     `json:"legal_hold"`
		Jurisdiction string  `json:"jurisdiction"`
		Enabled     bool     `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = mustTenant(r, reqID, w)
		if tenantID == "" {
			return
		}
	}
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "name is required", reqID, tenantID)
		return
	}
	threshold := req.Threshold
	if threshold <= 0 {
		threshold = 2
	}
	guardianIDs := req.GuardianIDs
	if guardianIDs == nil {
		guardianIDs = []string{}
	}
	p := EscrowPolicy{
		ID:           newID("epol"),
		TenantID:     tenantID,
		Name:         req.Name,
		Description:  req.Description,
		KeyFilter:    req.KeyFilter,
		Threshold:    threshold,
		GuardianIDs:  guardianIDs,
		LegalHold:    req.LegalHold,
		Jurisdiction: req.Jurisdiction,
		Enabled:      req.Enabled,
	}
	created, err := h.svc.store.CreateEscrowPolicy(r.Context(), p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_policy_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": created})
}

func (h *Handler) handleListEscrowedKeys(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	keys, err := h.svc.store.ListEscrowedKeys(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_escrowed_keys_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": keys})
}

func (h *Handler) handleAddEscrowedKey(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req struct {
		TenantID    string   `json:"tenant_id"`
		PolicyID    string   `json:"policy_id"`
		PolicyName  string   `json:"policy_name"`
		KeyID       string   `json:"key_id"`
		KeyName     string   `json:"key_name"`
		Algorithm   string   `json:"algorithm"`
		GuardianIDs []string `json:"guardian_ids"`
		EscrowedBy  string   `json:"escrowed_by"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, "")
		return
	}
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = mustTenant(r, reqID, w)
		if tenantID == "" {
			return
		}
	}
	if req.PolicyID == "" || req.KeyID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "policy_id and key_id are required", reqID, tenantID)
		return
	}
	guardianIDs := req.GuardianIDs
	if guardianIDs == nil {
		guardianIDs = []string{}
	}
	escrowedBy := req.EscrowedBy
	if escrowedBy == "" {
		escrowedBy = "admin"
	}
	ek := EscrowedKey{
		ID:          newID("ekey"),
		TenantID:    tenantID,
		PolicyID:    req.PolicyID,
		PolicyName:  req.PolicyName,
		KeyID:       req.KeyID,
		KeyName:     req.KeyName,
		Algorithm:   req.Algorithm,
		GuardianIDs: guardianIDs,
		EscrowedBy:  escrowedBy,
	}
	created, err := h.svc.store.AddEscrowedKey(r.Context(), ek)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "escrow_key_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": created})
}

func (h *Handler) handleListRecoveryRequests(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	requests, err := h.svc.store.ListRecoveryRequests(r.Context(), tenantID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list_recovery_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": requests})
}

func (h *Handler) handleCreateRecoveryRequest(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	var req struct {
		TenantID         string `json:"tenant_id"`
		EscrowID         string `json:"escrow_id"`
		KeyID            string `json:"key_id"`
		KeyName          string `json:"key_name"`
		Requestor        string `json:"requestor"`
		Reason           string `json:"reason"`
		LegalReference   string `json:"legal_reference"`
		RequiredApprovals int   `json:"required_approvals"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, req.TenantID)
		return
	}
	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = mustTenant(r, reqID, w)
		if tenantID == "" {
			return
		}
	}
	if req.EscrowID == "" || req.Reason == "" || req.Requestor == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "escrow_id, requestor, and reason are required", reqID, tenantID)
		return
	}
	required := req.RequiredApprovals
	if required <= 0 {
		required = 2
	}
	rr := RecoveryRequest{
		ID:                newID("recov"),
		TenantID:          tenantID,
		EscrowID:          req.EscrowID,
		KeyID:             req.KeyID,
		KeyName:           req.KeyName,
		Requestor:         req.Requestor,
		Reason:            req.Reason,
		LegalReference:    req.LegalReference,
		RequiredApprovals: required,
	}
	created, err := h.svc.store.CreateRecoveryRequest(r.Context(), rr)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create_recovery_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": created})
}

func (h *Handler) handleApproveRecovery(w http.ResponseWriter, r *http.Request) {
	h.handleRecoveryDecision(w, r, "approved")
}

func (h *Handler) handleDenyRecovery(w http.ResponseWriter, r *http.Request) {
	h.handleRecoveryDecision(w, r, "denied")
}

func (h *Handler) handleRecoveryDecision(w http.ResponseWriter, r *http.Request, decision string) {
	reqID := requestID(r)
	tenantID := mustTenant(r, reqID, w)
	if tenantID == "" {
		return
	}
	recoveryID := strings.TrimSpace(r.PathValue("id"))
	if recoveryID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "recovery request id is required", reqID, tenantID)
		return
	}

	var body struct {
		GuardianID string `json:"guardian_id"`
		Notes      string `json:"notes"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, tenantID)
		return
	}
	if body.GuardianID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "guardian_id is required", reqID, tenantID)
		return
	}

	existing, err := h.svc.store.GetRecoveryRequest(r.Context(), tenantID, recoveryID)
	if err != nil {
		if err == errStoreNotFound {
			writeErr(w, http.StatusNotFound, "not_found", "recovery request not found", reqID, tenantID)
			return
		}
		writeErr(w, http.StatusInternalServerError, "get_recovery_failed", err.Error(), reqID, tenantID)
		return
	}
	if existing.Status != "pending" {
		writeErr(w, http.StatusConflict, "already_decided", "recovery request is no longer pending", reqID, tenantID)
		return
	}

	// Check for duplicate guardian vote.
	for _, a := range existing.Approvals {
		if a.GuardianID == body.GuardianID {
			writeErr(w, http.StatusConflict, "already_voted", "guardian has already voted on this request", reqID, tenantID)
			return
		}
	}

	newApproval := RecoveryApproval{
		GuardianID: body.GuardianID,
		Decision:   decision,
		DecidedAt:  time.Now().UTC(),
		Notes:      body.Notes,
	}
	approvals := append(existing.Approvals, newApproval)

	// Determine new status.
	approveCount := 0
	denyCount := 0
	for _, a := range approvals {
		switch a.Decision {
		case "approved":
			approveCount++
		case "denied":
			denyCount++
		}
	}

	newStatus := "pending"
	if denyCount > 0 {
		newStatus = "denied"
	} else if approveCount >= existing.RequiredApprovals {
		newStatus = "approved"
	}

	updated, err := h.svc.store.UpdateRecoveryRequestStatus(r.Context(), tenantID, recoveryID, newStatus, approvals)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "update_recovery_failed", err.Error(), reqID, tenantID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": updated})
}
