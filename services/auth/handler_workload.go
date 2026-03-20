package main

import (
	"net/http"
	"os"
	"strings"
	"time"
)

func (h *Handler) handleIssueWorkloadToken(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	sharedSecret := strings.TrimSpace(os.Getenv("WORKLOAD_IDENTITY_SHARED_SECRET"))
	providedSecret := strings.TrimSpace(r.Header.Get("X-Workload-Identity-Secret"))
	if sharedSecret == "" || providedSecret == "" || sharedSecret != providedSecret {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid workload identity service secret", reqID, "")
		return
	}

	var req struct {
		TenantID            string   `json:"tenant_id"`
		ClientID            string   `json:"client_id"`
		SubjectID           string   `json:"subject_id"`
		InterfaceName       string   `json:"interface_name"`
		Permissions         []string `json:"permissions"`
		AllowedKeyIDs       []string `json:"allowed_key_ids"`
		WorkloadTrustDomain string   `json:"workload_trust_domain"`
		TTLSeconds          int      `json:"ttl_seconds"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error(), reqID, strings.TrimSpace(req.TenantID))
		return
	}

	req.TenantID = strings.TrimSpace(req.TenantID)
	req.ClientID = strings.TrimSpace(req.ClientID)
	req.SubjectID = strings.TrimSpace(req.SubjectID)
	req.InterfaceName = strings.TrimSpace(req.InterfaceName)
	req.WorkloadTrustDomain = strings.TrimSpace(req.WorkloadTrustDomain)
	if req.TenantID == "" || req.ClientID == "" || req.SubjectID == "" || req.InterfaceName == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "tenant_id, client_id, subject_id, and interface_name are required", reqID, req.TenantID)
		return
	}
	if !strings.HasPrefix(strings.ToLower(req.SubjectID), "spiffe://") {
		writeErr(w, http.StatusBadRequest, "bad_request", "subject_id must be a SPIFFE ID", reqID, req.TenantID)
		return
	}
	if len(req.Permissions) == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "at least one permission is required", reqID, req.TenantID)
		return
	}
	ttl := 5 * time.Minute
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	token, expiresAt, err := h.logic.IssueWorkloadJWT(
		req.TenantID,
		req.ClientID,
		req.SubjectID,
		req.InterfaceName,
		req.Permissions,
		req.AllowedKeyIDs,
		req.WorkloadTrustDomain,
		ttl,
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token_issue_failed", "failed to issue workload token", reqID, req.TenantID)
		return
	}
	_ = h.publishAudit(r.Context(), "audit.auth.workload_token_issued", reqID, req.TenantID, map[string]any{
		"client_id":             req.ClientID,
		"subject_id":            req.SubjectID,
		"interface_name":        req.InterfaceName,
		"permission_count":      len(req.Permissions),
		"allowed_key_id_count":  len(req.AllowedKeyIDs),
		"workload_trust_domain": req.WorkloadTrustDomain,
		"ttl_seconds":           int(time.Until(expiresAt).Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_at":   expiresAt.Format(time.RFC3339Nano),
		"request_id":   reqID,
	})
}
