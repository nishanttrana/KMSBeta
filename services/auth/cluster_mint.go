package main

import (
	"net/http"
	"strings"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/tenantcheck"
)

// POST /auth/cluster/mint (docs/CLUSTERING.md, slice 3).
//
// On a primary, the cluster-manager forwards a member's lifecycle write. The
// member verified the caller's token with its own key; this mints an
// equivalent short-lived token signed by this primary so its services accept
// it natively. Only the cluster-manager service identity may call it (it
// authenticates the member with its per-member credential first). A member
// that could forge identities here already holds the master key and all
// replicated data, so the trust boundary does not widen. Every mint is audited.

const clusterManagerClientID = "kms-cluster-manager"

func (h *Handler) handleClusterMint(w http.ResponseWriter, r *http.Request) {
	reqID := requestID(r)
	refuse := func(status int, code, msg, tenantID, caller, node string) {
		_ = h.publishAudit(r.Context(), "audit.auth.cluster_mint_refused", reqID, tenantID, map[string]any{
			"reason": code, "caller": caller, "forwarded_by": node, "severity": "warning", "result": "refused",
			"description": "a forwarded-token mint was refused",
		})
		writeErr(w, status, code, msg, reqID, tenantID)
	}
	raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
	caller, err := h.logic.ParseJWT(raw)
	if err != nil || !tenantcheck.IsServicePrincipal(caller) || caller.ClientID != clusterManagerClientID {
		callerID := ""
		if caller != nil {
			callerID = caller.ClientID + caller.UserID
		}
		refuse(http.StatusForbidden, "service_identity_required", "only the cluster-manager service identity may mint forwarded tokens", "", callerID, "")
		return
	}
	var req struct {
		Claims      pkgauth.Claims `json:"claims"`
		ForwardedBy string         `json:"forwarded_by"`
	}
	if err := decodeJSON(r, &req); err != nil {
		refuse(http.StatusBadRequest, "bad_request", err.Error(), "", caller.ClientID, "")
		return
	}
	src := req.Claims
	node := strings.TrimSpace(req.ForwardedBy)
	switch {
	case node == "":
		refuse(http.StatusBadRequest, "bad_request", "forwarded_by is required", src.TenantID, caller.ClientID, node)
		return
	case strings.TrimSpace(src.TenantID) == "" || strings.TrimSpace(src.Role) == "":
		refuse(http.StatusBadRequest, "bad_request", "claims need tenant_id and role", src.TenantID, caller.ClientID, node)
		return
	case src.MustChangePassword:
		refuse(http.StatusForbidden, "password_change_required", "the user must change their password before making changes", src.TenantID, caller.ClientID, node)
		return
	}
	token, exp, err := h.logic.IssueForwardedJWT(&src, node)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "mint_failed", err.Error(), reqID, src.TenantID)
		return
	}
	severity := "info"
	if tenantcheck.IsServicePrincipal(&src) {
		severity = "warning" // a member's service identity acting on the primary
	}
	_ = h.publishAudit(r.Context(), "audit.auth.cluster_token_minted", reqID, src.TenantID, map[string]any{
		"forwarded_by": node, "user_id": src.UserID, "client_id": src.ClientID, "role": src.Role,
		"expires_at": exp, "severity": severity, "result": "success",
		"description": "short-lived token minted for a write forwarded from a cluster member",
	})
	writeJSON(w, http.StatusOK, map[string]any{"access_token": token, "expires_at": exp, "request_id": reqID})
}
