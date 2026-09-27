package main

import (
	"net/http"
	"strings"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/tenantcheck"
)

// Access levels for the approval API.
const (
	approvalRead  = "read"  // list/read requests and policies
	approvalWrite = "write" // create or cancel a request, vote
	approvalAdmin = "admin" // create, change or delete a policy
)

// approvalCaller authenticates a caller of the approval API and enforces its
// tenant. Every route needs a verified token: a user or client of the tenant,
// or a platform service principal acting for it (hyok, keycore and autokey
// open requests on a user's behalf). Policy changes need a tenant
// administrator. Only the email-link vote and page skip this; their one-time
// token is the credential. Every refusal is audited.
func (h *Handler) approvalCaller(w http.ResponseWriter, r *http.Request, reqID, tenantID, level string) (*pkgauth.Claims, bool) {
	tenantID = strings.TrimSpace(tenantID)
	claims, ok := pkgauth.ClaimsFromContext(r.Context())
	switch {
	case !ok || claims == nil:
		h.refuseApproval(w, r, reqID, tenantID, http.StatusUnauthorized, "unauthorized", "authentication_required", "a bearer token is required")
	case tenantID == "":
		h.refuseApproval(w, r, reqID, tenantID, http.StatusBadRequest, "bad_request", "tenant_required", "tenant_id is required")
	case tenantcheck.Enforce(r, tenantID) != nil:
		h.refuseApproval(w, r, reqID, tenantID, http.StatusForbidden, "forbidden", "tenant_mismatch", "tenant_id does not match authenticated token")
	case level == approvalAdmin && (tenantcheck.IsServicePrincipal(claims) || !claimsAllowSystemAdmin(claims, true)):
		h.refuseApproval(w, r, reqID, tenantID, http.StatusForbidden, "forbidden", "insufficient_privileges", "changing approval policies requires a tenant administrator")
	default:
		return claims, true
	}
	return nil, false
}

// callerIsUser reports whether the caller is a person, not a service.
func callerIsUser(claims *pkgauth.Claims) bool {
	return claims != nil && strings.TrimSpace(claims.UserID) != "" && !tenantcheck.IsServicePrincipal(claims)
}

func (h *Handler) refuseApproval(w http.ResponseWriter, r *http.Request, reqID, tenantID string, status int, code, reason, message string) {
	writeErr(w, status, code, message, reqID, tenantID)
	actor, authenticated := "unauthenticated", false
	if claims, ok := pkgauth.ClaimsFromContext(r.Context()); ok && claims != nil {
		actor, authenticated = firstNonEmptyString(claims.UserID, claims.ClientID, claims.Subject), true
	}
	_ = h.svc.publishAudit(r.Context(), "audit.governance.approval_refused", tenantID, map[string]interface{}{
		"route":         r.Method + " " + r.URL.Path,
		"reason":        reason,
		"message":       message,
		"result":        "refused",
		"severity":      "warning",
		"status":        status,
		"actor":         actor,
		"authenticated": authenticated,
		"request_id":    reqID,
	})
}

func requestTenant(r *http.Request) string {
	return firstNonEmpty(strings.TrimSpace(r.URL.Query().Get("tenant_id")), strings.TrimSpace(r.Header.Get("X-Tenant-ID")))
}

// approverEmail resolves the authenticated user's own email. Services have
// no approval queue and cannot vote.
func (h *Handler) approverEmail(w http.ResponseWriter, r *http.Request, reqID, tenantID string, claims *pkgauth.Claims) (string, bool) {
	if !callerIsUser(claims) {
		h.refuseApproval(w, r, reqID, tenantID, http.StatusForbidden, "forbidden", "not_a_user", "approving needs a user account")
		return "", false
	}
	email, err := h.svc.store.UserEmail(r.Context(), tenantID, claims.UserID)
	if err != nil {
		h.refuseApproval(w, r, reqID, tenantID, http.StatusForbidden, "forbidden", "no_user_email", "your account has no email to approve as")
		return "", false
	}
	return email, true
}

// bindRequester fixes who a request is from. A user is who their token says;
// they cannot pick their approvers or make governance call a service. Only a
// platform service principal (opening a request for the user it serves) may
// name the requester, extra approver emails and a completion callback.
func (h *Handler) bindRequester(r *http.Request, claims *pkgauth.Claims, in *CreateApprovalRequestInput) {
	if tenantcheck.IsServicePrincipal(claims) {
		return
	}
	in.RequesterID = firstNonEmpty(claims.UserID, claims.ClientID)
	in.RequesterEmail = ""
	if callerIsUser(claims) {
		if email, err := h.svc.store.UserEmail(r.Context(), in.TenantID, claims.UserID); err == nil {
			in.RequesterEmail = email
		}
	}
	delete(in.TargetDetails, "approver_emails")
	in.CallbackService, in.CallbackAction, in.CallbackPayload = "", "", nil
}
