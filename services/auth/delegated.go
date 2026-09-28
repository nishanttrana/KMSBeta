package main

import (
	"context"
	"errors"
	"net/http"
	"strings"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// Delegated operations let a compliance playbook act for the person who
// authorized it, with that person's current rights (docs/DECISIONS.md,
// 2026-09-28). Only the kms-compliance service identity may call these
// routes. Auth, which owns users and roles, re-checks the named person at the
// moment of the call: they must exist in the tenant, be active and hold the
// permission the operation needs. The person is a delegation to verify, not
// an identity taken from the request: the caller is verified by its token,
// and nothing is done that the named person couldn't do themselves.
// Platform service identities, the delegator themself and the last full
// administrator are never targets.

const delegatingService = "kms-compliance"

// Refusal reasons for delegated operations.
const (
	reasonServiceIdentityRequired = "service_identity_required"
	reasonDelegatorUnknown        = "delegator_unknown"
	reasonDelegatorInactive       = "delegator_inactive"
	reasonDelegatorLacks          = "delegator_lacks_permission"
	reasonSelfTarget              = "self_target"
	reasonLastAdministrator       = "last_administrator"
	reasonServiceIdentityTarget   = "service_identity_protected"
)

type delegation struct {
	TenantID      string `json:"tenant_id"` // verified by the kernel
	OnBehalfOf    string `json:"on_behalf_of"`
	Reason        string `json:"reason"`
	PlaybookRunID string `json:"playbook_run_id"`
}

// kernelEmitter sends kernel events through auth's unified audit client,
// resolved per call so it can be wired after the routes are built.
type kernelEmitter struct{ h *Handler }

func (e kernelEmitter) Emit(ctx context.Context, action string, evt pkgaudit.Event) error {
	if e.h.kernelAudit == nil {
		return nil
	}
	return e.h.kernelAudit.Emit(ctx, action, evt)
}

// SetAuditClient wires the unified audit client used by kernel routes.
func (h *Handler) SetAuditClient(c *pkgaudit.Client) {
	if c != nil {
		h.kernelAudit = c
	}
}

func (h *Handler) delegatedRouter() *route.Router {
	r := route.New("auth", kernelEmitter{h}, h.logger)
	spec := func(action, resource, target string) route.Spec {
		return route.Spec{Action: action, Permission: route.Authenticated, Resource: resource, TargetParam: target, Severity: "warning"}
	}
	r.Handle("POST /auth/delegated/authority", route.Spec{Action: "delegated_authority_checked", Permission: route.Authenticated, Resource: "user"}, h.delegatedAuthority)
	r.Handle("POST /auth/delegated/users/{id}/disable", spec("delegated_user_disabled", "user", "id"), h.delegatedDisableUser)
	r.Handle("POST /auth/delegated/api-keys/{id}/revoke", spec("delegated_api_key_revoked", "api_key", "id"), h.delegatedRevokeAPIKey)
	r.Handle("POST /auth/delegated/clients/{id}/revoke", spec("delegated_client_revoked", "client", "id"), h.delegatedRevokeClient)
	return r
}

// mountKernel serves r's routes on mux with the bearer token verified into
// the request context (auth has no global JWT middleware: its legacy routes
// parse the token themselves).
func (h *Handler) mountKernel(mux *http.ServeMux, r *route.Router) {
	verified := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if raw := strings.TrimSpace(strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer")); raw != "" && h.logic != nil {
			if claims, err := h.logic.ParseJWT(raw); err == nil {
				req = req.WithContext(pkgauth.ContextWithClaims(req.Context(), claims))
			}
		}
		r.ServeHTTP(w, req)
	})
	for _, rt := range r.Routes() {
		mux.Handle(rt.Pattern, verified)
	}
}

func delegationCaller(c *route.Call) bool {
	if tenantcheck.IsServicePrincipal(c.Claims) && c.Claims.ClientID == delegatingService {
		return true
	}
	c.Refuse(http.StatusForbidden, reasonServiceIdentityRequired, "only the compliance service may act on a person's behalf")
	return false
}

// delegatorHolds checks that userID is an active user of the tenant holding
// perm now.
func (h *Handler) delegatorHolds(c *route.Call, userID, perm string) (User, bool) {
	c.Detail("on_behalf_of", userID)
	c.Detail("permission", perm)
	user, err := h.store.GetUserByID(c.R.Context(), c.Tenant, strings.TrimSpace(userID))
	if err != nil || strings.TrimSpace(userID) == "" {
		c.Refuse(http.StatusForbidden, reasonDelegatorUnknown, "the delegating user is not a user of this tenant")
		return User{}, false
	}
	if normalizeUserStatus(user.Status) != "active" {
		c.Refuse(http.StatusForbidden, reasonDelegatorInactive, "the delegating user is not active")
		return User{}, false
	}
	perms, err := h.resolveEffectivePermissions(c.R.Context(), c.Tenant, user.ID, user.Role)
	if err != nil || !route.Allowed(&pkgauth.Claims{Permissions: perms}, perm) {
		c.Refuse(http.StatusForbidden, reasonDelegatorLacks, "the delegating user no longer holds "+perm)
		return User{}, false
	}
	return user, true
}

func (h *Handler) decodeDelegation(c *route.Call) (delegation, bool) {
	var d delegation
	if !c.Decode(&d) {
		return d, false
	}
	if d.PlaybookRunID != "" {
		c.Detail("playbook_run_id", d.PlaybookRunID)
	}
	if d.Reason != "" {
		c.Detail("reason_given", d.Reason)
	}
	c.Detail("via", delegatingService)
	return d, true
}

// delegatedAuthority reports whether a user is active and which of the
// given permissions they no longer hold. Playbooks ask before every
// automatic run, so a person who lost a permission stops their playbooks.
func (h *Handler) delegatedAuthority(c *route.Call) {
	if !delegationCaller(c) {
		return
	}
	var in struct {
		TenantID    string   `json:"tenant_id"`
		UserID      string   `json:"user_id"`
		Permissions []string `json:"permissions"`
	}
	if !c.Decode(&in) {
		return
	}
	c.Target(in.UserID)
	out := map[string]interface{}{"active": false, "missing": in.Permissions}
	user, err := h.store.GetUserByID(c.R.Context(), c.Tenant, strings.TrimSpace(in.UserID))
	if err == nil && normalizeUserStatus(user.Status) == "active" {
		perms, err := h.resolveEffectivePermissions(c.R.Context(), c.Tenant, user.ID, user.Role)
		if err != nil {
			c.Error(http.StatusInternalServerError, "internal_error", "resolve permissions failed")
			return
		}
		held := &pkgauth.Claims{Permissions: perms}
		missing := []string{}
		for _, p := range in.Permissions {
			if !route.Allowed(held, p) {
				missing = append(missing, p)
			}
		}
		out["active"], out["missing"] = true, missing
	} else if err != nil && !errors.Is(err, errNotFound) {
		c.Error(http.StatusInternalServerError, "internal_error", "read user failed")
		return
	}
	c.Detail("active", out["active"])
	c.Detail("missing", out["missing"])
	c.JSON(http.StatusOK, out)
}

func (h *Handler) delegatedDisableUser(c *route.Call) {
	if !delegationCaller(c) {
		return
	}
	d, ok := h.decodeDelegation(c)
	if !ok {
		return
	}
	delegator, ok := h.delegatorHolds(c, d.OnBehalfOf, "auth.user.write")
	if !ok {
		return
	}
	ctx := c.R.Context()
	targetID := c.R.PathValue("id")
	if targetID == delegator.ID {
		c.Refuse(http.StatusConflict, reasonSelfTarget, "a playbook can't disable the user it acts for")
		return
	}
	target, err := h.store.GetUserByID(ctx, c.Tenant, targetID)
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "user not found")
		return
	} else if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "read user failed")
		return
	}
	if last, err := h.lastAdministrator(ctx, c.Tenant, target); err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "check administrators failed")
		return
	} else if last {
		c.Refuse(http.StatusConflict, reasonLastAdministrator, "disabling this user would leave the tenant without an active administrator")
		return
	}
	if err := h.store.UpdateUserStatus(ctx, c.Tenant, target.ID, "inactive"); err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "update user failed")
		return
	}
	c.Detail("username", target.Username)
	c.JSON(http.StatusOK, map[string]interface{}{"status": "disabled", "user_id": target.ID})
}

// lastAdministrator reports whether target is the tenant's only active user
// with full permissions ("*").
func (h *Handler) lastAdministrator(ctx context.Context, tenant string, target User) (bool, error) {
	full := func(u User) (bool, error) {
		perms, err := h.resolveEffectivePermissions(ctx, tenant, u.ID, u.Role)
		if err != nil {
			return false, nil // an unresolvable role grants nothing
		}
		for _, p := range perms {
			if p == "*" {
				return true, nil
			}
		}
		return false, nil
	}
	if ok, _ := full(target); !ok || normalizeUserStatus(target.Status) != "active" {
		return false, nil
	}
	users, err := h.store.ListUsers(ctx, tenant)
	if err != nil {
		return false, err
	}
	for _, u := range users {
		if u.ID == target.ID || normalizeUserStatus(u.Status) != "active" {
			continue
		}
		if ok, _ := full(u); ok {
			return false, nil
		}
	}
	return true, nil
}

func serviceIdentityName(id string) bool { return strings.HasPrefix(strings.TrimSpace(id), "kms-") }

func (h *Handler) delegatedRevokeAPIKey(c *route.Call) {
	if !delegationCaller(c) {
		return
	}
	d, ok := h.decodeDelegation(c)
	if !ok {
		return
	}
	if _, ok := h.delegatorHolds(c, d.OnBehalfOf, "auth.api_key.write"); !ok {
		return
	}
	ctx := c.R.Context()
	key, err := h.store.GetAPIKeyByID(ctx, c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "api key not found")
		return
	} else if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "read api key failed")
		return
	}
	if serviceIdentityName(key.ClientID) || len(tenantcheck.StripReserved(key.Permissions)) != len(key.Permissions) {
		c.Refuse(http.StatusConflict, reasonServiceIdentityTarget, "a platform service identity's key can't be revoked by a playbook")
		return
	}
	if err := h.store.DeleteAPIKey(ctx, c.Tenant, key.ID); err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "revoke api key failed")
		return
	}
	c.Detail("key_owner", firstNonEmpty(key.UserID, key.ClientID))
	c.JSON(http.StatusOK, map[string]interface{}{"status": "revoked", "api_key_id": key.ID})
}

func (h *Handler) delegatedRevokeClient(c *route.Call) {
	if !delegationCaller(c) {
		return
	}
	d, ok := h.decodeDelegation(c)
	if !ok {
		return
	}
	if _, ok := h.delegatorHolds(c, d.OnBehalfOf, "auth.client.write"); !ok {
		return
	}
	ctx := c.R.Context()
	reg, err := h.store.GetClientRegistration(ctx, c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "client not found")
		return
	} else if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "read client failed")
		return
	}
	if serviceIdentityName(reg.ID) || serviceIdentityName(reg.ClientName) {
		c.Refuse(http.StatusConflict, reasonServiceIdentityTarget, "a platform service identity can't be revoked by a playbook")
		return
	}
	if err := h.store.RevokeClientRegistration(ctx, c.Tenant, reg.ID); err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "revoke client failed")
		return
	}
	c.Detail("client_name", reg.ClientName)
	c.JSON(http.StatusOK, map[string]interface{}{"status": "revoked", "client_id": reg.ID})
}
