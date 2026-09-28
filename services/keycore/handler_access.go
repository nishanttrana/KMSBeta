package main

import (
	"errors"
	"net/http"
	"strings"

	"vecta-kms/pkg/route"
)

// Key access management through the route kernel (4.0.0-beta). Before this,
// these routes sat on the raw mux with no permission check, and tokenless
// requests reached them: any caller could rewrite a key's grants, the
// tenant's groups and access settings. Permissions:
//
//	key.access.read    read grants, groups, settings, interface config
//	key.access.manage  change one key's grants, as its creator or an admin
//	key.access.admin   tenant-wide: groups, settings, interface policies,
//	                   interface ports and their TLS defaults
//
// The actor recorded is always the verified token's; the old updated_by and
// created_by body fields are gone (CLAUDE.md rule 4). The kernel emits every
// event, refusals included, under the subjects the service used to publish.
func (h *Handler) accessRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	read := func(action, resource string) route.Spec {
		return route.Spec{Action: action, Permission: "key.access.read", Resource: resource}
	}
	admin := func(action, resource, target string) route.Spec {
		return route.Spec{Action: action, Permission: "key.access.admin", Resource: resource, TargetParam: target, Severity: "warning"}
	}
	r.Handle("GET /keys/{id}/access-policy", route.Spec{Action: "access_policy_read", Permission: "key.access.read", Resource: "key", TargetParam: "id"}, h.getKeyAccessPolicy)
	r.Handle("PUT /keys/{id}/access-policy", route.Spec{Action: "access_policy_updated", Permission: "key.access.manage", Resource: "key", TargetParam: "id", Severity: "warning"}, h.putKeyAccessPolicy)
	r.Handle("GET /access/groups", read("access_groups_listed", "access_group"), h.listAccessGroups)
	r.Handle("POST /access/groups", admin("access_group_created", "access_group", ""), h.createAccessGroup)
	r.Handle("DELETE /access/groups/{id}", admin("access_group_deleted", "access_group", "id"), h.deleteAccessGroup)
	r.Handle("PUT /access/groups/{id}/members", admin("access_group_members_updated", "access_group", "id"), h.setAccessGroupMembers)
	r.Handle("GET /access/settings", read("access_settings_read", "access_settings"), h.getAccessSettings)
	r.Handle("PUT /access/settings", admin("access_settings_updated", "access_settings", ""), h.putAccessSettings)
	r.Handle("GET /access/interface-policies", read("interface_policies_listed", "interface_policy"), h.listInterfacePolicies)
	r.Handle("POST /access/interface-policies", admin("interface_policy_upserted", "interface_policy", ""), h.upsertInterfacePolicy)
	r.Handle("DELETE /access/interface-policies/{id}", admin("interface_policy_deleted", "interface_policy", "id"), h.deleteInterfacePolicy)
	r.Handle("GET /access/interface-tls-config", read("interface_tls_config_read", "interface_tls_config"), h.getInterfaceTLSConfig)
	r.Handle("PUT /access/interface-tls-config", admin("interface_tls_config_updated", "interface_tls_config", ""), h.putInterfaceTLSConfig)
	r.Handle("GET /access/interface-ports", read("interface_ports_listed", "interface_port"), h.listInterfacePorts)
	r.Handle("POST /access/interface-ports", admin("interface_port_upserted", "interface_port", ""), h.upsertInterfacePort)
	r.Handle("DELETE /access/interface-ports/{name}", admin("interface_port_deleted", "interface_port", "name"), h.deleteInterfacePort)
	return r
}

// actorOf is the verified identity the kernel resolved for c.
func actorOf(c *route.Call) string {
	if a := c.Actor(); a != "" {
		return a
	}
	return "unknown"
}

// storeErr writes err as 404 for a missing record, else as status.
func storeErr(c *route.Call, err error, status int, code string) {
	if errors.Is(err, errStoreNotFound) {
		c.Error(http.StatusNotFound, "not_found", err.Error())
		return
	}
	c.Error(status, code, err.Error())
}

func (h *Handler) getKeyAccessPolicy(c *route.Call) {
	policy, err := h.svc.GetKeyAccessPolicy(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		storeErr(c, err, http.StatusInternalServerError, "key_access_policy_failed")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"policy": policy})
}

func (h *Handler) putKeyAccessPolicy(c *route.Call) {
	var req struct {
		Grants []KeyAccessGrant `json:"grants"`
	}
	if !c.Decode(&req) {
		return
	}
	err := h.svc.ReplaceKeyAccessPolicy(c.R.Context(), c.Tenant, c.R.PathValue("id"), req.Grants, actorOf(c))
	var refusal *accessRefusal
	var approval approvalRequiredError
	switch {
	case errors.As(err, &refusal):
		c.Refuse(http.StatusForbidden, refusal.reason, refusal.msg)
	case errors.As(err, &approval):
		c.Detail("approval_request_id", approval.RequestID)
		c.JSON(http.StatusAccepted, map[string]interface{}{"status": "pending_approval", "approval_request_id": approval.RequestID})
	case err != nil:
		storeErr(c, err, http.StatusBadRequest, "key_access_policy_update_failed")
	default:
		c.Detail("grant_count", len(req.Grants))
		c.Detail("grants", req.Grants)
		c.JSON(http.StatusOK, map[string]interface{}{"status": "ok"})
	}
}

func (h *Handler) listAccessGroups(c *route.Call) {
	items, err := h.svc.ListAccessGroups(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_access_groups_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) createAccessGroup(c *route.Call) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !c.Decode(&req) {
		return
	}
	group, err := h.svc.CreateAccessGroup(c.R.Context(), c.Tenant, req.Name, req.Description, actorOf(c))
	if err != nil {
		c.Error(http.StatusBadRequest, "create_access_group_failed", err.Error())
		return
	}
	c.Target(group.ID)
	c.Detail("name", group.Name)
	c.JSON(http.StatusCreated, map[string]interface{}{"group": group})
}

func (h *Handler) deleteAccessGroup(c *route.Call) {
	if err := h.svc.DeleteAccessGroup(c.R.Context(), c.Tenant, c.R.PathValue("id")); err != nil {
		storeErr(c, err, http.StatusBadRequest, "delete_access_group_failed")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "ok"})
}

func (h *Handler) setAccessGroupMembers(c *route.Call) {
	var req struct {
		UserIDs []string `json:"user_ids"`
		Members []string `json:"members"`
	}
	if !c.Decode(&req) {
		return
	}
	userIDs := req.UserIDs
	if len(userIDs) == 0 {
		userIDs = req.Members
	}
	members, err := h.svc.SetAccessGroupMembers(c.R.Context(), c.Tenant, c.R.PathValue("id"), userIDs)
	if err != nil {
		storeErr(c, err, http.StatusBadRequest, "set_access_group_members_failed")
		return
	}
	c.Detail("user_count", len(members))
	c.Detail("member_user", members)
	c.JSON(http.StatusOK, map[string]interface{}{"status": "ok"})
}

func (h *Handler) getAccessSettings(c *route.Call) {
	settings, err := h.svc.GetKeyAccessSettings(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "access_settings_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"settings": settings})
}

func (h *Handler) putAccessSettings(c *route.Call) {
	current, err := h.svc.GetKeyAccessSettings(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "access_settings_failed", err.Error())
		return
	}
	// The dashboard sends back the settings it read, so the read-only fields
	// are accepted and ignored; updated_by is always the verified actor.
	var req struct {
		DenyByDefault                  *bool  `json:"deny_by_default"`
		RequireApprovalForPolicyChange *bool  `json:"require_approval_for_policy_change"`
		GrantDefaultTTLMinutes         *int   `json:"grant_default_ttl_minutes"`
		GrantMaxTTLMinutes             *int   `json:"grant_max_ttl_minutes"`
		EnforceSignedRequests          *bool  `json:"enforce_signed_requests"`
		ReplayWindowSeconds            *int   `json:"replay_window_seconds"`
		NonceTTLSeconds                *int   `json:"nonce_ttl_seconds"`
		RequireInterfacePolicies       *bool  `json:"require_interface_policies"`
		TenantID                       string `json:"tenant_id"`
		UpdatedBy                      string `json:"updated_by"`
		UpdatedAt                      string `json:"updated_at"`
	}
	if !c.Decode(&req) {
		return
	}
	setBool := func(dst *bool, v *bool) {
		if v != nil {
			*dst = *v
		}
	}
	setInt := func(dst *int, v *int) {
		if v != nil {
			*dst = *v
		}
	}
	setBool(&current.DenyByDefault, req.DenyByDefault)
	setBool(&current.RequireApprovalForPolicyChange, req.RequireApprovalForPolicyChange)
	setInt(&current.GrantDefaultTTLMinutes, req.GrantDefaultTTLMinutes)
	setInt(&current.GrantMaxTTLMinutes, req.GrantMaxTTLMinutes)
	setBool(&current.EnforceSignedRequests, req.EnforceSignedRequests)
	setInt(&current.ReplayWindowSeconds, req.ReplayWindowSeconds)
	setInt(&current.NonceTTLSeconds, req.NonceTTLSeconds)
	setBool(&current.RequireInterfacePolicies, req.RequireInterfacePolicies)
	current.TenantID = c.Tenant
	current.UpdatedBy = actorOf(c)
	out, err := h.svc.UpdateKeyAccessSettings(c.R.Context(), current)
	if err != nil {
		c.Error(http.StatusBadRequest, "access_settings_update_failed", err.Error())
		return
	}
	c.Detail("deny_by_default", out.DenyByDefault)
	c.Detail("require_approval_for_policy_change", out.RequireApprovalForPolicyChange)
	c.Detail("grant_default_ttl_minutes", out.GrantDefaultTTLMinutes)
	c.Detail("grant_max_ttl_minutes", out.GrantMaxTTLMinutes)
	c.Detail("enforce_signed_requests", out.EnforceSignedRequests)
	c.Detail("replay_window_seconds", out.ReplayWindowSeconds)
	c.Detail("nonce_ttl_seconds", out.NonceTTLSeconds)
	c.Detail("require_interface_policies", out.RequireInterfacePolicies)
	c.JSON(http.StatusOK, map[string]interface{}{"settings": out})
}

func (h *Handler) listInterfacePolicies(c *route.Call) {
	items, err := h.svc.ListKeyInterfaceSubjectPolicies(c.R.Context(), c.Tenant, strings.TrimSpace(c.R.URL.Query().Get("interface")))
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_interface_policies_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) upsertInterfacePolicy(c *route.Call) {
	var req KeyInterfaceSubjectPolicy
	if !c.Decode(&req) {
		return
	}
	req.TenantID, req.CreatedBy = c.Tenant, actorOf(c)
	out, err := h.svc.UpsertKeyInterfaceSubjectPolicy(c.R.Context(), req)
	if err != nil {
		c.Error(http.StatusBadRequest, "upsert_interface_policy_failed", err.Error())
		return
	}
	c.Target(out.ID)
	c.Detail("interface_name", out.InterfaceName)
	c.Detail("subject_type", out.SubjectType)
	c.Detail("subject_id", out.SubjectID)
	c.Detail("operations", out.Operations)
	c.Detail("enabled", out.Enabled)
	c.JSON(http.StatusOK, map[string]interface{}{"policy": out})
}

func (h *Handler) deleteInterfacePolicy(c *route.Call) {
	if err := h.svc.DeleteKeyInterfaceSubjectPolicy(c.R.Context(), c.Tenant, c.R.PathValue("id")); err != nil {
		storeErr(c, err, http.StatusBadRequest, "delete_interface_policy_failed")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "ok"})
}

func (h *Handler) getInterfaceTLSConfig(c *route.Call) {
	cfg, err := h.svc.GetKeyInterfaceTLSConfig(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "get_interface_tls_config_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"config": cfg})
}

func (h *Handler) putInterfaceTLSConfig(c *route.Call) {
	var req KeyInterfaceTLSConfig
	if !c.Decode(&req) {
		return
	}
	req.TenantID, req.UpdatedBy = c.Tenant, actorOf(c)
	out, err := h.svc.UpdateKeyInterfaceTLSConfig(c.R.Context(), req)
	if err != nil {
		c.Error(http.StatusBadRequest, "put_interface_tls_config_failed", err.Error())
		return
	}
	c.Detail("certificate_source", out.CertSource)
	c.Detail("ca_id", out.CAID)
	c.Detail("certificate_id", out.CertificateID)
	c.JSON(http.StatusOK, map[string]interface{}{"config": out})
}

func (h *Handler) listInterfacePorts(c *route.Call) {
	items, err := h.svc.ListKeyInterfacePorts(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "list_interface_ports_failed", err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) upsertInterfacePort(c *route.Call) {
	var req KeyInterfacePort
	if !c.Decode(&req) {
		return
	}
	req.TenantID, req.UpdatedBy = c.Tenant, actorOf(c)
	out, err := h.svc.UpsertKeyInterfacePort(c.R.Context(), req)
	if err != nil {
		c.Error(http.StatusBadRequest, "upsert_interface_port_failed", err.Error())
		return
	}
	c.Target(out.InterfaceName)
	c.Detail("bind_address", out.BindAddress)
	c.Detail("port", out.Port)
	c.Detail("protocol", out.Protocol)
	c.Detail("pqc_mode", out.PQCMode)
	c.Detail("cert_source", out.CertSource)
	c.Detail("ca_id", out.CAID)
	c.Detail("certificate_id", out.CertificateID)
	c.Detail("enabled", out.Enabled)
	c.JSON(http.StatusOK, map[string]interface{}{"item": out})
}

func (h *Handler) deleteInterfacePort(c *route.Call) {
	if err := h.svc.DeleteKeyInterfacePort(c.R.Context(), c.Tenant, c.R.PathValue("name")); err != nil {
		storeErr(c, err, http.StatusBadRequest, "delete_interface_port_failed")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"status": "ok"})
}
