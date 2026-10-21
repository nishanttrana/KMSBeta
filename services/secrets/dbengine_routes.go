package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/clusterstate"
	"vecta-kms/pkg/credstore"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// Permissions for dynamic database credentials. Defining a role runs SQL as
// the database's administrator, so it is its own permission.
const (
	permDBRead  = "secrets.database.read"
	permDBCreds = "secrets.database.creds"
	permDBAdmin = "secrets.database.admin"
)

func (h *Handler) databaseRoutes() {
	r := h.router
	role := func(action, perm string) route.Spec {
		return route.Spec{Action: action, Permission: perm, Resource: "database_role", TargetParam: "name"}
	}
	lease := func(action, perm string) route.Spec {
		return route.Spec{Action: action, Permission: perm, Resource: "database_lease", TargetParam: "id", Severity: "warning"}
	}
	r.Handle("GET /secrets/database/roles", route.Spec{Action: "database_roles_listed", Permission: permDBRead, Resource: "database_role"}, h.listDBRoles)
	r.Handle("PUT /secrets/database/roles/{name}", warnSpec(role("database_role_saved", permDBAdmin)), h.putDBRole)
	r.Handle("DELETE /secrets/database/roles/{name}", warnSpec(role("database_role_deleted", permDBAdmin)), h.deleteDBRole)
	r.Handle("POST /secrets/database/roles/{name}/creds", warnSpec(role("database_credentials_issued", permDBCreds)), h.issueDBCreds)
	r.Handle("GET /secrets/database/leases", route.Spec{Action: "database_leases_listed", Permission: permDBRead, Resource: "database_lease"}, h.listDBLeases)
	r.Handle("POST /secrets/database/leases/{id}/renew", lease("database_lease_renewed", permDBCreds), h.renewDBLease)
	r.Handle("POST /secrets/database/leases/{id}/revoke", lease("database_lease_revoked", permDBCreds), h.revokeDBLease)
	// Vault / OpenBao database secrets engine: GET creds, leases renew and
	// revoke (lease_id database/creds/<role>/<lease id>).
	vault := func(action, perm string) route.Spec {
		return route.Spec{Action: action, Permission: perm, Resource: "database_lease", TenantHeaders: vaultTenantHeaders, Severity: "warning"}
	}
	r.Handle("GET /v1/database/creds/{name}", vault("vault_database_credentials_issued", permDBCreds), h.vaultDBCreds)
	for _, m := range []string{"PUT", "POST"} {
		r.Handle(m+" /v1/sys/leases/renew", vault("vault_lease_renewed", permDBCreds), h.vaultLeaseRenew)
		r.Handle(m+" /v1/sys/leases/revoke", vault("vault_lease_revoked", permDBCreds), h.vaultLeaseRevoke)
	}
	r.Handle("GET /secrets/credential-usage", route.Spec{Action: "credential_usage_read", Permission: route.Authenticated, Resource: "credential"}, h.credentialUsage)
}

func warnSpec(s route.Spec) route.Spec { s.Severity = "warning"; return s }

// dbFail answers a database-engine error with its status.
func dbFail(c *route.Call, err error) {
	var de dbError
	switch {
	case errors.As(err, &de):
		if de.status < 500 {
			c.Refuse(de.status, de.code, de.msg)
		} else {
			c.Error(de.status, de.code, de.msg)
		}
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, credstore.ErrNotDeployed):
		c.Error(http.StatusConflict, "credentials_not_deployed", err.Error())
	default:
		c.Error(http.StatusInternalServerError, "internal_error", "internal error")
	}
}

func (h *Handler) listDBRoles(c *route.Call) {
	roles, err := h.svc.store.ListDBRoles(c.R.Context(), c.Tenant)
	if err != nil {
		dbFail(c, err)
		return
	}
	items := make([]map[string]interface{}, 0, len(roles))
	for _, r := range roles {
		n, err := h.svc.store.CountActiveDBLeases(c.R.Context(), c.Tenant, r.Name)
		if err != nil {
			dbFail(c, err)
			return
		}
		items = append(items, map[string]interface{}{"role": r, "active_leases": n})
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items, "defaults": map[string]interface{}{"creation_statements": defaultCreation, "revocation_statements": defaultRevocation}})
}

func (h *Handler) putDBRole(c *route.Call) {
	var req struct {
		ConnectionID         string   `json:"connection_id"`
		CreationStatements   []string `json:"creation_statements"`
		RevocationStatements []string `json:"revocation_statements"`
		DefaultTTLSeconds    int      `json:"default_ttl_seconds"`
		MaxTTLSeconds        int      `json:"max_ttl_seconds"`
		TenantID             string   `json:"tenant_id"`
	}
	if !c.Decode(&req) {
		return
	}
	name := strings.TrimSpace(c.R.PathValue("name"))
	if !dbRoleNameRe.MatchString(name) {
		c.Refuse(http.StatusBadRequest, "bad_request", "role name: lowercase letters, digits, '-' and '_', up to 63")
		return
	}
	if req.CreationStatements == nil {
		req.CreationStatements = defaultCreation
	}
	if req.RevocationStatements == nil {
		req.RevocationStatements = defaultRevocation
	}
	if err := checkStatements(req.CreationStatements, req.RevocationStatements); err != nil {
		c.Refuse(http.StatusBadRequest, "bad_statements", err.Error())
		return
	}
	if req.DefaultTTLSeconds < int(dbMinTTL.Seconds()) || req.MaxTTLSeconds < req.DefaultTTLSeconds || req.MaxTTLSeconds > int(dbMaxTTL.Seconds()) {
		c.Refuse(http.StatusBadRequest, "bad_ttl", "default_ttl_seconds at least 60, max_ttl_seconds from the default to 30 days")
		return
	}
	if !credstore.MayAttach(c.R.Context()) {
		c.Refuse(http.StatusForbidden, "credential_use_not_permitted", "attaching a credential needs "+credstore.PermissionUse)
		return
	}
	// The credential is checked by connecting: a role that can't reach its
	// database is refused here, not on the first request.
	conn, err := h.openTarget(c.R.Context(), c.Tenant, req.ConnectionID)
	if err != nil {
		c.Refuse(http.StatusBadRequest, "database_unreachable", "the database could not be reached with this credential: "+err.Error())
		return
	}
	conn.Close(context.Background()) //nolint:errcheck
	role := DBRole{
		TenantID: c.Tenant, Name: name, ConnectionID: req.ConnectionID, Engine: dbEngine,
		CreationStatements: req.CreationStatements, RevocationStatements: req.RevocationStatements,
		DefaultTTLSeconds: req.DefaultTTLSeconds, MaxTTLSeconds: req.MaxTTLSeconds, CreatedBy: c.Actor(),
	}
	if err := h.svc.store.PutDBRole(c.R.Context(), role); err != nil {
		dbFail(c, err)
		return
	}
	c.Detail("connection_id", req.ConnectionID)
	c.JSON(http.StatusOK, map[string]interface{}{"role": role})
}

func (h *Handler) deleteDBRole(c *route.Call) {
	name := c.R.PathValue("name")
	n, err := h.svc.store.CountActiveDBLeases(c.R.Context(), c.Tenant, name)
	if err != nil {
		dbFail(c, err)
		return
	}
	if n > 0 {
		c.Refuse(http.StatusConflict, "role_has_leases", "revoke the role's leases first")
		return
	}
	if err := h.svc.store.DeleteDBRole(c.R.Context(), c.Tenant, name); err != nil {
		dbFail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"deleted": name})
}

func (h *Handler) issueFor(c *route.Call, name string, ttl int) (DBLease, string, bool) {
	role, err := h.svc.store.GetDBRole(c.R.Context(), c.Tenant, name)
	if err != nil {
		dbFail(c, err)
		return DBLease{}, "", false
	}
	lease, password, err := h.issue(c.R.Context(), c.Tenant, role, ttl, c.Actor())
	if err != nil {
		dbFail(c, err)
		return DBLease{}, "", false
	}
	c.Target(lease.ID)
	c.Detail("role", name)
	c.Detail("username", lease.Username)
	c.Detail("expires_at", lease.ExpiresAt.Format(time.RFC3339))
	return lease, password, true
}

func (h *Handler) issueDBCreds(c *route.Call) {
	var req struct {
		TTLSeconds int    `json:"ttl_seconds"`
		TenantID   string `json:"tenant_id"`
	}
	if c.R.ContentLength != 0 && !c.Decode(&req) {
		return
	}
	lease, password, ok := h.issueFor(c, c.R.PathValue("name"), req.TTLSeconds)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"lease": lease, "username": lease.Username, "password": password})
}

func (h *Handler) listDBLeases(c *route.Call) {
	items, err := h.svc.store.ListDBLeases(c.R.Context(), c.Tenant, strings.TrimSpace(c.R.URL.Query().Get("role")), 500)
	if err != nil {
		dbFail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) renewDBLease(c *route.Call) {
	var req struct {
		IncrementSeconds int    `json:"increment_seconds"`
		TenantID         string `json:"tenant_id"`
	}
	if c.R.ContentLength != 0 && !c.Decode(&req) {
		return
	}
	lease, err := h.renew(c.R.Context(), c.Tenant, c.R.PathValue("id"), req.IncrementSeconds)
	if err != nil {
		dbFail(c, err)
		return
	}
	c.Detail("expires_at", lease.ExpiresAt.Format(time.RFC3339))
	c.JSON(http.StatusOK, map[string]interface{}{"lease": lease})
}

func (h *Handler) revokeDBLease(c *route.Call) {
	lease, err := h.svc.store.GetDBLease(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if err != nil {
		dbFail(c, err)
		return
	}
	if lease.State != "active" && lease.State != "revoke_failed" {
		c.Refuse(http.StatusConflict, "lease_ended", "the lease is "+lease.State)
		return
	}
	out, err := h.revoke(c.R.Context(), lease, "revoked")
	if err != nil {
		dbFail(c, err)
		return
	}
	c.Detail("username", out.Username)
	c.JSON(http.StatusOK, map[string]interface{}{"lease": out})
}

// vaultLeaseID is Vault's form, database/creds/<role>/<lease id>.
func vaultLeaseID(l DBLease) string { return "database/creds/" + l.RoleName + "/" + l.ID }

func leaseFromVault(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 {
		return id[i+1:]
	}
	return id
}

func (h *Handler) vaultDBCreds(c *route.Call) {
	lease, password, ok := h.issueFor(c, c.R.PathValue("name"), 0)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{
		"lease_id": vaultLeaseID(lease), "renewable": true, "lease_duration": int(time.Until(lease.ExpiresAt).Seconds()),
		"data": map[string]string{"username": lease.Username, "password": password},
	})
}

func (h *Handler) vaultLeaseRenew(c *route.Call) {
	var req struct {
		LeaseID   string `json:"lease_id"`
		Increment int    `json:"increment"`
	}
	if !c.Decode(&req) {
		return
	}
	lease, err := h.renew(c.R.Context(), c.Tenant, leaseFromVault(req.LeaseID), req.Increment)
	if err != nil {
		dbFail(c, err)
		return
	}
	c.Target(lease.ID)
	c.JSON(http.StatusOK, map[string]interface{}{"lease_id": vaultLeaseID(lease), "renewable": true, "lease_duration": int(time.Until(lease.ExpiresAt).Seconds())})
}

func (h *Handler) vaultLeaseRevoke(c *route.Call) {
	var req struct {
		LeaseID string `json:"lease_id"`
	}
	if !c.Decode(&req) {
		return
	}
	lease, err := h.svc.store.GetDBLease(c.R.Context(), c.Tenant, leaseFromVault(req.LeaseID))
	if err != nil {
		dbFail(c, err)
		return
	}
	c.Target(lease.ID)
	if lease.State == "active" || lease.State == "revoke_failed" {
		if _, err := h.revoke(c.R.Context(), lease, "revoked"); err != nil {
			dbFail(c, err)
			return
		}
	}
	c.W.WriteHeader(http.StatusNoContent)
}

// credentialUsage names the roles using each database credential, for the
// credential store's "used by" and its delete guard. Only compliance asks.
func (h *Handler) credentialUsage(c *route.Call) {
	if !tenantcheck.IsServicePrincipal(c.Claims) || c.Claims.ClientID != "kms-compliance" {
		c.Refuse(http.StatusForbidden, "caller_not_allowed", "only the credential store may call this")
		return
	}
	roles, err := h.svc.store.ListDBRoles(c.R.Context(), c.Tenant)
	if err != nil {
		dbFail(c, err)
		return
	}
	items := []map[string]string{}
	for _, r := range roles {
		items = append(items, map[string]string{"connection_id": r.ConnectionID, "label": "database role " + r.Name})
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

// sweepDBLeases drops the logins of expired leases and retries failed
// revocations. Primary only: it writes replicated rows.
func (h *Handler) sweepDBLeases(ctx context.Context, now time.Time) int {
	if !clusterstate.RunsPrimaryJobs(ctx) {
		return 0
	}
	due, err := h.svc.store.DueDBLeases(ctx, now, 200)
	if err != nil {
		h.logf("database lease sweep: %v", err)
		return 0
	}
	ended := 0
	for _, l := range due {
		out, err := h.revoke(ctx, l, "expired")
		evt := pkgaudit.Event{TenantID: l.TenantID, ActorID: "system:lease-sweep", ActorType: "service", TargetType: "database_lease", TargetID: l.ID,
			Details: map[string]interface{}{"role": l.RoleName, "username": l.Username, "expires_at": l.ExpiresAt.Format(time.RFC3339)}}
		if err != nil {
			evt.Result = "failure"
			evt.Details["reason"] = out.LastError
			evt.Details["severity"] = "warning"
			h.emit(ctx, "database_lease_revoke_failed", evt)
			continue
		}
		evt.Result = "success"
		h.emit(ctx, "database_lease_expired", evt)
		ended++
	}
	return ended
}

func (h *Handler) runDBLeaseSweep(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			h.sweepDBLeases(ctx, now.UTC())
		}
	}
}
