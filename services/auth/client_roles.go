package main

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// A role for a REST client (13.53.0-beta; docs/CI_CD_AUTOMATION.md "A role
// for a client"). By default a client's tokens hold kms.read and kms.write:
// secrets and signing, no key. An administrator may grant the client one of
// the tenant's roles; its tokens then hold that role's permissions as they
// are when each token is issued. The administrator must hold every
// permission the role grants, so granting a role can't raise anyone's
// access. In keycore a key grant can then name the client (subject_type
// "client").

const reasonRoleExceedsCaller = "role_exceeds_caller"

func (s *SQLStore) GetClientRole(ctx context.Context, tenantID, clientID string) (string, error) {
	var role string
	err := s.db.SQL().QueryRowContext(ctx, `SELECT role_name FROM auth_client_roles WHERE tenant_id = $1 AND client_id = $2`, tenantID, clientID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return role, err
}

func (s *SQLStore) SetClientRole(ctx context.Context, tenantID, clientID, role, by string, at time.Time) error {
	_, err := s.db.SQL().ExecContext(ctx, `
INSERT INTO auth_client_roles (tenant_id, client_id, role_name, granted_by, granted_at) VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (tenant_id, client_id) DO UPDATE SET role_name = EXCLUDED.role_name, granted_by = EXCLUDED.granted_by, granted_at = EXCLUDED.granted_at`,
		tenantID, clientID, role, by, at.UTC())
	return err
}

func (s *SQLStore) DeleteClientRole(ctx context.Context, tenantID, clientID string) error {
	_, err := s.db.SQL().ExecContext(ctx, `DELETE FROM auth_client_roles WHERE tenant_id = $1 AND client_id = $2`, tenantID, clientID)
	return err
}

func (h *Handler) clientRoleRoutes(r *route.Router) {
	r.Handle("GET /auth/clients/{id}/role", route.Spec{Action: "client_role_read", Permission: "auth.client.read", Resource: "client", TargetParam: "id"}, h.getClientRole)
	r.Handle("PUT /auth/clients/{id}/role", route.Spec{Action: "client_role_set", Permission: "auth.client.write", Resource: "client", TargetParam: "id", Severity: "warning"}, h.setClientRole)
}

// clientTokenPermissions is what a client's next token may hold: its role's
// permissions now, or the default client permissions without a role.
func (h *Handler) clientTokenPermissions(ctx context.Context, tenantID, clientID string, keyPerms []string) ([]string, string, error) {
	role, err := h.store.GetClientRole(ctx, tenantID, clientID)
	if err != nil || role == "" {
		return keyPerms, "", err
	}
	perms, err := h.store.GetRolePermissions(ctx, tenantID, role)
	if errors.Is(err, errNotFound) {
		// The role was deleted: the client holds nothing until an
		// administrator grants another or clears it.
		return nil, role, nil
	}
	return perms, role, err
}

func (h *Handler) getClientRole(c *route.Call) {
	reg, err := h.store.GetClientRegistration(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	if errors.Is(err, errNotFound) {
		c.Error(http.StatusNotFound, "not_found", "client not found")
		return
	} else if err != nil {
		c.Error(http.StatusInternalServerError, "store_error", "failed to read client")
		return
	}
	perms, role, err := h.clientTokenPermissions(c.R.Context(), c.Tenant, reg.ID, clientKeyPermissions)
	if err != nil {
		c.Error(http.StatusInternalServerError, "store_error", "failed to read the client's role")
		return
	}
	sort.Strings(perms)
	c.JSON(http.StatusOK, map[string]interface{}{"client_id": reg.ID, "role": role, "permissions": perms, "requested_role": reg.RequestedRole})
}

func (h *Handler) setClientRole(c *route.Call) {
	var in struct {
		Role string `json:"role"`
	}
	if !c.Decode(&in) {
		return
	}
	reg, ok := h.clientForAdmin(c)
	if !ok {
		return
	}
	role := strings.TrimSpace(in.Role)
	c.Detail("role", role)
	if reg.Status == "revoked" {
		c.Refuse(http.StatusConflict, reasonClientState, "a revoked client is not given a role")
		return
	}
	ctx := c.R.Context()
	if role == "" {
		if err := h.store.DeleteClientRole(ctx, c.Tenant, reg.ID); err != nil {
			c.Error(http.StatusInternalServerError, "store_error", "failed to clear the role")
			return
		}
		c.Detail("permissions", clientKeyPermissions)
		c.JSON(http.StatusOK, map[string]interface{}{"client_id": reg.ID, "role": "", "permissions": clientKeyPermissions})
		return
	}
	perms, err := h.store.GetRolePermissions(ctx, c.Tenant, role)
	if errors.Is(err, errNotFound) {
		c.Refuse(http.StatusBadRequest, "role_not_found", "no role "+role+" in this tenant")
		return
	} else if err != nil {
		c.Error(http.StatusInternalServerError, "store_error", "failed to read the role")
		return
	}
	var missing []string
	for _, p := range perms {
		if tenantcheck.ServicePermissionReserved(p) || !route.Allowed(c.Claims, p) || tenantcheck.IsServicePrincipal(c.Claims) {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		c.Detail("missing_permissions", missing)
		c.Refuse(http.StatusForbidden, reasonRoleExceedsCaller, "you can't grant a role with permissions you don't hold: "+strings.Join(missing, ", "))
		return
	}
	if err := h.store.SetClientRole(ctx, c.Tenant, reg.ID, role, c.Actor(), time.Now().UTC().Truncate(time.Microsecond)); err != nil {
		c.Error(http.StatusInternalServerError, "store_error", "failed to set the role")
		return
	}
	sort.Strings(perms)
	c.Detail("permissions", perms)
	c.JSON(http.StatusOK, map[string]interface{}{"client_id": reg.ID, "role": role, "permissions": perms})
}
