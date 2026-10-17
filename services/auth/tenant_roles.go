package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"vecta-kms/pkg/route"
)

// A user, a group binding, an imported identity or a SCIM default holds one
// of its tenant's roles, never a name the tenant doesn't define: a user given
// an undefined role can't sign in (resolveEffectivePermissions refuses it),
// and the console offers only the roles GET /auth/roles lists.

// tenantIDPattern is what a tenant ID may be; the sign-in form takes the
// same.
var tenantIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// tenantAdminRoles are the roles a new tenant's first administrator may
// hold: the two every tenant is created with that grant "*".
var tenantAdminRoles = map[string]bool{"admin": true, "tenant-admin": true}

const reasonSelfChange = "self_change"

// requireTenantRole fails unless tenantID defines role.
func (h *Handler) requireTenantRole(ctx context.Context, tenantID, role string) error {
	role = strings.TrimSpace(role)
	if role == "" {
		return errors.New("role is required")
	}
	if _, err := h.store.GetRolePermissions(ctx, tenantID, role); errors.Is(err, errNotFound) {
		return fmt.Errorf("role %q is not defined in tenant %s", role, tenantID)
	} else if err != nil {
		return err
	}
	return nil
}

// writeRoleError answers a requireTenantRole failure: 400 for an undefined
// role, 500 for a store failure.
func writeRoleError(w http.ResponseWriter, err error, reqID, tenantID string) {
	if strings.Contains(err.Error(), "is not defined") || strings.Contains(err.Error(), "is required") {
		writeErr(w, http.StatusBadRequest, "unknown_role", err.Error(), reqID, tenantID)
		return
	}
	writeErr(w, http.StatusInternalServerError, "store_error", "failed to read roles", reqID, tenantID)
}

func (h *Handler) rolesRouter() *route.Router {
	r := route.New("auth", kernelEmitter{h}, h.logger)
	// PlatformScoped: the handler resolves the tenant, so that a platform
	// administrator can read another tenant's roles and nobody else can.
	r.Handle("GET /auth/roles", route.Spec{Action: "roles_listed", Permission: "auth.user.read", Resource: "role", Tenancy: route.PlatformScoped}, h.listRoles)
	return r
}

// listRoles lists the roles a tenant defines, with their permissions.
func (h *Handler) listRoles(c *route.Call) {
	tenantID := strings.TrimSpace(c.R.URL.Query().Get("tenant_id"))
	if tenantID == "" {
		tenantID = strings.TrimSpace(c.Claims.TenantID)
	}
	c.Detail("target_tenant", tenantID)
	if !strings.EqualFold(tenantID, strings.TrimSpace(c.Claims.TenantID)) && !platformAdministrator(c.Claims, "auth.tenant.read") {
		c.Refuse(http.StatusForbidden, reasonNotPlatformAdmin, "reading another tenant's roles requires an administrator of the platform (root) tenant")
		return
	}
	roles, err := h.store.ListTenantRoles(c.R.Context(), tenantID)
	if err != nil {
		c.Error(http.StatusInternalServerError, "store_error", "failed to list roles")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"items": roles, "tenant_id": tenantID})
}

type tenantAdminInput struct {
	Username, Email, Password, Role, Status string
	MustChangePassword                      *bool
}

// tenantInputError is a create request the platform refuses as given.
type tenantInputError struct {
	status int
	code   string
	msg    string
}

func (e tenantInputError) Error() string { return e.msg }

func badTenantInput(msg string) error {
	return tenantInputError{status: http.StatusBadRequest, code: "bad_request", msg: msg}
}

// createTenant creates a tenant with its default roles and, when any admin
// field is given, its first administrator. Everything is checked before
// anything is written, and a failure part-way removes the tenant again, so
// a refused request can be corrected and sent again under the same ID.
func (h *Handler) createTenant(ctx context.Context, t Tenant, admin tenantAdminInput) (string, error) {
	if !tenantIDPattern.MatchString(t.ID) {
		return "", badTenantInput("tenant id must be 1-64 letters, digits, '-' or '_'")
	}
	if t.Name == "" {
		return "", badTenantInput("tenant name is required")
	}
	if _, err := h.store.GetTenant(ctx, t.ID); err == nil {
		return "", tenantInputError{status: http.StatusConflict, code: "tenant_exists", msg: "tenant " + t.ID + " already exists"}
	} else if !errors.Is(err, errNotFound) {
		return "", err
	}
	withAdmin := strings.TrimSpace(admin.Username) != "" || strings.TrimSpace(admin.Email) != "" || strings.TrimSpace(admin.Password) != ""
	if withAdmin {
		if strings.TrimSpace(admin.Username) == "" || strings.TrimSpace(admin.Email) == "" || strings.TrimSpace(admin.Password) == "" {
			return "", badTenantInput("admin_username, admin_email and admin_password are required to create tenant admin")
		}
		if role := strings.TrimSpace(admin.Role); role != "" && !tenantAdminRoles[role] {
			return "", badTenantInput("admin_role must be admin or tenant-admin")
		}
		// The new tenant has no policy yet, so this is the default it will
		// start with.
		if err := h.enforcePasswordPolicy(ctx, t.ID, strings.TrimSpace(admin.Password), admin.Username, admin.Email); err != nil {
			return "", badTenantInput(err.Error())
		}
	}
	if err := h.store.CreateTenant(ctx, t); err != nil {
		return "", err
	}
	userID, err := "", h.ensureTenantDefaults(ctx, t.ID)
	if err == nil && withAdmin {
		userID, err = h.createTenantAdminUser(ctx, t.ID, admin.Username, admin.Email, admin.Password, admin.Role, admin.Status, admin.MustChangePassword)
	}
	if err != nil {
		if _, rollbackErr := h.store.DeleteTenant(ctx, t.ID); rollbackErr != nil && h.logger != nil {
			h.logger.Printf("tenant %s: create failed and its removal failed too: %v", t.ID, rollbackErr)
		}
		return "", err
	}
	return userID, nil
}
