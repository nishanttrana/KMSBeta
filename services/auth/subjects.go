package main

import (
	"errors"
	"net/http"
	"strings"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// subjectsCaller is the one service that may ask whether users, roles and
// clients exist in a tenant: secrets checks the subject of an access rule
// before storing it (docs/SECURITY/SECRET_ACCESS.md).
const subjectsCaller = "kms-secrets"

const maxSubjectsPerCheck = 600

type subjectRef struct {
	Type string `json:"type"` // user | role | client
	ID   string `json:"id"`
}

type subjectResult struct {
	subjectRef
	Exists bool `json:"exists"`
	// Label is the user's username or the client's name, for display.
	Label string `json:"label,omitempty"`
}

// subjectsRouter answers whether users, roles and clients exist in a
// tenant, to the secrets service identity only. It returns existence and a
// display name, nothing else about the account.
func (h *Handler) subjectsRouter() *route.Router {
	r := route.New("auth", kernelEmitter{h}, h.logger)
	r.Handle("POST /internal/subjects/check", route.Spec{Action: "subjects_checked", Permission: route.Authenticated, Resource: "tenant", Tenancy: route.PlatformScoped}, h.checkSubjects)
	return r
}

func (h *Handler) checkSubjects(c *route.Call) {
	if !tenantcheck.IsServicePrincipal(c.Claims) || c.Claims.ClientID != subjectsCaller {
		c.Refuse(http.StatusForbidden, reasonServiceIdentityRequired, "only the secrets service may check subjects")
		return
	}
	var req struct {
		TenantID string       `json:"tenant_id"`
		Subjects []subjectRef `json:"subjects"`
	}
	if !c.Decode(&req) {
		return
	}
	tenant := strings.TrimSpace(req.TenantID)
	if tenant == "" || len(req.Subjects) > maxSubjectsPerCheck {
		c.Error(http.StatusBadRequest, "bad_request", "tenant_id is required and at most 600 subjects may be checked at once")
		return
	}
	c.Target(tenant)
	c.Detail("count", len(req.Subjects))
	ctx := c.R.Context()
	users, err := h.store.ListUsers(ctx, tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "store_error", "failed to read users")
		return
	}
	out := make([]subjectResult, 0, len(req.Subjects))
	for _, s := range req.Subjects {
		res := subjectResult{subjectRef: s}
		id := strings.TrimSpace(s.ID)
		switch s.Type {
		case "user":
			for _, u := range users {
				if u.ID == id {
					res.Exists, res.Label = true, u.Username
				}
			}
		case "role":
			// A role exists if the tenant defines it or one of its users holds it
			// (built-in roles are not rows in the tenant's role table).
			if _, err := h.store.GetRolePermissions(ctx, tenant, id); err == nil {
				res.Exists = true
			} else if !errors.Is(err, errNotFound) {
				c.Error(http.StatusInternalServerError, "store_error", "failed to read roles")
				return
			}
			for _, u := range users {
				res.Exists = res.Exists || u.Role == id
			}
		case "client":
			reg, err := h.store.GetClientRegistration(ctx, tenant, id)
			if err == nil {
				res.Exists, res.Label = true, reg.ClientName
			} else if !errors.Is(err, errNotFound) {
				c.Error(http.StatusInternalServerError, "store_error", "failed to read clients")
				return
			}
		default:
			c.Error(http.StatusBadRequest, "bad_request", "subject type must be user, role or client")
			return
		}
		out = append(out, res)
	}
	c.JSON(http.StatusOK, map[string]interface{}{"subjects": out})
}
