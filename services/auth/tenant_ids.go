package main

import (
	"net/http"
	"strings"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// tenantIDsCaller is the one service that may enumerate tenants: reporting
// raises alerts from audit for every tenant on a schedule, including one
// that has never used reporting.
const tenantIDsCaller = "kms-reporting"

// tenantIDsRouter serves the active tenant IDs (no names or other fields) to
// the reporting service identity only.
func (h *Handler) tenantIDsRouter() *route.Router {
	r := route.New("auth", kernelEmitter{h}, h.logger)
	r.Handle("GET /internal/tenant-ids", route.Spec{Action: "tenant_ids_listed", Permission: route.Authenticated, Resource: "tenant", Tenancy: route.PlatformScoped}, h.listTenantIDs)
	return r
}

func (h *Handler) listTenantIDs(c *route.Call) {
	if !tenantcheck.IsServicePrincipal(c.Claims) || c.Claims.ClientID != tenantIDsCaller {
		c.Refuse(http.StatusForbidden, reasonServiceIdentityRequired, "only the reporting service may list tenants")
		return
	}
	items, err := h.store.ListTenants(c.R.Context())
	if err != nil {
		c.Error(http.StatusInternalServerError, "store_error", "failed to list tenants")
		return
	}
	ids := make([]string, 0, len(items))
	for _, t := range items {
		if strings.EqualFold(t.Status, "active") || t.Status == "" {
			ids = append(ids, t.ID)
		}
	}
	c.Detail("count", len(ids))
	c.JSON(http.StatusOK, map[string]interface{}{"items": ids})
}
