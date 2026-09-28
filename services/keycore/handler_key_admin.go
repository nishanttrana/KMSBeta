package main

import (
	"net/http"

	"vecta-kms/pkg/route"
)

// keyAdminRouter puts keycore's key-management writes behind the route
// kernel (4.0.0-beta). Until then they were on the raw mux with no
// permission check: any verified token, including a readonly user's, could
// make a key exportable, drop its approval requirement, rotate or destroy it.
//
// The handlers themselves are unchanged, and the service methods keep their
// domain events (audit.key.rotated, audit.key.export_policy_updated, ...)
// because the rotation scheduler, playbooks and other jobs call the same
// methods. The kernel adds authentication, the tenant check (including a
// tenant_id in the body, which POST /keys trusted before), the permission,
// and a request event audit.key.<action>_requested that is emitted for
// refusals and failures too. Moving the handler bodies onto route.Call is
// the rest of keycore's migration (docs/ARCHITECTURE_MIGRATION.md).
//
// Crypto operations stay on the per-key grants in enforceKeyAccess.
func (h *Handler) keyAdminRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	add := func(pattern, action, perm, target, severity string, fn http.HandlerFunc) {
		r.Handle(pattern, route.Spec{
			Action: action + "_requested", Permission: perm, Resource: "key", TargetParam: target, Severity: severity,
		}, func(c *route.Call) { fn(c.W, c.R) })
	}
	add("POST /keys", "create", "key.create", "", "", h.handleCreateKey)
	add("POST /keys/import", "import", "key.import", "", "warning", h.handleImportKey)
	add("POST /keys/form", "form", "key.form", "", "warning", h.handleFormKey)
	add("POST /keys/bulk-import", "bulk_import", "key.import", "", "warning", h.handleBulkImport)
	add("POST /keys/bulk-rotate", "bulk_rotate", "key.rotate", "", "warning", h.handleBulkRotate)
	add("POST /keys/bulk-delete", "bulk_delete", "key.destroy", "", "critical", h.handleBulkDelete)
	add("PUT /keys/{id}", "update", "key.update", "id", "", h.handleUpdateKey)
	add("POST /keys/{id}/rotate", "rotate", "key.rotate", "id", "warning", h.handleRotateKey)
	add("POST /keys/{id}/activate", "activate", "key.activate", "id", "", h.handleActivateKey)
	add("POST /keys/{id}/deactivate", "deactivate", "key.deactivate", "id", "warning", h.handleDeactivateKey)
	add("POST /keys/{id}/disable", "disable", "key.disable", "id", "warning", h.handleDisableKey)
	add("POST /keys/{id}/destroy", "destroy", "key.destroy", "id", "critical", h.handleDestroyKey)
	add("PUT /keys/{id}/export-policy", "export_policy_update", "key.export_policy_update", "id", "warning", h.handleSetExportPolicy)
	add("POST /keys/{id}/versions/{ver}/activate", "version_activate", "key.activate", "id", "", h.handleActivateVersion)
	add("POST /keys/{id}/versions/{ver}/deactivate", "version_deactivate", "key.deactivate", "id", "warning", h.handleDeactivateVersion)
	add("DELETE /keys/{id}/versions/{ver}", "version_delete", "key.destroy", "id", "critical", h.handleDeleteVersion)
	add("PUT /keys/{id}/usage/limit", "usage_limit_update", "key.usage_limit_update", "id", "", h.handleSetUsageLimit)
	add("POST /keys/{id}/usage/reset", "usage_reset", "key.usage_limit_update", "id", "warning", h.handleResetUsage)
	add("PUT /keys/{id}/approval", "approval_update", "key.approval_update", "id", "warning", h.handleSetApproval)
	add("PUT /keys/{id}/iv-mode", "iv_mode_update", "key.update", "id", "", h.handleSetIVMode)
	add("POST /tags", "tag_upsert", "key.tags.write", "", "", h.handleUpsertTag)
	add("DELETE /tags/{name}", "tag_delete", "key.tags.write", "name", "", h.handleDeleteTag)
	return r
}
