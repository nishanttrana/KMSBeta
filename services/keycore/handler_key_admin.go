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
	r.Handle("POST /keys", route.Spec{Action: "create_requested", Permission: "key.create", Resource: "key"}, legacy(h.handleCreateKey))
	r.Handle("POST /keys/import", route.Spec{Action: "import_requested", Permission: "key.import", Resource: "key", Severity: "warning"}, legacy(h.handleImportKey))
	r.Handle("POST /keys/form", route.Spec{Action: "form_requested", Permission: "key.form", Resource: "key", Severity: "warning"}, legacy(h.handleFormKey))
	r.Handle("POST /keys/bulk-import", route.Spec{Action: "bulk_import_requested", Permission: "key.import", Resource: "key", Severity: "warning"}, legacy(h.handleBulkImport))
	r.Handle("POST /keys/bulk-rotate", route.Spec{Action: "bulk_rotate_requested", Permission: "key.rotate", Resource: "key", Severity: "warning"}, legacy(h.handleBulkRotate))
	r.Handle("POST /keys/bulk-delete", route.Spec{Action: "bulk_delete_requested", Permission: "key.destroy", Resource: "key", Severity: "critical"}, legacy(h.handleBulkDelete))
	r.Handle("PUT /keys/{id}", route.Spec{Action: "update_requested", Permission: "key.update", Resource: "key", TargetParam: "id"}, legacy(h.handleUpdateKey))
	r.Handle("POST /keys/{id}/rotate", route.Spec{Action: "rotate_requested", Permission: "key.rotate", Resource: "key", TargetParam: "id", Severity: "warning"}, legacy(h.handleRotateKey))
	r.Handle("POST /keys/{id}/activate", route.Spec{Action: "activate_requested", Permission: "key.activate", Resource: "key", TargetParam: "id"}, legacy(h.handleActivateKey))
	r.Handle("POST /keys/{id}/deactivate", route.Spec{Action: "deactivate_requested", Permission: "key.deactivate", Resource: "key", TargetParam: "id", Severity: "warning"}, legacy(h.handleDeactivateKey))
	r.Handle("POST /keys/{id}/disable", route.Spec{Action: "disable_requested", Permission: "key.disable", Resource: "key", TargetParam: "id", Severity: "warning"}, legacy(h.handleDisableKey))
	r.Handle("POST /keys/{id}/destroy", route.Spec{Action: "destroy_requested", Permission: "key.destroy", Resource: "key", TargetParam: "id", Severity: "critical"}, legacy(h.handleDestroyKey))
	r.Handle("PUT /keys/{id}/export-policy", route.Spec{Action: "export_policy_update_requested", Permission: "key.export_policy_update", Resource: "key", TargetParam: "id", Severity: "warning"}, legacy(h.handleSetExportPolicy))
	r.Handle("POST /keys/{id}/versions/{ver}/activate", route.Spec{Action: "version_activate_requested", Permission: "key.activate", Resource: "key", TargetParam: "id"}, legacy(h.handleActivateVersion))
	r.Handle("POST /keys/{id}/versions/{ver}/deactivate", route.Spec{Action: "version_deactivate_requested", Permission: "key.deactivate", Resource: "key", TargetParam: "id", Severity: "warning"}, legacy(h.handleDeactivateVersion))
	r.Handle("DELETE /keys/{id}/versions/{ver}", route.Spec{Action: "version_delete_requested", Permission: "key.destroy", Resource: "key", TargetParam: "id", Severity: "critical"}, legacy(h.handleDeleteVersion))
	r.Handle("PUT /keys/{id}/usage/limit", route.Spec{Action: "usage_limit_update_requested", Permission: "key.usage_limit_update", Resource: "key", TargetParam: "id"}, legacy(h.handleSetUsageLimit))
	r.Handle("POST /keys/{id}/usage/reset", route.Spec{Action: "usage_reset_requested", Permission: "key.usage_limit_update", Resource: "key", TargetParam: "id", Severity: "warning"}, legacy(h.handleResetUsage))
	r.Handle("PUT /keys/{id}/approval", route.Spec{Action: "approval_update_requested", Permission: "key.approval_update", Resource: "key", TargetParam: "id", Severity: "warning"}, legacy(h.handleSetApproval))
	r.Handle("PUT /keys/{id}/iv-mode", route.Spec{Action: "iv_mode_update_requested", Permission: "key.update", Resource: "key", TargetParam: "id"}, legacy(h.handleSetIVMode))
	r.Handle("POST /tags", route.Spec{Action: "tag_upsert_requested", Permission: "key.tags.write", Resource: "key"}, legacy(h.handleUpsertTag))
	r.Handle("DELETE /tags/{name}", route.Spec{Action: "tag_delete_requested", Permission: "key.tags.write", Resource: "key", TargetParam: "name"}, legacy(h.handleDeleteTag))
	return r
}

// legacy runs a pre-kernel handler under the kernel: the kernel has already
// authenticated the caller, checked the tenant and the permission, and will
// emit the route's event from the status the handler writes.
func legacy(fn http.HandlerFunc) func(*route.Call) {
	return func(c *route.Call) { fn(c.W, c.R) }
}
