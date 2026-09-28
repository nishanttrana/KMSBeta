package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// Key visibility (4.0.0-beta, owner decision 2026-09-29, option A): a key is
// listed and readable only by a caller who may do something with it. Tenant
// admins, service identities and holders of key.inventory.read see every key;
// anyone else sees the keys they created, the keys an active grant gives them
// (any operation, including "read"), and the keys their workload is bound to.
// This mirrors evaluateKeyAccess, so a key never shows up for someone who
// can't touch it, and vice versa (KEY_ACCESS_MODEL.md section 8).

const permInventoryRead = "key.inventory.read"

// keyView is the caller's view of a tenant's keys.
type keyView struct {
	all   bool
	scope KeyScope
	ids   map[string]bool
}

func (v keyView) sees(k Key) bool {
	if v.all || v.ids[k.ID] {
		return true
	}
	createdBy := strings.ToLower(strings.TrimSpace(k.CreatedBy))
	for _, c := range v.scope.CreatedBy {
		if createdBy != "" && createdBy == c {
			return true
		}
	}
	return false
}

// keyViewFor builds the caller's view from the verified token in ctx.
func (s *Service) keyViewFor(ctx context.Context, tenantID string) (keyView, error) {
	actor := accessActorFromContext(ctx)
	claims, _ := pkgauth.ClaimsFromContext(ctx)
	if actorIsServicePrincipal(actor) || (actor.Authenticated && actorIsAdmin(actor)) || route.Allowed(claims, permInventoryRead) {
		return keyView{all: true}, nil
	}
	v := keyView{ids: map[string]bool{}}
	if !actor.Authenticated {
		return v, nil
	}
	if strings.TrimSpace(actor.WorkloadIdentity) != "" {
		for _, id := range normalizeActorKeyIDs(actor.AllowedKeyIDs) {
			if id == "*" {
				return keyView{all: true}, nil
			}
			v.ids[id] = true
		}
	}
	users := dedupeLower([]string{actor.UserID, actor.Username})
	v.scope.CreatedBy = users
	groups := normalizeActorGroups(actor.Groups)
	if uid := strings.TrimSpace(actor.UserID); uid != "" {
		stored, err := s.store.ListAccessGroupIDsForUser(ctx, tenantID, uid)
		if err != nil {
			return keyView{}, err
		}
		groups = normalizeActorGroups(append(groups, stored...))
	}
	granted, err := s.store.ListGrantedKeyIDs(ctx, tenantID, users, groups)
	if err != nil {
		return keyView{}, err
	}
	now := time.Now().UTC()
	for keyID, grants := range granted {
		for _, g := range grants {
			if grantActiveAt(g, now) && len(g.Operations) > 0 {
				v.ids[keyID] = true
				break
			}
		}
	}
	for id := range v.ids {
		v.scope.KeyIDs = append(v.scope.KeyIDs, id)
	}
	return v, nil
}

// ensureKeyVisible refuses a read of a key the caller can't see. The caller
// gets errStoreNotFound (a 404, so the key's existence isn't confirmed); the
// refusal is audited as audit.key.access_refused with reason not_visible.
func (s *Service) ensureKeyVisible(ctx context.Context, key Key) error {
	v, err := s.keyViewFor(ctx, key.TenantID)
	if err != nil {
		return err
	}
	if v.sees(key) {
		return nil
	}
	actor := accessActorFromContext(ctx)
	_ = s.publishAudit(ctx, "audit.key.access_refused", key.TenantID, map[string]any{
		"key_id":        key.ID,
		"operation":     "read",
		"reason":        "not_visible",
		"result":        "refused",
		"severity":      "warning",
		"actor":         firstNonEmpty(actor.UserID, actor.Username, actor.ClientID, "unauthenticated"),
		"authenticated": actor.Authenticated,
		"source_ip":     actor.SourceIP,
		"description":   "the caller holds no grant on this key, didn't create it and lacks key.inventory.read",
	})
	return errStoreNotFound
}

// visibleKeyRoute wraps a legacy per-key read: the key named by {id} must
// exist and be visible to the caller. A missing key and a hidden key get the
// same 404, so the answer doesn't reveal which. A request the handler would
// refuse anyway (no tenant, another tenant) goes straight to the handler, so
// no key is looked up across tenants.
func (h *Handler) visibleKeyRoute(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := tenantFromRequest(r)
		if tenantID == "" || tenantcheck.Enforce(r, tenantID) != nil {
			next(w, r)
			return
		}
		key, err := h.svc.store.GetKey(r.Context(), tenantID, strings.TrimSpace(r.PathValue("id")))
		if err == nil {
			err = h.svc.ensureKeyVisible(r.Context(), key)
		}
		switch {
		case errors.Is(err, errStoreNotFound):
			writeErr(w, http.StatusNotFound, "not_found", "key not found", requestID(r), tenantID)
		case err != nil:
			writeErr(w, http.StatusInternalServerError, "visibility_check_failed", "failed to check key visibility", requestID(r), tenantID)
		default:
			next(w, r)
		}
	}
}

// visibleKey is visibleKeyRoute for kernel routes: false means the 404 was
// written.
func (h *Handler) visibleKey(c *route.Call) bool {
	ctx := c.R.Context()
	if !accessActorFromContext(ctx).Authenticated {
		ctx = contextWithAccessActor(ctx, accessActorFromHTTPRequest(c.R))
	}
	key, err := h.svc.store.GetKey(ctx, c.Tenant, strings.TrimSpace(c.R.PathValue("id")))
	if err == nil {
		err = h.svc.ensureKeyVisible(ctx, key)
	}
	switch {
	case errors.Is(err, errStoreNotFound):
		c.Error(http.StatusNotFound, "not_found", "key not found")
		return false
	case err != nil:
		c.Error(http.StatusInternalServerError, "visibility_check_failed", "failed to check key visibility")
		return false
	}
	return true
}

// inventoryRouter serves the tenant-wide views over every key (inventory,
// analytics, health, compromise events, DSPM). Under key visibility they need
// key.inventory.read, which admins hold through "*" and auditors are given
// explicitly; before 4.0.0-beta any verified token could read them.
func (h *Handler) inventoryRouter(audit route.Emitter) *route.Router {
	r := route.New("key", audit, nil)
	r.Handle("GET /inventory/keys", route.Spec{Action: "inventory_keys_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleListInventory))
	r.Handle("GET /inventory/orphans", route.Spec{Action: "inventory_orphans_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleListOrphanedInventory))
	r.Handle("GET /inventory/duplicates", route.Spec{Action: "inventory_duplicates_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleListDuplicateKeys))
	r.Handle("GET /inventory/dependencies", route.Spec{Action: "inventory_dependencies_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleListKeyDependencies))
	r.Handle("GET /rotation/analytics", route.Spec{Action: "rotation_analytics_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleGetRotationAnalytics))
	r.Handle("GET /rotation/analytics/overdue", route.Spec{Action: "rotation_overdue_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleListOverdueRotationMetrics))
	r.Handle("GET /enterprise/summary", route.Spec{Action: "enterprise_summary_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleGetEnterpriseAuditSummary))
	r.Handle("GET /health/summary", route.Spec{Action: "health_summary_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleGetHealthSummary))
	r.Handle("GET /compromise/events", route.Spec{Action: "compromise_events_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleListCompromiseEvents))
	r.Handle("GET /analytics/usage", route.Spec{Action: "analytics_usage_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleGetKeyUsageMetrics))
	r.Handle("GET /analytics/hotspots", route.Spec{Action: "analytics_hotspots_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleListKeyHotspots))
	r.Handle("GET /analytics/trends", route.Spec{Action: "analytics_trends_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleGetKeyTrend))
	r.Handle("GET /enterprise/dspm/findings", route.Spec{Action: "dspm_findings_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleListKeyDSPMFindings))
	r.Handle("GET /enterprise/dspm/events", route.Spec{Action: "dspm_events_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleExportKeyDSPMEvents))
	r.Handle("GET /enterprise/compliance/dashboard", route.Spec{Action: "compliance_dashboard_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleEnterpriseComplianceDashboard))
	r.Handle("GET /enterprise/cost/optimization", route.Spec{Action: "cost_optimization_read", Permission: permInventoryRead, Resource: "key_inventory"}, legacy(h.handleEnterpriseCostOptimization))
	return r
}
