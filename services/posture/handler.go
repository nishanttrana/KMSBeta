package main

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"vecta-kms/pkg/route"
)

// Posture permissions. The domain is not in route.CoarseDomains: posture is
// an analytics and remediation plane, so kms.read/kms.write don't reach it
// (docs/DECISIONS.md).
const (
	permRead    = "posture.read"
	permWrite   = "posture.write"
	permExecute = "posture.action.execute"
)

// reasonTenantWildcard refuses "*" or "all" as a tenant: the kernel binds one
// tenant, and "*" is the row key of the cross-tenant aggregate snapshot.
const reasonTenantWildcard = "tenant_wildcard"

type Handler struct {
	svc    *Service
	router *route.Router
	audit  route.Emitter // *pkgaudit.Client in production
}

func NewHandler(svc *Service) *Handler {
	h := &Handler{svc: svc}
	h.router = h.newRouter(postureEmitter{h})
	return h
}

// newRouter registers every posture route, engine and leak scanner, on one
// pkg/route kernel router.
func (h *Handler) newRouter(audit route.Emitter) *route.Router {
	r := route.New("posture", audit, nil)
	h.postureRoutes(r)
	h.leakRoutes(r)
	return r
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.router.ServeHTTP(w, r)
}

// postureRoutes registers the posture engine routes.
func (h *Handler) postureRoutes(r *route.Router) {
	spec := func(action, perm, resource string) route.Spec {
		return route.Spec{Action: action, Permission: perm, Resource: resource}
	}
	r.Handle("GET /posture/health", route.Spec{Action: "health_read", Permission: route.Authenticated, Tenancy: route.PlatformScoped}, h.handleHealth)
	r.Handle("POST /posture/events", spec("events_ingested", permWrite, "posture_event"), oneTenant(h.handleIngestEvent))
	r.Handle("POST /posture/events/batch", spec("events_ingested", permWrite, "posture_event"), oneTenant(h.handleIngestEventsBatch))
	r.Handle("POST /posture/ingest/audit", spec("audit_synced", permWrite, "posture_event"), oneTenant(h.handleIngestFromAudit))
	r.Handle("POST /posture/scan", spec("scan_run", permWrite, "posture_risk"), oneTenant(h.handleRunScan))

	r.Handle("GET /posture/findings", spec("findings_listed", permRead, "posture_finding"), oneTenant(h.handleListFindings))
	r.Handle("PUT /posture/findings/{id}/status", route.Spec{Action: "finding_status_updated", Permission: permWrite, Resource: "posture_finding", TargetParam: "id"}, oneTenant(h.handleUpdateFindingStatus))

	r.Handle("GET /posture/risk", spec("risk_read", permRead, "posture_risk"), oneTenant(h.handleLatestRisk))
	r.Handle("GET /posture/risk/history", spec("risk_history_read", permRead, "posture_risk"), oneTenant(h.handleRiskHistory))

	r.Handle("GET /posture/actions", spec("actions_listed", permRead, "posture_action"), oneTenant(h.handleListActions))
	r.Handle("POST /posture/actions/{id}/execute", route.Spec{Action: "action_executed", Permission: permExecute, Resource: "posture_action", TargetParam: "id", Severity: "warning"}, oneTenant(h.handleExecuteAction))

	r.Handle("GET /posture/dashboard", spec("dashboard_viewed", permRead, "posture_risk"), oneTenant(h.handleDashboard))
}

// oneTenant refuses the wildcard tenants the legacy handlers accepted. Only
// a tenant-less root token or a service principal could name one past the
// kernel; neither may read or scan every tenant through this API.
func oneTenant(next func(*route.Call)) func(*route.Call) {
	return func(c *route.Call) {
		if c.Tenant == "*" || strings.EqualFold(c.Tenant, "all") {
			c.Refuse(http.StatusForbidden, reasonTenantWildcard, "tenant_id must name one tenant")
			return
		}
		next(c)
	}
}

func (h *Handler) handleHealth(c *route.Call) {
	c.JSON(http.StatusOK, map[string]interface{}{"status": "ok", "service": "posture"})
}

func (h *Handler) handleIngestEvent(c *route.Call) {
	var payload NormalizedEvent
	if !c.Decode(&payload) {
		return
	}
	payload.TenantID = c.Tenant // the kernel checked any body tenant_id
	h.ingest(c, []NormalizedEvent{payload})
}

func (h *Handler) handleIngestEventsBatch(c *route.Call) {
	var payload struct {
		Items []NormalizedEvent `json:"items"`
	}
	if !c.Decode(&payload) {
		return
	}
	// The kernel sees only a top-level tenant_id; each item's is checked here.
	for i := range payload.Items {
		if t := strings.TrimSpace(payload.Items[i].TenantID); t != "" && !strings.EqualFold(t, c.Tenant) {
			c.Detail("requested_tenant", t)
			c.Refuse(http.StatusForbidden, route.ReasonTenantMismatch, "every item must belong to the request tenant")
			return
		}
		payload.Items[i].TenantID = c.Tenant
	}
	c.Detail("batch", true)
	h.ingest(c, payload.Items)
}

func (h *Handler) ingest(c *route.Call, events []NormalizedEvent) {
	inserted, err := h.svc.IngestEvents(c.R.Context(), events)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("submitted", len(events))
	c.Detail("inserted", inserted)
	c.JSON(http.StatusOK, map[string]interface{}{"inserted": inserted})
}

func (h *Handler) handleIngestFromAudit(c *route.Call) {
	limit := atoi(c.R.URL.Query().Get("limit"), 500, 1, 5000)
	inserted, err := h.svc.SyncFromAudit(c.R.Context(), c.Tenant, limit)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("inserted", inserted)
	c.JSON(http.StatusOK, map[string]interface{}{"inserted": inserted, "tenant_id": c.Tenant})
}

func (h *Handler) handleRunScan(c *route.Call) {
	syncAudit := parseBool(c.R.URL.Query().Get("sync_audit"))
	snap, err := h.svc.RunScanTenant(c.R.Context(), c.Tenant, syncAudit)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("sync_audit", syncAudit)
	c.Detail("risk_24h", snap.Risk24h)
	c.JSON(http.StatusOK, map[string]interface{}{"risk": snap, "tenant_id": c.Tenant})
}

func (h *Handler) handleListFindings(c *route.Call) {
	q := c.R.URL.Query()
	items, err := h.svc.ListFindings(c.R.Context(), c.Tenant, FindingQuery{
		Engine:      strings.TrimSpace(q.Get("engine")),
		Status:      strings.TrimSpace(q.Get("status")),
		Severity:    strings.TrimSpace(q.Get("severity")),
		FindingType: strings.TrimSpace(q.Get("finding_type")),
		Limit:       atoi(q.Get("limit"), 200, 1, 1000),
		Offset:      atoi(q.Get("offset"), 0, 0, 100000),
		From:        parseTimeString(q.Get("from")),
		To:          parseTimeString(q.Get("to")),
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) handleUpdateFindingStatus(c *route.Call) {
	var payload struct {
		Status string `json:"status"`
	}
	if !c.Decode(&payload) {
		return
	}
	if err := h.svc.UpdateFindingStatus(c.R.Context(), c.Tenant, c.R.PathValue("id"), payload.Status); err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("status", strings.TrimSpace(payload.Status))
	c.JSON(http.StatusOK, map[string]interface{}{"ok": true})
}

func (h *Handler) handleLatestRisk(c *route.Call) {
	item, err := h.svc.LatestRisk(c.R.Context(), c.Tenant)
	if errors.Is(err, errNotFound) {
		c.Detail("assessed", false)
		c.JSON(http.StatusOK, map[string]interface{}{"risk": RiskSnapshot{TenantID: c.Tenant}})
		return
	}
	if err != nil {
		h.fail(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"risk": item})
}

func (h *Handler) handleRiskHistory(c *route.Call) {
	items, err := h.svc.RiskHistory(c.R.Context(), c.Tenant, RiskQuery{
		Limit:  atoi(c.R.URL.Query().Get("limit"), 200, 1, 1000),
		Offset: atoi(c.R.URL.Query().Get("offset"), 0, 0, 100000),
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) handleListActions(c *route.Call) {
	q := c.R.URL.Query()
	items, err := h.svc.ListActions(c.R.Context(), c.Tenant, ActionQuery{
		Status:     strings.TrimSpace(q.Get("status")),
		ActionType: strings.TrimSpace(q.Get("action_type")),
		Limit:      atoi(q.Get("limit"), 200, 1, 1000),
		Offset:     atoi(q.Get("offset"), 0, 0, 100000),
	})
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

// handleExecuteAction records the verified caller as the executor. A body
// "actor" (or an X-Actor-ID header) is never identity: the field is rejected
// as unknown and the header is ignored.
func (h *Handler) handleExecuteAction(c *route.Call) {
	var payload struct {
		ApprovalRequestID string `json:"approval_request_id"`
	}
	if c.R.ContentLength != 0 && !c.Decode(&payload) {
		return
	}
	approval := strings.TrimSpace(payload.ApprovalRequestID)
	if err := h.svc.ExecuteAction(c.R.Context(), c.Tenant, c.R.PathValue("id"), c.Actor(), approval); err != nil {
		h.fail(c, err)
		return
	}
	if approval != "" {
		c.Detail("approval_request_id", approval)
	}
	c.JSON(http.StatusOK, map[string]interface{}{"ok": true})
}

func (h *Handler) handleDashboard(c *route.Call) {
	out, err := h.svc.Dashboard(c.R.Context(), c.Tenant)
	if err != nil {
		h.fail(c, err)
		return
	}
	c.Detail("risk_24h", out.Risk.Risk24h)
	c.Detail("open_findings", out.OpenFindings)
	c.Detail("critical_findings", out.CriticalFindings)
	c.Detail("risk_driver_count", len(out.RiskDrivers.Drivers))
	c.Detail("blast_radius", len(out.BlastRadius))
	c.Detail("action_count", len(out.PendingActions))
	c.JSON(http.StatusOK, map[string]interface{}{
		"risk":                out.Risk,
		"recent_findings":     out.RecentFindings,
		"pending_actions":     out.PendingActions,
		"open_findings":       out.OpenFindings,
		"critical_findings":   out.CriticalFindings,
		"risk_drivers":        out.RiskDrivers,
		"remediation_cockpit": out.RemediationCockpit,
		"blast_radius":        out.BlastRadius,
		"scenario_simulator":  out.ScenarioSimulator,
		"validation_badges":   out.ValidationBadges,
		"sla_overview":        out.SLAOverview,
	})
}

// fail maps a service error to its status; anything else is a 500 that
// never leaks internal detail to the client.
func (h *Handler) fail(c *route.Call, err error) {
	var svcErr serviceError
	switch {
	case errors.As(err, &svcErr):
		c.Error(svcErr.HTTPStatus, svcErr.Code, svcErr.Message)
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, "not_found", "not found")
	default:
		c.Error(http.StatusInternalServerError, "internal_error", "internal server error")
	}
}

func atoi(raw string, fallback int, min int, max int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if n < min {
		n = min
	}
	if max > 0 && n > max {
		n = max
	}
	return n
}
