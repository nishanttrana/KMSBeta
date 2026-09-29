package main

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"vecta-kms/pkg/route"
	"vecta-kms/pkg/tenantcheck"
)

// Permissions of the key-access routes (docs/API_REFERENCE.md).
const (
	permRead     = "keyaccess.read"
	permWrite    = "keyaccess.write"    // settings and justification codes
	permEvaluate = "keyaccess.evaluate" // held only by the evaluators below
)

// evaluators are the service identities that ask for a key-access decision
// before they use a key, and the service name each decision is scoped to. A
// caller outside this list, a root administrator included, is refused: a
// decision is recorded as the service's and can create a governance
// approval, so only the service that will act on it may ask.
var evaluators = map[string]string{
	"kms-ekm":        "ekm",
	"kms-cloud":      "cloud",
	"kms-hyok-proxy": "hyok",
}

const (
	reasonEvaluator       = "evaluator_identity_required"
	reasonServiceMismatch = "service_mismatch"
)

// Handler serves every key-access route through the pkg/route kernel: the
// verified token names the tenant, the route's permission is enforced, and
// each request emits audit.keyaccess.<action>, refusals included.
type Handler struct {
	svc    *Service
	router *route.Router
}

func NewHandler(svc *Service, audit route.Emitter, logger *log.Logger) *Handler {
	h := &Handler{svc: svc}
	r := route.New("keyaccess", audit, logger)
	r.Handle("GET /key-access/settings", route.Spec{Action: "settings_viewed", Permission: permRead, Resource: "key_access_settings"}, h.getSettings)
	r.Handle("PUT /key-access/settings", route.Spec{Action: "settings_updated", Permission: permWrite, Resource: "key_access_settings", Severity: "warning"}, h.putSettings)
	r.Handle("GET /key-access/summary", route.Spec{Action: "summary_viewed", Permission: permRead, Resource: "key_access_settings"}, h.getSummary)
	r.Handle("GET /key-access/codes", route.Spec{Action: "codes_viewed", Permission: permRead, Resource: "justification_code"}, h.listRules)
	r.Handle("POST /key-access/codes", route.Spec{Action: "code_upserted", Permission: permWrite, Resource: "justification_code"}, h.upsertRule)
	r.Handle("PUT /key-access/codes/{id}", route.Spec{Action: "code_upserted", Permission: permWrite, Resource: "justification_code", TargetParam: "id"}, h.upsertRule)
	r.Handle("DELETE /key-access/codes/{id}", route.Spec{Action: "code_deleted", Permission: permWrite, Resource: "justification_code", TargetParam: "id", Severity: "warning"}, h.deleteRule)
	r.Handle("GET /key-access/decisions", route.Spec{Action: "decisions_viewed", Permission: permRead, Resource: "key_access_decision"}, h.listDecisions)
	r.Handle("POST /key-access/evaluate", route.Spec{Action: "decision_evaluated", Permission: permEvaluate, Resource: "key", Severity: "warning"}, h.evaluate)
	h.router = r
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.router.ServeHTTP(w, r) }

func (h *Handler) getSettings(c *route.Call) {
	item, err := h.svc.GetSettings(c.R.Context(), c.Tenant)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"settings": item})
}

func (h *Handler) putSettings(c *route.Call) {
	var body KeyAccessSettings
	if !c.Decode(&body) {
		return
	}
	body.TenantID = c.Tenant
	body.UpdatedBy = c.Actor()
	item, err := h.svc.UpdateSettings(c.R.Context(), body)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Detail("enabled", item.Enabled)
	c.Detail("mode", item.Mode)
	c.Detail("default_action", item.DefaultAction)
	c.Detail("require_justification_code", item.RequireJustificationCode)
	c.Detail("require_justification_text", item.RequireJustificationText)
	c.Detail("approval_policy_id", item.ApprovalPolicyID)
	c.JSON(http.StatusOK, map[string]interface{}{"settings": item})
}

func (h *Handler) getSummary(c *route.Call) {
	item, err := h.svc.GetSummary(c.R.Context(), c.Tenant)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"summary": item})
}

func (h *Handler) listRules(c *route.Call) {
	items, err := h.svc.ListRules(c.R.Context(), c.Tenant)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Detail("count", len(items))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func (h *Handler) upsertRule(c *route.Call) {
	var body KeyAccessRule
	if !c.Decode(&body) {
		return
	}
	body.TenantID = c.Tenant
	body.UpdatedBy = c.Actor()
	if id := c.R.PathValue("id"); id != "" {
		body.ID = id
	}
	item, err := h.svc.UpsertRule(c.R.Context(), body)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Target(item.ID)
	c.Detail("code", item.Code)
	c.Detail("action", item.Action)
	c.Detail("services", item.Services)
	c.Detail("operations", item.Operations)
	c.Detail("enabled", item.Enabled)
	c.JSON(http.StatusOK, map[string]interface{}{"rule": item})
}

func (h *Handler) deleteRule(c *route.Call) {
	if err := h.svc.DeleteRule(c.R.Context(), c.Tenant, c.R.PathValue("id")); err != nil {
		writeServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"ok": true})
}

func (h *Handler) listDecisions(c *route.Call) {
	q := c.R.URL.Query()
	limit := 100
	if parsed, err := strconv.Atoi(strings.TrimSpace(q.Get("limit"))); err == nil {
		limit = parsed
	}
	items, err := h.svc.ListDecisions(c.R.Context(), c.Tenant, q.Get("service"), q.Get("action"), limit)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Detail("count", len(items))
	c.Detail("service", strings.ToLower(strings.TrimSpace(q.Get("service"))))
	c.Detail("decision", strings.ToLower(strings.TrimSpace(q.Get("action"))))
	c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

// evaluate returns the tenant's decision for a service about to use a key.
// Only the evaluator identities may ask, each for its own service name.
func (h *Handler) evaluate(c *route.Call) {
	service, ok := "", false
	if tenantcheck.IsServicePrincipal(c.Claims) {
		service, ok = evaluators[c.Claims.ClientID]
	}
	if !ok {
		c.Refuse(http.StatusForbidden, reasonEvaluator, "only the ekm, cloud and hyok service identities may request a key-access decision")
		return
	}
	var body EvaluateKeyAccessInput
	if !c.Decode(&body) {
		return
	}
	c.Detail("service", service)
	if s := strings.ToLower(strings.TrimSpace(body.Service)); s != "" && s != service {
		c.Detail("requested_service", s)
		c.Refuse(http.StatusForbidden, reasonServiceMismatch, "a service may request decisions only for itself")
		return
	}
	body.TenantID = c.Tenant
	body.Service = service
	body.RequestID = firstNonEmpty(body.RequestID, c.RequestID)
	c.Target(body.KeyID)
	item, err := h.svc.Evaluate(c.R.Context(), body)
	if err != nil {
		writeServiceError(c, err)
		return
	}
	c.Detail("decision_id", item.DecisionID)
	c.Detail("connector", body.Connector)
	c.Detail("operation", strings.ToLower(strings.TrimSpace(body.Operation)))
	c.Detail("decision", item.Action)
	c.Detail("decision_reason", item.Reason)
	c.Detail("policy_mode", item.Mode)
	c.Detail("policy_enabled", item.Enabled)
	c.Detail("bypass_detected", item.BypassDetected)
	c.Detail("justification_code", strings.ToUpper(strings.TrimSpace(body.JustificationCode)))
	c.Detail("matched_code", item.MatchedCode)
	c.Detail("approval_required", item.ApprovalRequired)
	c.Detail("approval_request_id", item.ApprovalRequestID)
	c.Detail("requester_id", strings.TrimSpace(body.RequesterID))
	status := http.StatusOK
	if item.ApprovalRequired {
		status = http.StatusAccepted
	}
	c.JSON(status, map[string]interface{}{"result": item})
}

// writeServiceError maps a service error onto the kernel's error envelope;
// server errors never leak their detail (OWASP A05).
func writeServiceError(c *route.Call, err error) {
	var se serviceError
	switch {
	case errors.As(err, &se):
		c.Error(se.HTTPStatus, se.Code, se.Message)
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, "not_found", "not found")
	default:
		c.Error(http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
