package main

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vecta-kms/pkg/route"
)

// Playbook permissions. Saving an enabled playbook or running one also needs
// every permission its actions name (ActionSpec.Permission).
const (
	permPlaybookRead   = "compliance.playbook.read"
	permPlaybookWrite  = "compliance.playbook.write"
	permPlaybookDelete = "compliance.playbook.delete"
	permPlaybookRun    = "compliance.playbook.run"

	reasonPlaybookInvalid    = "playbook_invalid"
	reasonConnectionMismatch = "connection_invalid"
	reasonRunNotCancellable  = "run_not_cancellable"
	reasonRunNotRetryable    = "run_not_retryable"
)

// PlaybookTrigger says which events fire a playbook: a catalogue trigger or
// a custom audit subject, narrowed by filters, and optionally only when
// Threshold matching events (per GroupBy value) arrive within WindowSeconds.
type PlaybookTrigger struct {
	Type          string        `json:"type"`
	Subject       string        `json:"subject,omitempty"`
	Filters       []EventFilter `json:"filters,omitempty"`
	Threshold     int           `json:"threshold,omitempty"`
	WindowSeconds int           `json:"window_seconds,omitempty"`
	GroupBy       string        `json:"group_by,omitempty"`
}

// PlaybookAction is one step of a playbook. Parameters may use {{...}}
// templates; Condition skips the step when the event doesn't match.
type PlaybookAction struct {
	Type            string            `json:"type"`
	Parameters      map[string]string `json:"parameters"`
	DelaySeconds    int               `json:"delay_seconds"`
	Condition       []EventFilter     `json:"condition,omitempty"`
	RequireApproval bool              `json:"require_approval,omitempty"`
}

// Playbook is an automated response definition. AuthorizedBy is the verified
// user who last saved it holding every action permission; automatic runs act
// on that user's authority, re-checked with auth at every run.
type Playbook struct {
	ID           string           `json:"id"`
	TenantID     string           `json:"tenant_id"`
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	Category     string           `json:"category"`
	Trigger      PlaybookTrigger  `json:"trigger"`
	Actions      []PlaybookAction `json:"actions"`
	Enabled      bool             `json:"enabled"`
	AuthorizedBy string           `json:"authorized_by"`
	RunCount     int              `json:"run_count"`
	LastRunAt    *time.Time       `json:"last_run_at,omitempty"`
	CreatedAt    time.Time        `json:"created_at"`
}

// PlaybookRun is one execution. Actor is on whose authority it ran.
type PlaybookRun struct {
	ID                string         `json:"id"`
	PlaybookID        string         `json:"playbook_id"`
	TenantID          string         `json:"tenant_id"`
	TriggerEvent      string         `json:"trigger_event"`
	Actor             string         `json:"actor"`
	ActorType         string         `json:"actor_type"`
	Status            string         `json:"status"`
	ActionsRun        int            `json:"actions_run"`
	Output            string         `json:"output"`
	Context           RunEvent       `json:"context"`
	Results           []ActionResult `json:"results"`
	ResumeIndex       int            `json:"resume_index"`
	ApprovedIndex     int            `json:"-"`
	ApprovalRequestID string         `json:"approval_request_id,omitempty"`
	IncidentID        string         `json:"incident_id,omitempty"`
	RetryOf           string         `json:"retry_of,omitempty"`
	StartedAt         time.Time      `json:"started_at"`
	CompletedAt       *time.Time     `json:"completed_at,omitempty"`
}

var playbookCategories = []string{
	"incident_response", "key_lifecycle", "certificate_management", "compliance",
	"access_control", "infrastructure", "data_protection", "operational",
}

// playbookInput is what a client may set. Unknown fields (client-chosen IDs,
// run counters) are rejected by Decode.
type playbookInput struct {
	TenantID    string           `json:"tenant_id"` // verified by the kernel
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Category    string           `json:"category"`
	Trigger     PlaybookTrigger  `json:"trigger"`
	Actions     []PlaybookAction `json:"actions"`
	Enabled     *bool            `json:"enabled"`
}

func (in playbookInput) playbook(tenant, id string) Playbook {
	p := Playbook{
		ID: id, TenantID: tenant, Name: strings.TrimSpace(in.Name), Description: in.Description,
		Category: firstNonEmpty(strings.TrimSpace(in.Category), "incident_response"),
		Trigger:  in.Trigger, Actions: in.Actions, Enabled: in.Enabled == nil || *in.Enabled,
	}
	for i := range p.Actions {
		if p.Actions[i].Parameters == nil {
			p.Actions[i].Parameters = map[string]string{}
		}
	}
	return p
}

// runInput is a manual run's optional event context: the values templates
// and conditions see. It is recorded as supplied by the runner.
type runInput struct {
	TenantID string    `json:"tenant_id"`
	Event    *RunEvent `json:"event"`
}

func (h *Handler) playbookRoutes(rt *route.Router) {
	read := func(action string, target string) route.Spec {
		return route.Spec{Action: action, Permission: permPlaybookRead, Resource: "playbook", TargetParam: target}
	}
	write := func(action, perm, target string) route.Spec {
		return route.Spec{Action: action, Permission: perm, Resource: "playbook", TargetParam: target, Severity: "warning"}
	}
	rt.Handle("GET /compliance/playbooks/catalog", route.Spec{Action: "playbook_catalog_read", Permission: permPlaybookRead, Resource: "playbook", Tenancy: route.PlatformScoped}, h.playbookCatalog)
	rt.Handle("GET /compliance/playbooks/summary", read("playbook_summary_read", ""), h.playbookSummary)
	rt.Handle("GET /compliance/playbooks", read("playbooks_listed", ""), h.listPlaybooks)
	rt.Handle("POST /compliance/playbooks", write("playbook_created", permPlaybookWrite, ""), h.createPlaybook)
	rt.Handle("GET /compliance/playbooks/{id}", read("playbook_read", "id"), h.getPlaybook)
	rt.Handle("PUT /compliance/playbooks/{id}", write("playbook_updated", permPlaybookWrite, "id"), h.updatePlaybook)
	rt.Handle("DELETE /compliance/playbooks/{id}", write("playbook_deleted", permPlaybookDelete, "id"), h.deletePlaybook)
	rt.Handle("POST /compliance/playbooks/{id}/run", write("playbook_run_requested", permPlaybookRun, "id"), h.runPlaybook)
	rt.Handle("POST /compliance/playbooks/{id}/dry-run", route.Spec{Action: "playbook_dry_run", Permission: permPlaybookRun, Resource: "playbook", TargetParam: "id"}, h.dryRunPlaybook)
	rt.Handle("GET /compliance/playbooks/{id}/runs", read("playbook_runs_listed", "id"), h.listPlaybookRuns)
	rt.Handle("GET /compliance/playbook-runs", read("playbook_runs_searched", ""), h.searchRuns)
	rt.Handle("GET /compliance/playbook-runs/{run_id}", route.Spec{Action: "playbook_run_read", Permission: permPlaybookRead, Resource: "playbook_run", TargetParam: "run_id"}, h.getRun)
	rt.Handle("POST /compliance/playbook-runs/{run_id}/cancel", route.Spec{Action: "playbook_run_cancelled", Permission: permPlaybookRun, Resource: "playbook_run", TargetParam: "run_id", Severity: "warning"}, h.cancelRun)
	rt.Handle("POST /compliance/playbook-runs/{run_id}/retry", route.Spec{Action: "playbook_run_retried", Permission: permPlaybookRun, Resource: "playbook_run", TargetParam: "run_id", Severity: "warning"}, h.retryRun)
	h.connectionRoutes(rt)
	h.serviceConnectionRoutes(rt)
}

func (h *Handler) playbookCatalog(c *route.Call) {
	c.JSON(http.StatusOK, map[string]interface{}{"data": map[string]interface{}{
		"triggers": playbookTriggers, "actions": playbookActions, "categories": playbookCategories,
		"connection_types": connectionTypes, "event_fields": eventFields, "filter_ops": []string{"eq", "neq", "in", "not_in", "contains", "prefix"},
		"templates":         []string{"{{event.<field>}}", "{{event.details.<key>}}", "{{run.id}}", "{{playbook.id}}", "{{playbook.name}}", "{{trigger}}"},
		"incident_statuses": []string{"open", "investigating", "resolved", "closed"},
	}})
}

func (h *Handler) listPlaybooks(c *route.Call) {
	items, err := h.svc.store.ListPlaybooks(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "list playbooks failed")
		return
	}
	for i := range items {
		items[i] = redactInline(items[i])
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": items})
}

func (h *Handler) getPlaybook(c *route.Call) {
	pb, ok := h.loadPlaybook(c, c.R.PathValue("id"))
	if !ok {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": redactInline(pb)})
}

func (h *Handler) createPlaybook(c *route.Call) {
	var in playbookInput
	if !c.Decode(&in) {
		return
	}
	pb := in.playbook(c.Tenant, newID("pb"))
	c.Target(pb.ID)
	if !h.authorizePlaybook(c, &pb) {
		return
	}
	created, err := h.svc.store.CreatePlaybook(c.R.Context(), pb)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "create playbook failed")
		return
	}
	h.triggers.Invalidate(c.Tenant)
	c.JSON(http.StatusCreated, map[string]interface{}{"data": created})
}

func (h *Handler) updatePlaybook(c *route.Call) {
	stored, ok := h.loadPlaybook(c, c.R.PathValue("id"))
	if !ok {
		return
	}
	var in playbookInput
	if !c.Decode(&in) {
		return
	}
	pb := in.playbook(c.Tenant, stored.ID)
	if !h.authorizePlaybook(c, &pb) {
		return
	}
	updated, err := h.svc.store.UpdatePlaybook(c.R.Context(), pb)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "update playbook failed")
		return
	}
	// Counts taken under the old trigger don't carry over to the new one.
	_ = h.svc.store.ResetThresholdHits(c.R.Context(), c.Tenant, stored.ID, "*")
	h.triggers.Invalidate(c.Tenant)
	c.JSON(http.StatusOK, map[string]interface{}{"data": updated})
}

// authorizePlaybook validates pb and binds it to the caller. An enabled
// playbook can be saved only by a user who holds every action permission;
// it runs on that user's authority, re-checked with auth at each run. A
// disabled one may be saved by any playbook writer and stays unauthorized
// until such a user saves it enabled.
func (h *Handler) authorizePlaybook(c *route.Call, pb *Playbook) bool {
	c.Detail("name", pb.Name)
	c.Detail("trigger", pb.Trigger.Type)
	c.Detail("actions", actionTypes(pb.Actions))
	c.Detail("enabled", pb.Enabled)
	if err := validatePlaybook(*pb); err != nil {
		c.Error(http.StatusBadRequest, "bad_request", err.Error())
		return false
	}
	if !knownCategory(pb.Category) {
		c.Error(http.StatusBadRequest, "bad_request", "unknown category "+strconv.Quote(pb.Category))
		return false
	}
	for i, a := range pb.Actions {
		kind := actionByType[a.Type].Connection
		if kind == "" {
			continue
		}
		conn, err := h.svc.store.GetConnection(c.R.Context(), c.Tenant, a.Parameters["connection_id"])
		if err != nil || !connectionFits(kind, conn.Type) {
			c.Refuse(http.StatusBadRequest, reasonConnectionMismatch, "action "+strconv.Itoa(i+1)+" ("+a.Type+") needs a "+kind+" connection of this tenant")
			return false
		}
	}
	missing := missingPermissions(c.Claims, pb.Actions)
	user := strings.TrimSpace(c.Claims.UserID)
	switch {
	case pb.Enabled && len(missing) > 0:
		c.Detail("missing_permissions", missing)
		c.Refuse(http.StatusForbidden, reasonActionPermission, "enabling this playbook needs "+strings.Join(missing, ", "))
		return false
	case pb.Enabled && user == "":
		c.Refuse(http.StatusForbidden, reasonUserRequired, "automatic runs act on a person's authority; enable this playbook as a user")
		return false
	}
	pb.AuthorizedBy = ""
	if len(missing) == 0 {
		pb.AuthorizedBy = user
	}
	c.Detail("authorized_by", pb.AuthorizedBy)
	return true
}

func (h *Handler) deletePlaybook(c *route.Call) {
	err := h.svc.store.DeletePlaybook(c.R.Context(), c.Tenant, c.R.PathValue("id"))
	switch {
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, "not_found", "playbook not found")
	case err != nil:
		c.Error(http.StatusInternalServerError, "internal_error", "delete playbook failed")
	default:
		_ = h.svc.store.ResetThresholdHits(c.R.Context(), c.Tenant, c.R.PathValue("id"), "*")
		h.triggers.Invalidate(c.Tenant)
		c.JSON(http.StatusOK, map[string]interface{}{"data": map[string]string{"status": "deleted"}})
	}
}

// manualReady checks a manual start: a valid playbook, and a runner holding
// every action permission, whoever authorized the playbook.
func (h *Handler) manualReady(c *route.Call, pb Playbook) bool {
	c.Detail("actions", actionTypes(pb.Actions))
	if err := validatePlaybook(pb); err != nil {
		c.Refuse(http.StatusConflict, reasonPlaybookInvalid, err.Error()+"; edit the playbook")
		return false
	}
	for _, a := range pb.Actions {
		if hasInlineSecrets(a) {
			c.Refuse(http.StatusConflict, reasonPlaybookInvalid, "credentials are still being moved into connections; retry shortly")
			return false
		}
	}
	if missing := missingPermissions(c.Claims, pb.Actions); len(missing) > 0 {
		c.Detail("missing_permissions", missing)
		c.Refuse(http.StatusForbidden, reasonActionPermission, "running this playbook needs "+strings.Join(missing, ", "))
		return false
	}
	if h.executor == nil {
		c.Error(http.StatusServiceUnavailable, "unavailable", "playbook executor not initialized")
		return false
	}
	return true
}

func runnerSource(c *route.Call, trigger string, ev RunEvent) runSource {
	actorType := "client"
	if strings.TrimSpace(c.Claims.UserID) != "" {
		actorType = "user"
	}
	return runSource{Trigger: trigger, Actor: c.Actor(), ActorType: actorType, Event: ev}
}

// suppliedEvent is a manual run's event context, never taken for observed.
func suppliedEvent(in runInput, tenant string) RunEvent {
	ev := RunEvent{}
	if in.Event != nil {
		ev = *in.Event
	}
	ev.TenantID, ev.Supplied = tenant, true
	return ev
}

// runPlaybook starts a manual run on the caller's own authority.
func (h *Handler) runPlaybook(c *route.Call) {
	pb, ok := h.loadPlaybook(c, c.R.PathValue("id"))
	if !ok {
		return
	}
	var in runInput
	if c.R.ContentLength != 0 && !c.Decode(&in) {
		return
	}
	if !h.manualReady(c, pb) {
		return
	}
	h.start(c, pb, runnerSource(c, "manual", suppliedEvent(in, c.Tenant)))
}

func (h *Handler) start(c *route.Call, pb Playbook, src runSource) {
	run, err := h.executor.Start(c.R.Context(), pb, src)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "start run failed")
		return
	}
	c.Detail("run_id", run.ID)
	h.dispatch(func() {
		ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
		defer cancel()
		h.executor.Execute(ctx, pb, run)
	})
	c.JSON(http.StatusAccepted, map[string]interface{}{"data": map[string]interface{}{
		"run_id": run.ID, "playbook_id": pb.ID, "status": runRunning,
	}})
}

// dryRunPlaybook shows what a run would do with an event, checking each
// target with its owning service. Nothing is changed.
func (h *Handler) dryRunPlaybook(c *route.Call) {
	pb, ok := h.loadPlaybook(c, c.R.PathValue("id"))
	if !ok {
		return
	}
	var in runInput
	if c.R.ContentLength != 0 && !c.Decode(&in) {
		return
	}
	if err := validatePlaybook(pb); err != nil {
		c.Error(http.StatusConflict, reasonPlaybookInvalid, err.Error())
		return
	}
	if h.executor == nil {
		c.Error(http.StatusServiceUnavailable, "unavailable", "playbook executor not initialized")
		return
	}
	ev := suppliedEvent(in, c.Tenant)
	steps := h.executor.DryRun(c.R.Context(), pb, ev, func(perm string) bool { return route.Allowed(c.Claims, perm) })
	c.JSON(http.StatusOK, map[string]interface{}{"data": map[string]interface{}{
		"playbook_id": pb.ID, "trigger_matches": matchFilters(ev, pb.Trigger.Filters), "steps": steps,
	}})
}

func (h *Handler) listPlaybookRuns(c *route.Call) {
	limit, _ := strconv.Atoi(c.R.URL.Query().Get("limit"))
	runs, err := h.svc.store.ListPlaybookRuns(c.R.Context(), c.Tenant, RunQuery{PlaybookID: c.R.PathValue("id"), Limit: limit})
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "list runs failed")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": runs})
}

// searchRuns lists runs across playbooks: by status (e.g.
// awaiting_approval) or by the reporting incident they responded to.
func (h *Handler) searchRuns(c *route.Call) {
	q := c.R.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	runs, err := h.svc.store.ListPlaybookRuns(c.R.Context(), c.Tenant, RunQuery{Status: q.Get("status"), IncidentID: q.Get("incident_id"), Limit: limit})
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "list runs failed")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": runs})
}

func (h *Handler) loadRun(c *route.Call) (PlaybookRun, bool) {
	run, err := h.svc.store.GetPlaybookRun(c.R.Context(), c.Tenant, c.R.PathValue("run_id"))
	switch {
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, "not_found", "run not found")
		return run, false
	case err != nil:
		c.Error(http.StatusInternalServerError, "internal_error", "read run failed")
		return run, false
	}
	c.Detail("playbook_id", run.PlaybookID)
	return run, true
}

func (h *Handler) getRun(c *route.Call) {
	if run, ok := h.loadRun(c); ok {
		c.JSON(http.StatusOK, map[string]interface{}{"data": run})
	}
}

// cancelRun stops a running or paused run. The runner must hold the
// playbook's action permissions, as for starting it.
func (h *Handler) cancelRun(c *route.Call) {
	run, ok := h.loadRun(c)
	if !ok {
		return
	}
	pb, ok := h.loadPlaybook(c, run.PlaybookID)
	if !ok {
		return
	}
	if missing := missingPermissions(c.Claims, pb.Actions); len(missing) > 0 {
		c.Detail("missing_permissions", missing)
		c.Refuse(http.StatusForbidden, reasonActionPermission, "cancelling this run needs "+strings.Join(missing, ", "))
		return
	}
	if h.executor == nil {
		c.Error(http.StatusServiceUnavailable, "unavailable", "playbook executor not initialized")
		return
	}
	c.Detail("status_before", run.Status)
	out, err := h.executor.Cancel(c.R.Context(), pb, run)
	if err != nil {
		c.Refuse(http.StatusConflict, reasonRunNotCancellable, err.Error())
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": map[string]string{"run_id": out.ID, "status": firstNonEmpty(out.Status, runCancelled)}})
}

// retryRun starts a new run with the same event context from the first
// action that did not complete, on the caller's authority.
func (h *Handler) retryRun(c *route.Call) {
	run, ok := h.loadRun(c)
	if !ok {
		return
	}
	switch run.Status {
	case runFailed, runPartialFailure, runCancelled, runApprovalDenied, runApprovalExpired:
	default:
		c.Refuse(http.StatusConflict, reasonRunNotRetryable, "a "+run.Status+" run can't be retried")
		return
	}
	pb, ok := h.loadPlaybook(c, run.PlaybookID)
	if !ok || !h.manualReady(c, pb) {
		return
	}
	done := map[int]bool{}
	for _, r := range run.Results {
		if r.Status == outcomeDone || r.Status == resultSkipped || r.Status == outcomePendingApproval {
			done[r.Index-1] = true
		}
	}
	from := 0
	for from < len(pb.Actions) && done[from] {
		from++
	}
	if from >= len(pb.Actions) {
		c.Refuse(http.StatusConflict, reasonRunNotRetryable, "every action of this run completed")
		return
	}
	src := runnerSource(c, "retry", run.Context)
	src.ResumeFrom, src.RetryOf = from, run.ID
	c.Detail("retry_of", run.ID)
	c.Detail("resume_from", from+1)
	h.start(c, pb, src)
}

func (h *Handler) playbookSummary(c *route.Call) {
	summary, err := h.svc.store.GetPlaybookSummary(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "summary failed")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": summary})
}

func (h *Handler) loadPlaybook(c *route.Call, id string) (Playbook, bool) {
	pb, err := h.svc.store.GetPlaybook(c.R.Context(), c.Tenant, id)
	switch {
	case errors.Is(err, errNotFound):
		c.Error(http.StatusNotFound, "not_found", "playbook not found")
		return Playbook{}, false
	case err != nil:
		c.Error(http.StatusInternalServerError, "internal_error", "read playbook failed")
		return Playbook{}, false
	}
	return pb, true
}

func actionTypes(actions []PlaybookAction) []string {
	out := make([]string, len(actions))
	for i, a := range actions {
		out[i] = a.Type
	}
	return out
}

func knownCategory(c string) bool {
	for _, k := range playbookCategories {
		if k == c {
			return true
		}
	}
	return false
}
