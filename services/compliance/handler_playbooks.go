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

// Playbook permissions. Saving or running a playbook also needs every
// permission its actions name (ActionSpec.Permission).
const (
	permPlaybookRead   = "compliance.playbook.read"
	permPlaybookWrite  = "compliance.playbook.write"
	permPlaybookDelete = "compliance.playbook.delete"
	permPlaybookRun    = "compliance.playbook.run"

	reasonPlaybookInvalid = "playbook_invalid"
)

// PlaybookTrigger names the catalogue trigger that fires a playbook.
type PlaybookTrigger struct {
	Type string `json:"type"`
}

// PlaybookAction is one step of a playbook.
type PlaybookAction struct {
	Type         string            `json:"type"`
	Parameters   map[string]string `json:"parameters"`
	DelaySeconds int               `json:"delay_seconds"`
}

// Playbook is an automated response definition. AuthorizedBy is the verified
// caller who last saved it holding every action permission; automatic runs
// act on that authority and are refused while it is empty.
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
	ID           string     `json:"id"`
	PlaybookID   string     `json:"playbook_id"`
	TenantID     string     `json:"tenant_id"`
	TriggerEvent string     `json:"trigger_event"`
	Actor        string     `json:"actor"`
	Status       string     `json:"status"`
	ActionsRun   int        `json:"actions_run"`
	Output       string     `json:"output"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
}

var playbookCategories = []string{
	"incident_response", "key_lifecycle", "certificate_management", "compliance",
	"access_control", "infrastructure", "data_protection", "operational",
}

// playbookInput is what a client may set. Unknown fields (the old trigger
// threshold, client-chosen IDs, run counters) are rejected by Decode.
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

func (h *Handler) playbookRoutes(rt *route.Router) {
	read := func(action string) route.Spec {
		return route.Spec{Action: action, Permission: permPlaybookRead, Resource: "playbook"}
	}
	rt.Handle("GET /compliance/playbooks/catalog", route.Spec{Action: "playbook_catalog_read", Permission: permPlaybookRead, Resource: "playbook", Tenancy: route.PlatformScoped}, h.playbookCatalog)
	rt.Handle("GET /compliance/playbooks/summary", read("playbook_summary_read"), h.playbookSummary)
	rt.Handle("GET /compliance/playbooks", read("playbooks_listed"), h.listPlaybooks)
	rt.Handle("POST /compliance/playbooks", route.Spec{Action: "playbook_created", Permission: permPlaybookWrite, Resource: "playbook", Severity: "warning"}, h.createPlaybook)
	rt.Handle("GET /compliance/playbooks/{id}", route.Spec{Action: "playbook_read", Permission: permPlaybookRead, Resource: "playbook", TargetParam: "id"}, h.getPlaybook)
	rt.Handle("PUT /compliance/playbooks/{id}", route.Spec{Action: "playbook_updated", Permission: permPlaybookWrite, Resource: "playbook", TargetParam: "id", Severity: "warning"}, h.updatePlaybook)
	rt.Handle("DELETE /compliance/playbooks/{id}", route.Spec{Action: "playbook_deleted", Permission: permPlaybookDelete, Resource: "playbook", TargetParam: "id", Severity: "warning"}, h.deletePlaybook)
	rt.Handle("POST /compliance/playbooks/{id}/run", route.Spec{Action: "playbook_run_requested", Permission: permPlaybookRun, Resource: "playbook", TargetParam: "id", Severity: "warning"}, h.runPlaybook)
	rt.Handle("GET /compliance/playbooks/{id}/runs", route.Spec{Action: "playbook_runs_listed", Permission: permPlaybookRead, Resource: "playbook", TargetParam: "id"}, h.listPlaybookRuns)
}

func (h *Handler) playbookCatalog(c *route.Call) {
	c.JSON(http.StatusOK, map[string]interface{}{"data": map[string]interface{}{
		"triggers": playbookTriggers, "actions": playbookActions, "categories": playbookCategories,
	}})
}

func (h *Handler) listPlaybooks(c *route.Call) {
	items, err := h.svc.store.ListPlaybooks(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "list playbooks failed")
		return
	}
	for i := range items {
		items[i] = redactPlaybook(items[i])
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": items})
}

func (h *Handler) getPlaybook(c *route.Call) {
	pb, ok := h.loadPlaybook(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": redactPlaybook(pb)})
}

func (h *Handler) createPlaybook(c *route.Call) {
	var in playbookInput
	if !c.Decode(&in) {
		return
	}
	pb := in.playbook(c.Tenant, newID("pb"))
	c.Target(pb.ID)
	if !authorizePlaybook(c, &pb) {
		return
	}
	created, err := h.svc.store.CreatePlaybook(c.R.Context(), pb)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "create playbook failed")
		return
	}
	c.JSON(http.StatusCreated, map[string]interface{}{"data": redactPlaybook(created)})
}

func (h *Handler) updatePlaybook(c *route.Call) {
	stored, ok := h.loadPlaybook(c)
	if !ok {
		return
	}
	var in playbookInput
	if !c.Decode(&in) {
		return
	}
	pb := in.playbook(c.Tenant, stored.ID)
	if err := restoreSecrets(pb.Actions, stored.Actions); err != nil {
		c.Error(http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if !authorizePlaybook(c, &pb) {
		return
	}
	updated, err := h.svc.store.UpdatePlaybook(c.R.Context(), pb)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "update playbook failed")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": redactPlaybook(updated)})
}

// authorizePlaybook validates pb and binds it to the caller. An enabled
// playbook can be saved only by someone who holds every action permission,
// and it runs on that person's authority. A disabled one may be saved by any
// playbook writer; it stays unauthorized until someone who holds them saves
// it enabled.
func authorizePlaybook(c *route.Call, pb *Playbook) bool {
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
	if err := validateOutboundURLs(*pb); err != nil {
		c.Refuse(http.StatusBadRequest, reasonURLBlocked, err.Error())
		return false
	}
	missing := missingPermissions(c.Claims, pb.Actions)
	if len(missing) > 0 && pb.Enabled {
		c.Detail("missing_permissions", missing)
		c.Refuse(http.StatusForbidden, reasonActionPermission, "enabling this playbook needs "+strings.Join(missing, ", "))
		return false
	}
	pb.AuthorizedBy = ""
	if len(missing) == 0 {
		pb.AuthorizedBy = c.Actor()
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
		c.JSON(http.StatusOK, map[string]interface{}{"data": map[string]string{"status": "deleted"}})
	}
}

// runPlaybook starts a manual run on the caller's own authority: the caller
// must hold every action permission, whoever authorized the playbook.
func (h *Handler) runPlaybook(c *route.Call) {
	pb, ok := h.loadPlaybook(c)
	if !ok {
		return
	}
	c.Detail("actions", actionTypes(pb.Actions))
	if err := validatePlaybook(pb); err != nil {
		c.Refuse(http.StatusConflict, reasonPlaybookInvalid, err.Error()+"; edit the playbook")
		return
	}
	if missing := missingPermissions(c.Claims, pb.Actions); len(missing) > 0 {
		c.Detail("missing_permissions", missing)
		c.Refuse(http.StatusForbidden, reasonActionPermission, "running this playbook needs "+strings.Join(missing, ", "))
		return
	}
	if h.executor == nil {
		c.Error(http.StatusServiceUnavailable, "unavailable", "playbook executor not initialized")
		return
	}
	src := runSource{Trigger: "manual", Actor: c.Actor()}
	run, err := h.executor.Start(c.R.Context(), pb, src)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "start run failed")
		return
	}
	c.Detail("run_id", run.ID)
	h.dispatch(func() {
		ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
		defer cancel()
		h.executor.Execute(ctx, pb, run, src)
	})
	c.JSON(http.StatusAccepted, map[string]interface{}{"data": map[string]interface{}{
		"run_id": run.ID, "playbook_id": pb.ID, "status": runRunning,
	}})
}

func (h *Handler) listPlaybookRuns(c *route.Call) {
	limit, _ := strconv.Atoi(c.R.URL.Query().Get("limit"))
	runs, err := h.svc.store.ListPlaybookRuns(c.R.Context(), c.Tenant, c.R.PathValue("id"), limit)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "list runs failed")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": runs})
}

func (h *Handler) playbookSummary(c *route.Call) {
	summary, err := h.svc.store.GetPlaybookSummary(c.R.Context(), c.Tenant)
	if err != nil {
		c.Error(http.StatusInternalServerError, "internal_error", "summary failed")
		return
	}
	c.JSON(http.StatusOK, map[string]interface{}{"data": summary})
}

func (h *Handler) loadPlaybook(c *route.Call) (Playbook, bool) {
	pb, err := h.svc.store.GetPlaybook(c.R.Context(), c.Tenant, c.R.PathValue("id"))
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
