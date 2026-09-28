package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"sort"
	"strings"
	"sync"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/siem"
	"vecta-kms/pkg/ssrfguard"
	"vecta-kms/pkg/svctls"
)

// RunContext carries what every action of one run needs.
type RunContext struct {
	PlaybookID   string
	PlaybookName string
	RunID        string
	TenantID     string
	Actor        string
	Event        RunEvent // what triggered the run (SIEM alerts carry it)
}

// runSource says why a run starts and on whose authority: the person who ran
// it by hand, or the person who last authorized the playbook.
type runSource struct {
	Trigger    string // "manual", "retry" or a trigger type
	Actor      string
	ActorType  string // "user" or "client"
	Event      RunEvent
	ResumeFrom int
	RetryOf    string
}

// Action outcomes and result statuses.
const (
	outcomeDone            = "done"
	outcomePendingApproval = "pending_approval"
	resultSkipped          = "skipped"
	resultFailed           = "failed"
	resultRefused          = "refused"
	resultAwaiting         = "awaiting_approval"
)

// Run statuses.
const (
	runRunning          = "running"
	runAwaitingApproval = "awaiting_approval"
	runCompleted        = "completed"
	runPendingApproval  = "pending_approval"
	runPartialFailure   = "partial_failure"
	runFailed           = "failed"
	runCancelled        = "cancelled"
	runApprovalDenied   = "approval_denied"
	runApprovalExpired  = "approval_expired"
)

// ActionResult is one action's outcome in a run.
type ActionResult struct {
	Index     int       `json:"index"`
	Type      string    `json:"type"`
	Status    string    `json:"status"`
	Reason    string    `json:"reason,omitempty"`
	Error     string    `json:"error,omitempty"`
	Target    string    `json:"target,omitempty"`
	At        time.Time `json:"at"`
	ElapsedMS int64     `json:"elapsed_ms"`
}

// PlaybookExecutor runs playbook actions. Platform actions call keycore,
// certs, auth, governance, reporting and posture as the compliance service
// identity; notifications go through sealed connections and a client that
// reaches only public HTTPS endpoints and presents no client certificate.
type PlaybookExecutor struct {
	store    Store
	urls     platformURLs
	audit    route.Emitter
	platform *http.Client
	outbound *http.Client
	// dial opens TLS syslog connections; nil is ssrfguard.DialContext.
	dial      func(ctx context.Context, network, addr string) (net.Conn, error)
	logger    *log.Logger
	ops       complianceOps
	vault     *connVault
	authority AuthorityChecker
	approvals ApprovalService

	mu      sync.Mutex
	running map[string]context.CancelFunc
}

type complianceOps interface {
	RunAssessment(ctx context.Context, tenantID string, trigger string, recompute bool, templateID string) (AssessmentResult, error)
	GetPosture(ctx context.Context, tenantID string, refresh bool) (PostureSnapshot, error)
}

// NewPlaybookExecutor creates an executor for the given platform services.
func NewPlaybookExecutor(store Store, urls platformURLs, audit route.Emitter, vault *connVault, logger *log.Logger) *PlaybookExecutor {
	if c, ok := audit.(*pkgaudit.Client); ok && c == nil {
		audit = nil
	}
	if logger == nil {
		logger = log.Default()
	}
	for _, u := range []*string{&urls.Keycore, &urls.Certs, &urls.Auth, &urls.Governance, &urls.Reporting, &urls.Posture} {
		*u = strings.TrimRight(*u, "/")
	}
	// http.DefaultTransport is svctls's router: platform hosts over mTLS.
	platform := &http.Client{Timeout: 30 * time.Second}
	pc := platformClient{urls: urls, http: platform}
	return &PlaybookExecutor{
		store: store, urls: urls, audit: audit, platform: platform,
		outbound: ssrfguard.NewHTTPSClient(30 * time.Second), logger: logger,
		vault: vault, authority: pc, approvals: pc, running: map[string]context.CancelFunc{},
	}
}

// Start records a new run.
func (e *PlaybookExecutor) Start(ctx context.Context, pb Playbook, src runSource) (PlaybookRun, error) {
	return e.store.CreatePlaybookRun(ctx, PlaybookRun{
		ID: newID("pbrun"), PlaybookID: pb.ID, TenantID: pb.TenantID, TriggerEvent: src.Trigger,
		Actor: src.Actor, ActorType: firstNonEmpty(src.ActorType, "user"), Status: runRunning,
		Context: src.Event, IncidentID: src.Event.incidentID(), ResumeIndex: src.ResumeFrom,
		ApprovedIndex: -1, RetryOf: src.RetryOf, Results: []ActionResult{},
	})
}

// Execute runs pb's actions from run.ResumeIndex. It returns when the run
// finishes, is cancelled, or pauses for a governance approval (a later
// Resume continues it). One audit event is emitted per action, and one when
// the run finishes.
func (e *PlaybookExecutor) Execute(ctx context.Context, pb Playbook, run PlaybookRun) PlaybookRun {
	ctx, cancel := context.WithCancel(ctx)
	e.mu.Lock()
	e.running[run.ID] = cancel
	e.mu.Unlock()
	defer func() {
		cancel()
		e.mu.Lock()
		delete(e.running, run.ID)
		e.mu.Unlock()
	}()

	rc := RunContext{PlaybookID: pb.ID, PlaybookName: pb.Name, RunID: run.ID, TenantID: pb.TenantID, Actor: run.Actor, Event: run.Context}
	halted, cancelled := false, false
	for i := run.ResumeIndex; i < len(pb.Actions); i++ {
		a := pb.Actions[i]
		approved := run.ApprovedIndex == i
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		if a.DelaySeconds > 0 && !approved {
			select {
			case <-time.After(time.Duration(a.DelaySeconds) * time.Second):
			case <-ctx.Done():
				cancelled = true
			}
			if cancelled {
				break
			}
		}
		if !matchFilters(run.Context, a.Condition) {
			e.record(pb, &run, ActionResult{Index: i + 1, Type: a.Type, Status: resultSkipped, At: time.Now().UTC()}, nil)
			continue
		}
		params := renderParams(a.Parameters, run.Context, pb, run)
		if gated(a) && !approved {
			if e.requestApproval(ctx, pb, &run, i, a, params) {
				return run
			}
			if a.Parameters["stop_on_failure"] == "true" {
				halted = true
				break
			}
			continue
		}
		start := time.Now()
		outcome, err := e.executeAction(ctx, a.Type, params, rc)
		res := ActionResult{Index: i + 1, Type: a.Type, Status: outcome, Target: actionTarget(params), At: start.UTC(), ElapsedMS: time.Since(start).Milliseconds()}
		var removed actionRemovedError
		switch {
		case errors.As(err, &removed):
			res.Status, res.Reason, res.Error = resultRefused, reasonActionRemoved, err.Error()
		case err != nil:
			res.Status, res.Error = resultFailed, err.Error()
		}
		if approved {
			run.ApprovedIndex = -1
		}
		e.record(pb, &run, res, err)
		if err != nil && a.Parameters["stop_on_failure"] == "true" {
			halted = true
			break
		}
	}
	return e.finish(pb, run, halted, cancelled)
}

// record appends a result, persists the run and audits the action.
func (e *PlaybookExecutor) record(pb Playbook, run *PlaybookRun, res ActionResult, err error) {
	run.Results = append(run.Results, res)
	run.ActionsRun = len(run.Results)
	run.Output = outputOf(run.Results)
	e.save(run)
	e.emitAction(pb, *run, res, err)
}

func (e *PlaybookExecutor) save(run *PlaybookRun) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if updated, err := e.store.UpdatePlaybookRun(ctx, *run); err != nil {
		e.logger.Printf("playbook run=%s: record: %v", run.ID, err)
	} else {
		*run = updated
	}
}

func (e *PlaybookExecutor) finish(pb Playbook, run PlaybookRun, halted, cancelled bool) PlaybookRun {
	failed, pending := false, false
	for _, r := range run.Results {
		failed = failed || r.Status == resultFailed || r.Status == resultRefused
		pending = pending || r.Status == outcomePendingApproval
	}
	switch {
	case cancelled:
		run.Status = runCancelled
	case failed && halted:
		run.Status = runFailed
	case failed:
		run.Status = runPartialFailure
	case pending:
		run.Status = runPendingApproval
	default:
		run.Status = runCompleted
	}
	now := time.Now().UTC()
	run.CompletedAt = &now
	e.save(&run)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.store.IncrementPlaybookRunCount(ctx, pb.TenantID, pb.ID, now); err != nil {
		e.logger.Printf("playbook run=%s: count run: %v", run.ID, err)
	}
	e.emitRun(pb, run)
	return run
}

// endRun closes a paused run that won't resume (denied, expired, cancelled,
// or refused on resume).
func (e *PlaybookExecutor) endRun(pb Playbook, run PlaybookRun, status string, res *ActionResult) PlaybookRun {
	if res != nil {
		e.record(pb, &run, *res, errors.New(res.Error))
	}
	now := time.Now().UTC()
	run.Status, run.CompletedAt, run.ApprovalRequestID = status, &now, ""
	e.save(&run)
	e.emitRun(pb, run)
	return run
}

func outputOf(results []ActionResult) string {
	lines := make([]string, 0, len(results))
	for _, r := range results {
		line := fmt.Sprintf("[%d] %s %s", r.Index, r.Type, strings.ToUpper(r.Status))
		if r.Target != "" {
			line += " " + r.Target
		}
		if r.Error != "" {
			line += ": " + r.Error
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// actionTarget names what an action acted on, for the run record.
func actionTarget(p map[string]string) string {
	for _, k := range []string{"key_id", "cert_id", "user_id", "api_key_id", "client_id", "alert_id", "incident_id", "policy_id", "connection_id", "template_id"} {
		if v := p[k]; v != "" {
			return k + "=" + v
		}
	}
	return ""
}

// ---- approvals ----

// approvalHash binds a governance approval to one action of one run with its
// resolved parameters: a playbook edited while the run waits doesn't run
// something other than what was approved.
func approvalHash(tenantID, runID string, index int, actionType string, params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{"playbook-action", tenantID, runID, fmt.Sprint(index), actionType}
	for _, k := range keys {
		parts = append(parts, k+"="+params[k])
	}
	sum := pkgcrypto.SHA256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum)
}

func approvalTarget(runID string, index int) string { return fmt.Sprintf("%s#%d", runID, index) }

// requestApproval opens a governance request for action i and pauses the
// run. It returns false (and records the failure) when no request could be
// opened: the action doesn't run without one.
func (e *PlaybookExecutor) requestApproval(ctx context.Context, pb Playbook, run *PlaybookRun, i int, a PlaybookAction, params map[string]string) bool {
	res := ActionResult{Index: i + 1, Type: a.Type, Target: actionTarget(params), At: time.Now().UTC()}
	if e.approvals == nil {
		res.Status, res.Error = resultFailed, "approval required, but governance is not wired"
		e.record(pb, run, res, errors.New(res.Error))
		return false
	}
	id, err := e.approvals.RequestApproval(ctx, ApprovalRequestInput{
		TenantID: pb.TenantID, Action: "playbook." + a.Type, TargetType: "playbook_action",
		TargetID: approvalTarget(run.ID, i), RequesterID: run.Actor,
		TargetDetails: map[string]interface{}{
			"payload_hash": approvalHash(pb.TenantID, run.ID, i, a.Type, params),
			"playbook_id":  pb.ID, "playbook_name": pb.Name, "run_id": run.ID, "index": i + 1,
			"action": a.Type, "parameters": params, "trigger": run.TriggerEvent,
			"event_subject": run.Context.Subject, "event_target": run.Context.TargetID,
		},
	})
	if err != nil {
		res.Status, res.Error = resultFailed, "approval request refused: "+err.Error()
		e.record(pb, run, res, err)
		return false
	}
	res.Status = resultAwaiting
	run.Status, run.ApprovalRequestID, run.ResumeIndex = runAwaitingApproval, id, i
	e.record(pb, run, res, nil)
	e.emit("playbook_approval_requested", pkgaudit.Event{
		TenantID: pb.TenantID, ActorID: run.Actor, TargetType: "playbook_run", TargetID: run.ID, Result: route.ResultSuccess,
		CorrelationID: run.ID, Details: map[string]interface{}{
			"playbook_id": pb.ID, "index": i + 1, "action": a.Type, "approval_request_id": id, "severity": "warning",
		},
	})
	return true
}

// Resolve acts on a governance decision for a paused run. Approval is taken
// from governance itself, not from the event: the request must be approved,
// name this run's action and requester, and carry the hash of the action as
// the playbook now defines it. The authorizing person must still hold the
// permissions. It returns the run and whether execution continues (the
// caller runs Execute).
func (e *PlaybookExecutor) Resolve(ctx context.Context, run PlaybookRun, pb Playbook, decision string) (PlaybookRun, bool) {
	i := run.ResumeIndex
	refuse := func(reason, msg string) (PlaybookRun, bool) {
		res := ActionResult{Index: i + 1, Status: resultRefused, Reason: reason, Error: msg, At: time.Now().UTC()}
		if i < len(pb.Actions) {
			res.Type = pb.Actions[i].Type
		}
		return e.endRun(pb, run, runFailed, &res), false
	}
	switch decision {
	case "quorum_denied":
		return e.endRun(pb, run, runApprovalDenied, nil), false
	case "request_expired":
		return e.endRun(pb, run, runApprovalExpired, nil), false
	case "request_cancelled":
		return e.endRun(pb, run, runCancelled, nil), false
	case "quorum_reached":
	default:
		return run, false
	}
	if i >= len(pb.Actions) {
		return refuse("definition_changed", "the playbook no longer has this action")
	}
	a := pb.Actions[i]
	appr, err := e.approvals.GetApproval(ctx, run.TenantID, run.ApprovalRequestID)
	if err != nil {
		return refuse("approval_unverified", err.Error())
	}
	hash, _ := appr.TargetDetails["payload_hash"].(string)
	params := renderParams(a.Parameters, run.Context, pb, run)
	switch {
	case !strings.EqualFold(appr.Status, "approved"):
		return refuse("approval_mismatch", "governance reports the request as "+appr.Status)
	case appr.TargetType != "playbook_action" || appr.TargetID != approvalTarget(run.ID, i) || appr.Action != "playbook."+a.Type || appr.RequesterID != run.Actor:
		return refuse("approval_mismatch", "the approval names a different action or requester")
	case hash != approvalHash(run.TenantID, run.ID, i, a.Type, params):
		return refuse("definition_changed", "the action changed after approval was requested")
	}
	if run.ActorType == "user" {
		if reason, msg := e.checkAuthority(ctx, run.TenantID, run.Actor, requiredPermissions(pb.Actions[i:])); reason != "" {
			return refuse(reason, msg)
		}
	}
	run.Status, run.ApprovedIndex, run.ApprovalRequestID = runRunning, i, ""
	e.save(&run)
	e.emit("playbook_approval_granted", pkgaudit.Event{
		TenantID: run.TenantID, ActorID: run.Actor, TargetType: "playbook_run", TargetID: run.ID, Result: route.ResultSuccess,
		CorrelationID: run.ID, Details: map[string]interface{}{"playbook_id": pb.ID, "index": i + 1, "action": a.Type, "approval_request_id": appr.ID, "severity": "info"},
	})
	return run, true
}

// checkAuthority asks auth whether user is active and holds perms now. It
// returns a refusal reason and message, or "" when the authority stands.
func (e *PlaybookExecutor) checkAuthority(ctx context.Context, tenantID, user string, perms []string) (string, string) {
	if e.authority == nil {
		return reasonAuthorityUnknown, "auth is not wired"
	}
	a, err := e.authority.Authority(ctx, tenantID, user, perms)
	switch {
	case err != nil:
		return reasonAuthorityUnknown, err.Error()
	case !a.Active:
		return reasonAuthorityRevoked, user + " is no longer an active user"
	case len(a.Missing) > 0:
		return reasonAuthorityRevoked, user + " no longer holds " + strings.Join(a.Missing, ", ")
	}
	return "", ""
}

// Cancel stops a run: a running one at its next step, a paused one at once
// (its governance request is withdrawn).
func (e *PlaybookExecutor) Cancel(ctx context.Context, pb Playbook, run PlaybookRun) (PlaybookRun, error) {
	switch run.Status {
	case runRunning:
		e.mu.Lock()
		cancel, ok := e.running[run.ID]
		e.mu.Unlock()
		if !ok {
			return run, errors.New("the run is not executing on this node")
		}
		cancel()
		return run, nil
	case runAwaitingApproval:
		if e.approvals != nil && run.ApprovalRequestID != "" {
			if err := e.approvals.CancelApproval(ctx, run.TenantID, run.ApprovalRequestID, run.Actor); err != nil {
				e.logger.Printf("playbook run=%s: withdraw approval %s: %v", run.ID, run.ApprovalRequestID, err)
			}
		}
		return e.endRun(pb, run, runCancelled, nil), nil
	}
	return run, fmt.Errorf("a %s run can't be cancelled", run.Status)
}

// ---- actions ----

// actionRemovedError is an action saved before it left the catalogue
// (destroy_key, notify_soc, ...).
type actionRemovedError struct{ action string }

func (e actionRemovedError) Error() string {
	return fmt.Sprintf("action %q is not supported; edit the playbook", e.action)
}

// executeAction performs one action with resolved parameters. A platform
// call that opens its own approval instead of acting returns
// outcomePendingApproval, never done.
func (e *PlaybookExecutor) executeAction(ctx context.Context, typ string, p map[string]string, rc RunContext) (string, error) {
	spec, known := actionByType[typ]
	if !known {
		return "", actionRemovedError{typ}
	}
	for _, k := range spec.Required {
		if strings.TrimSpace(p[k]) == "" {
			return "", fmt.Errorf("parameter %s resolved empty", k)
		}
	}
	esc := neturl.PathEscape
	post := func(base, path string, body interface{}) (string, error) {
		return e.platformCall(ctx, http.MethodPost, base+path, rc, body)
	}
	put := func(base, path string, body interface{}) (string, error) {
		return e.platformCall(ctx, http.MethodPut, base+path, rc, body)
	}
	delegated := func(path string) (string, error) {
		return post(e.urls.Auth, path, map[string]string{
			"on_behalf_of": rc.Actor, "reason": "playbook " + rc.PlaybookID + " run " + rc.RunID, "playbook_run_id": rc.RunID,
		})
	}
	switch typ {
	case "send_slack":
		return e.notifyVia(ctx, rc, p["connection_id"], "slack", func(conn Connection) (string, error) {
			f := conn.Fields
			return e.outboundCall(ctx, http.MethodPost, f["webhook_url"], map[string]any{"text": messageOr(p)}, nil)
		})
	case "send_teams":
		return e.notifyVia(ctx, rc, p["connection_id"], "teams", func(conn Connection) (string, error) {
			f := conn.Fields
			return e.outboundCall(ctx, http.MethodPost, f["webhook_url"], teamsCard(messageOr(p)), nil)
		})
	case "send_webhook":
		return e.notifyVia(ctx, rc, p["connection_id"], "webhook", func(conn Connection) (string, error) {
			f := conn.Fields
			headers := map[string]string{}
			if raw := strings.TrimSpace(f["headers"]); raw != "" {
				if err := json.Unmarshal([]byte(raw), &headers); err != nil {
					return "", errors.New("connection headers are not a JSON object")
				}
			}
			body := json.RawMessage(`{}`)
			if b := strings.TrimSpace(p["body"]); b != "" {
				if !json.Valid([]byte(b)) {
					return "", errors.New("body is not valid JSON after templating")
				}
				body = json.RawMessage(b)
			}
			if f["signing_secret"] != "" {
				headers["X-KMS-Signature"] = signature(f["signing_secret"], body)
			}
			return e.outboundCall(ctx, firstNonEmpty(strings.ToUpper(strings.TrimSpace(p["method"])), http.MethodPost), f["url"], body, headers)
		})
	case "send_siem_alert":
		return e.notifyVia(ctx, rc, p["connection_id"], categorySIEM, func(conn Connection) (string, error) {
			return outcomeDone, e.sendSIEM(ctx, conn, siemAlert(rc, p))
		})
	case "create_jira_ticket":
		return e.notifyVia(ctx, rc, p["connection_id"], "jira", func(conn Connection) (string, error) {
			f := conn.Fields
			return e.outboundCall(ctx, http.MethodPost, strings.TrimRight(f["base_url"], "/")+"/rest/api/2/issue", map[string]any{"fields": map[string]any{
				"project": map[string]string{"key": p["project"]}, "summary": p["summary"], "description": p["description"],
				"issuetype": map[string]string{"name": firstNonEmpty(p["issuetype"], "Task")},
			}}, bearerOrBasic("Basic ", f["api_token"]))
		})
	case "create_servicenow_incident":
		return e.notifyVia(ctx, rc, p["connection_id"], "servicenow", func(conn Connection) (string, error) {
			f := conn.Fields
			return e.outboundCall(ctx, http.MethodPost, strings.TrimRight(f["instance_url"], "/")+"/api/now/table/incident", map[string]any{
				"short_description": p["short_description"], "description": p["description"],
				"urgency": firstNonEmpty(p["urgency"], "2"), "impact": firstNonEmpty(p["impact"], "2"), "caller_id": p["caller_id"],
			}, bearerOrBasic("Bearer ", f["auth_token"]))
		})
	case "send_email":
		var to []string
		for _, r := range strings.Split(p["to"], ",") {
			if r = strings.TrimSpace(r); r != "" {
				to = append(to, r)
			}
		}
		return post(e.urls.Governance, "/governance/notify/email", map[string]interface{}{
			"to": to, "subject": p["subject"], "body": p["body"], "playbook_run_id": rc.RunID,
		})
	case "create_audit_event":
		if e.audit == nil {
			return "", errors.New("audit pipeline unavailable")
		}
		return outcomeDone, e.audit.Emit(ctx, "playbook_action", pkgaudit.Event{
			TenantID: rc.TenantID, ActorID: rc.Actor, TargetType: "playbook_run", TargetID: rc.RunID, CorrelationID: rc.RunID,
			Details: map[string]interface{}{"playbook_id": rc.PlaybookID, "run_id": rc.RunID, "message": p["message"]},
		})
	case "rotate_key":
		return post(e.urls.Keycore, "/keys/"+esc(p["key_id"])+"/rotate", map[string]string{"reason": "playbook " + rc.PlaybookID + " run " + rc.RunID})
	case "disable_key":
		return post(e.urls.Keycore, "/keys/"+esc(p["key_id"])+"/disable", map[string]string{})
	case "deactivate_key":
		return post(e.urls.Keycore, "/keys/"+esc(p["key_id"])+"/deactivate", map[string]string{})
	case "activate_key":
		return post(e.urls.Keycore, "/keys/"+esc(p["key_id"])+"/activate", map[string]string{"mode": "immediate"})
	case "trigger_rotation_policy":
		return post(e.urls.Keycore, "/rotation/policies/"+esc(p["policy_id"])+"/trigger", nil)
	case "renew_certificate":
		return post(e.urls.Certs, "/certs/"+esc(p["cert_id"])+"/renew", map[string]string{})
	case "revoke_certificate":
		return post(e.urls.Certs, "/certs/"+esc(p["cert_id"])+"/revoke", map[string]string{"reason": firstNonEmpty(p["reason"], "playbook "+rc.PlaybookID)})
	case "disable_user":
		return delegated("/auth/delegated/users/" + esc(p["user_id"]) + "/disable")
	case "revoke_api_key":
		return delegated("/auth/delegated/api-keys/" + esc(p["api_key_id"]) + "/revoke")
	case "revoke_client":
		return delegated("/auth/delegated/clients/" + esc(p["client_id"]) + "/revoke")
	case "acknowledge_alert":
		return put(e.urls.Reporting, "/alerts/"+esc(p["alert_id"])+"/acknowledge", map[string]string{})
	case "resolve_alert":
		return put(e.urls.Reporting, "/alerts/"+esc(p["alert_id"])+"/resolve", map[string]string{"note": p["note"]})
	case "set_incident_status":
		status := strings.ToLower(strings.TrimSpace(p["status"]))
		if !incidentStatuses[status] {
			return "", fmt.Errorf("status %q is not open, investigating, resolved or closed", status)
		}
		return put(e.urls.Reporting, "/incidents/"+esc(p["incident_id"])+"/status", map[string]string{"status": status, "notes": p["notes"]})
	case "assign_incident":
		return put(e.urls.Reporting, "/incidents/"+esc(p["incident_id"])+"/assign", map[string]string{"assigned_to": p["assigned_to"]})
	case "generate_report":
		return post(e.urls.Reporting, "/reports/generate", map[string]string{"template_id": p["template_id"], "format": firstNonEmpty(p["format"], "pdf")})
	case "run_posture_scan":
		return post(e.urls.Posture, "/posture/scan", nil)
	case "trigger_assessment":
		if e.ops == nil {
			return "", errors.New("compliance service not wired")
		}
		_, err := e.ops.RunAssessment(ctx, rc.TenantID, "playbook:"+rc.RunID, true, p["template_id"])
		return outcomeDone, err
	case "snapshot_posture":
		if e.ops == nil {
			return "", errors.New("compliance service not wired")
		}
		_, err := e.ops.GetPosture(ctx, rc.TenantID, true)
		return outcomeDone, err
	}
	return "", actionRemovedError{typ}
}

func bearerOrBasic(prefix, token string) map[string]string {
	if token == "" {
		return nil
	}
	return map[string]string{"Authorization": prefix + token}
}

// platformCall calls a platform service as the compliance service identity,
// for the run's tenant, correlated to the run.
func (e *PlaybookExecutor) platformCall(ctx context.Context, method, url string, rc RunContext, body interface{}) (string, error) {
	status, err := callJSON(ctx, e.platform, method, url, rc.TenantID, rc.RunID, body, nil)
	if err != nil {
		return "", err
	}
	if status == outcomePendingApproval {
		return outcomePendingApproval, nil
	}
	return outcomeDone, nil
}

// notifyVia opens the named connection (which must fit kind) and sends
// through it.
func (e *PlaybookExecutor) notifyVia(ctx context.Context, rc RunContext, connID, kind string, send func(Connection) (string, error)) (string, error) {
	conn, err := e.store.GetConnection(ctx, rc.TenantID, connID)
	if err != nil {
		return "", fmt.Errorf("connection %s: %w", connID, err)
	}
	if !connectionFits(kind, conn.Type) {
		return "", fmt.Errorf("connection %s is %s, not %s", connID, conn.Type, kind)
	}
	opened, err := e.vault.Open(conn)
	if err != nil {
		return "", err
	}
	return send(opened)
}

// sendSIEM delivers events through an opened SIEM connection (pkg/siem),
// over the outbound client: public HTTPS at TLS 1.3, or TLS syslog.
func (e *PlaybookExecutor) sendSIEM(ctx context.Context, conn Connection, events ...siem.Event) error {
	d, err := siem.New(conn.Type, conn.Fields, siem.Options{Client: e.outbound, Dial: e.dial})
	if err != nil {
		return err
	}
	_, err = d.Send(ctx, events)
	return err
}

// siemAlert is the event a send_siem_alert action raises: the playbook, the
// run and the event that triggered it, at the chosen severity.
func siemAlert(rc RunContext, p map[string]string) siem.Event {
	ev := rc.Event
	title := firstNonEmpty(strings.TrimSpace(p["title"]), "Vecta KMS playbook "+firstNonEmpty(rc.PlaybookName, rc.PlaybookID)+" responded to "+firstNonEmpty(ev.Subject, "a manual run"))
	severity := firstNonEmpty(strings.ToLower(strings.TrimSpace(p["severity"])), "high")
	return siem.Event{
		ID: rc.RunID, Timestamp: time.Now().UTC(), TenantID: rc.TenantID, Service: "compliance", Action: "audit.compliance.playbook_alert",
		ActorID: rc.Actor, TargetType: firstNonEmpty(ev.TargetType, "playbook_run"), TargetID: firstNonEmpty(ev.TargetID, rc.RunID),
		Result: "alert", Severity: severity,
		Record: map[string]any{
			"title": title, "severity": severity, "playbook_id": rc.PlaybookID, "playbook_name": rc.PlaybookName, "run_id": rc.RunID,
			"authorized_by": rc.Actor, "trigger_event": ev,
		},
	}
}

// signature is the X-KMS-Signature header for body under a webhook
// connection's signing secret (HMAC-SHA256 from pkg/crypto).
func signature(secret string, body json.RawMessage) string {
	return "sha256=" + hex.EncodeToString(pkgcrypto.HMACSHA256([]byte(secret), body))
}

// testConnection makes a harmless real call through a connection.
func (e *PlaybookExecutor) testConnection(ctx context.Context, conn Connection) error {
	opened, err := e.vault.Open(conn)
	if err != nil {
		return err
	}
	f := opened.Fields
	msg := "Vecta KMS connection test (" + conn.Name + ")"
	switch conn.Type {
	case "slack":
		_, err = e.outboundCall(ctx, http.MethodPost, f["webhook_url"], map[string]any{"text": msg}, nil)
	case "teams":
		_, err = e.outboundCall(ctx, http.MethodPost, f["webhook_url"], teamsCard(msg), nil)
	case "webhook":
		headers := map[string]string{}
		_ = json.Unmarshal([]byte(firstNonEmpty(f["headers"], "{}")), &headers)
		body, _ := json.Marshal(map[string]any{"test": true, "source": "vecta-kms", "message": msg})
		if f["signing_secret"] != "" {
			headers["X-KMS-Signature"] = signature(f["signing_secret"], body)
		}
		_, err = e.outboundCall(ctx, http.MethodPost, f["url"], json.RawMessage(body), headers)
	case "jira":
		_, err = e.outboundCall(ctx, http.MethodGet, strings.TrimRight(f["base_url"], "/")+"/rest/api/2/myself", nil, bearerOrBasic("Basic ", f["api_token"]))
	case "servicenow":
		_, err = e.outboundCall(ctx, http.MethodGet, strings.TrimRight(f["instance_url"], "/")+"/api/now/table/incident?sysparm_limit=1", nil, bearerOrBasic("Bearer ", f["auth_token"]))
	default:
		if connectionByType[conn.Type].Category == categorySIEM {
			// A real event, labelled as a test, through the same path a
			// stream or alert uses.
			err = e.sendSIEM(ctx, opened, siem.Event{
				ID: newID("conntest"), Timestamp: time.Now().UTC(), TenantID: conn.TenantID, Service: "compliance",
				Action: "audit.compliance.connection_tested", TargetType: "playbook_connection", TargetID: conn.ID,
				Result: "success", Severity: "info", Record: map[string]any{"message": msg, "test": true, "connection_id": conn.ID},
			})
			break
		}
		err = fmt.Errorf("unsupported connection type %q", conn.Type)
	}
	return err
}

// outboundCall calls an external endpoint. Errors name the host only: a
// webhook URL (Slack, Teams) is itself a credential.
func (e *PlaybookExecutor) outboundCall(ctx context.Context, method, rawURL string, payload any, headers map[string]string) (string, error) {
	u, err := neturl.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", errors.New("endpoint must be an https URL")
	}
	if svctls.IsInternalHost(u.Hostname()) {
		return "", fmt.Errorf("%s is a platform service, not an external endpoint", u.Hostname())
	}
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return "", errors.New("request body must be valid JSON")
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return "", errors.New("invalid request")
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.outbound.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s: %v", u.Hostname(), unwrapURLError(err))
	}
	defer resp.Body.Close() //nolint:errcheck
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8192))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("%s answered HTTP %d", u.Hostname(), resp.StatusCode)
	}
	return outcomeDone, nil
}

// unwrapURLError drops the *url.Error wrapper, which quotes the full URL.
func unwrapURLError(err error) error {
	var ue *neturl.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// ---- dry run ----

// DryRunStep is what a run would do at one action, checked without acting.
type DryRunStep struct {
	Index         int               `json:"index"`
	Type          string            `json:"type"`
	WouldRun      bool              `json:"would_run"`
	Reason        string            `json:"reason,omitempty"`
	Parameters    map[string]string `json:"parameters,omitempty"`
	Permission    string            `json:"permission,omitempty"`
	HasPermission bool              `json:"has_permission"`
	Approval      bool              `json:"approval_required"`
	TargetCheck   string            `json:"target_check"`
}

// DryRun resolves every action against ev and checks, by reading the owning
// service, that each target exists. Nothing is changed and no message sent.
func (e *PlaybookExecutor) DryRun(ctx context.Context, pb Playbook, ev RunEvent, allowed func(string) bool) []DryRunStep {
	run := PlaybookRun{ID: "dry-run", TriggerEvent: "dry_run", Context: ev}
	rc := RunContext{PlaybookID: pb.ID, RunID: run.ID, TenantID: pb.TenantID}
	steps := make([]DryRunStep, 0, len(pb.Actions))
	for i, a := range pb.Actions {
		spec, known := actionByType[a.Type]
		st := DryRunStep{Index: i + 1, Type: a.Type, Permission: spec.Permission, Approval: gated(a), HasPermission: spec.Permission == "" || allowed(spec.Permission), TargetCheck: "not checked"}
		if !known {
			st.Reason = actionRemovedError{a.Type}.Error()
			steps = append(steps, st)
			continue
		}
		if !matchFilters(ev, a.Condition) {
			st.Reason = "condition does not match the event"
			steps = append(steps, st)
			continue
		}
		st.Parameters = renderParams(a.Parameters, ev, pb, run)
		st.WouldRun = true
		for _, k := range spec.Required {
			if strings.TrimSpace(st.Parameters[k]) == "" {
				st.WouldRun, st.Reason = false, "parameter "+k+" resolves empty"
			}
		}
		if st.WouldRun {
			st.TargetCheck = e.checkTarget(ctx, a.Type, st.Parameters, rc)
		}
		steps = append(steps, st)
	}
	return steps
}

// checkTarget reads the action's target from its owning service.
func (e *PlaybookExecutor) checkTarget(ctx context.Context, typ string, p map[string]string, rc RunContext) string {
	esc := neturl.PathEscape
	get := func(url string) string {
		if _, err := callJSON(ctx, e.platform, http.MethodGet, url, rc.TenantID, "", nil, nil); err != nil {
			return "not found: " + err.Error()
		}
		return "found"
	}
	switch typ {
	case "rotate_key", "disable_key", "deactivate_key", "activate_key":
		return get(e.urls.Keycore + "/keys/" + esc(p["key_id"]) + "?tenant_id=" + neturl.QueryEscape(rc.TenantID))
	case "renew_certificate", "revoke_certificate":
		return get(e.urls.Certs + "/certs/" + esc(p["cert_id"]) + "?tenant_id=" + neturl.QueryEscape(rc.TenantID))
	case "acknowledge_alert", "resolve_alert":
		return get(e.urls.Reporting + "/alerts/" + esc(p["alert_id"]))
	case "set_incident_status", "assign_incident":
		return get(e.urls.Reporting + "/incidents/" + esc(p["incident_id"]))
	case "send_slack", "send_teams", "send_webhook", "create_jira_ticket", "create_servicenow_incident", "send_siem_alert":
		conn, err := e.store.GetConnection(ctx, rc.TenantID, p["connection_id"])
		if err != nil {
			return "connection not found"
		}
		return "connection " + conn.Name + " (" + conn.Endpoint + ")"
	}
	return "not checked"
}

// ---- audit ----

func (e *PlaybookExecutor) emitAction(pb Playbook, run PlaybookRun, res ActionResult, err error) {
	result, severity := route.ResultSuccess, "info"
	if actionByType[res.Type].Permission != "" {
		severity = "warning"
	}
	details := map[string]interface{}{
		"playbook_id": pb.ID, "playbook_name": pb.Name, "run_id": run.ID, "index": res.Index, "action": res.Type,
		"trigger": run.TriggerEvent, "authorized_by": run.Actor, "executed_as": "kms-compliance", "outcome": res.Status,
	}
	if res.Target != "" {
		details["target"] = res.Target
	}
	if run.IncidentID != "" {
		details["incident_id"] = run.IncidentID
	}
	switch res.Status {
	case resultRefused:
		result, severity = route.ResultRefused, "warning"
		details["reason"] = res.Reason
	case resultFailed:
		result, severity = route.ResultFailure, "warning"
	case outcomePendingApproval, resultAwaiting:
		result = "pending"
	case resultSkipped:
		result = "skipped"
	}
	details["severity"] = severity
	evt := pkgaudit.Event{
		TenantID: pb.TenantID, ActorID: run.Actor, TargetType: "playbook_run", TargetID: run.ID,
		Result: result, CorrelationID: run.ID, DurationMS: float64(res.ElapsedMS), Details: details,
	}
	if err != nil {
		evt.ErrorMessage = res.Error
	}
	e.emit("playbook_action_executed", evt)
}

func (e *PlaybookExecutor) emitRun(pb Playbook, run PlaybookRun) {
	result, severity := route.ResultFailure, "warning"
	switch run.Status {
	case runCompleted:
		result, severity = route.ResultSuccess, "info"
	case runPendingApproval:
		result, severity = "pending", "info"
	case runCancelled, runApprovalDenied, runApprovalExpired:
		result = route.ResultRefused
	}
	e.emit("playbook_run_completed", pkgaudit.Event{
		TenantID: pb.TenantID, ActorID: run.Actor, TargetType: "playbook", TargetID: pb.ID,
		Result: result, CorrelationID: run.ID,
		Details: map[string]interface{}{
			"playbook_name": pb.Name, "run_id": run.ID, "status": run.Status, "reason": run.Status,
			"actions_run": run.ActionsRun, "actions_total": len(pb.Actions), "trigger": run.TriggerEvent,
			"subject": run.Context.Subject, "event_target": run.Context.TargetID, "incident_id": run.IncidentID,
			"retry_of": run.RetryOf, "authorized_by": run.Actor, "severity": severity,
		},
	})
}

func (e *PlaybookExecutor) emit(action string, evt pkgaudit.Event) {
	if e.audit == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.audit.Emit(ctx, action, evt); err != nil {
		e.logger.Printf("playbook: audit %s: %v", action, err)
	}
}

func messageOr(p map[string]string) string {
	return firstNonEmpty(strings.TrimSpace(p["message"]), "KMS playbook triggered")
}

func teamsCard(message string) map[string]any {
	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]any{
				"$schema": "https://adaptivecards.io/schemas/adaptive-card.json",
				"type":    "AdaptiveCard",
				"version": "1.4",
				"body":    []map[string]any{{"type": "TextBlock", "text": message, "wrap": true}},
			},
		}},
	}
}
