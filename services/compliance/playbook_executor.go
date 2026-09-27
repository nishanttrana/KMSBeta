package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/servicetoken"
	"vecta-kms/pkg/ssrfguard"
	"vecta-kms/pkg/svctls"
)

// RunContext carries what every action of one run needs.
type RunContext struct {
	PlaybookID string
	RunID      string
	TenantID   string
}

// runSource says why a run started and on whose authority: the person who
// ran it by hand, or the person who last authorized the playbook.
type runSource struct {
	Trigger string // "manual" or a trigger type
	Subject string // the audit subject that fired it
	EventID string // that event's target, when it names one
	Actor   string
}

// Action outcomes.
const (
	outcomeDone            = "done"
	outcomePendingApproval = "pending_approval"
)

// Run statuses.
const (
	runRunning         = "running"
	runCompleted       = "completed"
	runPendingApproval = "pending_approval"
	runPartialFailure  = "partial_failure"
	runFailed          = "failed"
	runCancelled       = "cancelled"
)

// PlaybookExecutor runs playbook actions. Key and certificate actions call
// keycore and certs as the compliance service identity; notifications go
// through a client that reaches only public HTTPS endpoints and presents no
// client certificate.
type PlaybookExecutor struct {
	store      Store
	keycoreURL string
	certsURL   string
	audit      route.Emitter
	platform   *http.Client
	outbound   *http.Client
	logger     *log.Logger
	// ops runs compliance actions in-process (this service owns them).
	ops complianceOps
}

type complianceOps interface {
	RunAssessment(ctx context.Context, tenantID string, trigger string, recompute bool, templateID string) (AssessmentResult, error)
	GetPosture(ctx context.Context, tenantID string, refresh bool) (PostureSnapshot, error)
}

// NewPlaybookExecutor creates an executor for the given platform services.
func NewPlaybookExecutor(store Store, keycoreURL, certsURL string, audit route.Emitter, logger *log.Logger) *PlaybookExecutor {
	if c, ok := audit.(*pkgaudit.Client); ok && c == nil {
		audit = nil
	}
	if logger == nil {
		logger = log.Default()
	}
	return &PlaybookExecutor{
		store:      store,
		keycoreURL: strings.TrimRight(keycoreURL, "/"),
		certsURL:   strings.TrimRight(certsURL, "/"),
		audit:      audit,
		// http.DefaultTransport is svctls's router: platform hosts over mTLS.
		platform: &http.Client{Timeout: 30 * time.Second},
		outbound: ssrfguard.NewHTTPSClient(30 * time.Second),
		logger:   logger,
	}
}

// Start records a new run.
func (e *PlaybookExecutor) Start(ctx context.Context, pb Playbook, src runSource) (PlaybookRun, error) {
	return e.store.CreatePlaybookRun(ctx, PlaybookRun{
		ID:           newID("pbrun"),
		PlaybookID:   pb.ID,
		TenantID:     pb.TenantID,
		TriggerEvent: src.Trigger,
		Actor:        src.Actor,
		Status:       runRunning,
	})
}

// Execute runs every action of pb in order, records the outcome on run, and
// emits one audit event per action and one for the run.
func (e *PlaybookExecutor) Execute(ctx context.Context, pb Playbook, run PlaybookRun, src runSource) PlaybookRun {
	rc := RunContext{PlaybookID: pb.ID, RunID: run.ID, TenantID: pb.TenantID}
	var (
		lines                              []string
		ran                                int
		failed, pending, halted, cancelled bool
	)
	for i, a := range pb.Actions {
		if a.DelaySeconds > 0 {
			select {
			case <-time.After(time.Duration(a.DelaySeconds) * time.Second):
			case <-ctx.Done():
				cancelled = true
			}
			if cancelled {
				lines = append(lines, fmt.Sprintf("[%d] cancelled before %s", i+1, a.Type))
				break
			}
		}
		start := time.Now()
		outcome, err := e.executeAction(ctx, a, rc)
		took := time.Since(start).Round(time.Millisecond)
		ran++
		e.emitAction(pb, run, src, i, a, outcome, err, took)
		switch {
		case err != nil:
			failed = true
			lines = append(lines, fmt.Sprintf("[%d] %s FAILED (%s): %s", i+1, a.Type, took, err))
		case outcome == outcomePendingApproval:
			pending = true
			lines = append(lines, fmt.Sprintf("[%d] %s PENDING APPROVAL (%s)", i+1, a.Type, took))
		default:
			lines = append(lines, fmt.Sprintf("[%d] %s OK (%s)", i+1, a.Type, took))
		}
		if err != nil && a.Parameters["stop_on_failure"] == "true" {
			halted = true
			lines = append(lines, fmt.Sprintf("[%d] stop_on_failure: remaining actions skipped", i+1))
			break
		}
	}

	now := time.Now().UTC()
	run.ActionsRun, run.Output, run.CompletedAt = ran, strings.Join(lines, "\n"), &now
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
	// The run's context may have expired; the record must still be written.
	sctx, done := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer done()
	if updated, err := e.store.UpdatePlaybookRun(sctx, run); err != nil {
		e.logger.Printf("playbook run=%s: record outcome: %v", run.ID, err)
	} else {
		run = updated
	}
	if err := e.store.IncrementPlaybookRunCount(sctx, pb.TenantID, pb.ID, now); err != nil {
		e.logger.Printf("playbook run=%s: count run: %v", run.ID, err)
	}
	e.emitRun(pb, run, src)
	return run
}

// executeAction performs one action. A platform call that opens an approval
// instead of acting returns outcomePendingApproval, never done.
func (e *PlaybookExecutor) executeAction(ctx context.Context, a PlaybookAction, rc RunContext) (string, error) {
	p := a.Parameters
	keyPath := func(op string) string { return "/keys/" + neturl.PathEscape(p["key_id"]) + "/" + op }
	certPath := func(op string) string { return "/certs/" + neturl.PathEscape(p["cert_id"]) + "/" + op }
	switch a.Type {
	case "send_slack":
		return e.notify(ctx, http.MethodPost, p["webhook_url"], map[string]any{"text": messageOr(p)}, nil)
	case "send_teams":
		return e.notify(ctx, http.MethodPost, p["webhook_url"], teamsCard(messageOr(p)), nil)
	case "send_webhook":
		headers := map[string]string{}
		if raw := strings.TrimSpace(p["headers"]); raw != "" {
			if err := json.Unmarshal([]byte(raw), &headers); err != nil {
				return "", errors.New("headers must be a JSON object of strings")
			}
		}
		body := json.RawMessage("{}")
		if b := strings.TrimSpace(p["body"]); b != "" {
			body = json.RawMessage(b)
		}
		return e.notify(ctx, firstNonEmpty(strings.ToUpper(strings.TrimSpace(p["method"])), http.MethodPost), p["url"], body, headers)
	case "create_jira_ticket":
		headers := map[string]string{}
		if t := p["api_token"]; t != "" {
			headers["Authorization"] = "Basic " + t
		}
		return e.notify(ctx, http.MethodPost, strings.TrimRight(p["base_url"], "/")+"/rest/api/2/issue", map[string]any{"fields": map[string]any{
			"project":     map[string]string{"key": p["project"]},
			"summary":     p["summary"],
			"description": p["description"],
			"issuetype":   map[string]string{"name": firstNonEmpty(p["issuetype"], "Task")},
		}}, headers)
	case "create_servicenow_incident":
		headers := map[string]string{}
		if t := p["auth_token"]; t != "" {
			headers["Authorization"] = "Bearer " + t
		}
		return e.notify(ctx, http.MethodPost, strings.TrimRight(p["instance_url"], "/")+"/api/now/table/incident", map[string]any{
			"short_description": p["short_description"],
			"description":       p["description"],
			"urgency":           firstNonEmpty(p["urgency"], "2"),
			"impact":            firstNonEmpty(p["impact"], "2"),
			"caller_id":         p["caller_id"],
		}, headers)
	case "create_audit_event":
		if e.audit == nil {
			return "", errors.New("audit pipeline unavailable")
		}
		return outcomeDone, e.audit.Emit(ctx, "playbook_action", pkgaudit.Event{
			TenantID: rc.TenantID, TargetType: "playbook_run", TargetID: rc.RunID, CorrelationID: rc.RunID,
			Details: map[string]interface{}{"playbook_id": rc.PlaybookID, "run_id": rc.RunID, "message": p["message"]},
		})
	case "rotate_key":
		return e.platformCall(ctx, e.keycoreURL, keyPath("rotate"), rc, map[string]string{"reason": "playbook " + rc.PlaybookID + " run " + rc.RunID})
	case "disable_key":
		return e.platformCall(ctx, e.keycoreURL, keyPath("disable"), rc, map[string]string{})
	case "deactivate_key":
		return e.platformCall(ctx, e.keycoreURL, keyPath("deactivate"), rc, map[string]string{})
	case "activate_key":
		return e.platformCall(ctx, e.keycoreURL, keyPath("activate"), rc, map[string]string{"mode": "immediate"})
	case "renew_certificate":
		return e.platformCall(ctx, e.certsURL, certPath("renew"), rc, map[string]string{})
	case "revoke_certificate":
		return e.platformCall(ctx, e.certsURL, certPath("revoke"), rc, map[string]string{"reason": firstNonEmpty(p["reason"], "playbook "+rc.PlaybookID)})
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
	default:
		return "", actionRemovedError{a.Type}
	}
}

// actionRemovedError is an action saved before it left the catalogue
// (destroy_key, send_pagerduty, disable_user, ...).
type actionRemovedError struct{ action string }

func (e actionRemovedError) Error() string {
	return fmt.Sprintf("action %q is not supported; edit the playbook", e.action)
}

// platformCall POSTs to a platform service as the compliance service
// identity, for the run's tenant.
func (e *PlaybookExecutor) platformCall(ctx context.Context, base, path string, rc RunContext, body map[string]string) (string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", rc.TenantID)
	req.Header.Set("X-Correlation-ID", rc.RunID)
	servicetoken.Authorize(ctx, req)
	resp, err := e.platform.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s unreachable: %w", req.URL.Host, unwrapURLError(err))
	}
	defer resp.Body.Close() //nolint:errcheck
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	var out struct {
		Status string `json:"status"`
		Error  struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(payload, &out)
	if resp.StatusCode >= 400 {
		msg := http.StatusText(resp.StatusCode)
		if out.Error.Code != "" {
			msg = out.Error.Code + ": " + out.Error.Message
		}
		return "", fmt.Errorf("%s HTTP %d %s", req.URL.Host, resp.StatusCode, msg)
	}
	if out.Status == outcomePendingApproval {
		return outcomePendingApproval, nil
	}
	return outcomeDone, nil
}

// notify calls an external endpoint. Errors name the host only: a webhook URL
// (Slack, Teams) is itself a credential.
func (e *PlaybookExecutor) notify(ctx context.Context, method, rawURL string, payload any, headers map[string]string) (string, error) {
	u, err := neturl.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", errors.New("endpoint must be an https URL")
	}
	if svctls.IsInternalHost(u.Hostname()) {
		return "", fmt.Errorf("%s is a platform service, not an external endpoint", u.Hostname())
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", errors.New("request body must be valid JSON")
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(raw))
	if err != nil {
		return "", errors.New("invalid request")
	}
	req.Header.Set("Content-Type", "application/json")
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

func (e *PlaybookExecutor) emitAction(pb Playbook, run PlaybookRun, src runSource, i int, a PlaybookAction, outcome string, err error, took time.Duration) {
	result, severity := route.ResultSuccess, "info"
	if actionByType[a.Type].Permission != "" {
		severity = "warning"
	}
	details := map[string]interface{}{
		"playbook_id": pb.ID, "playbook_name": pb.Name, "run_id": run.ID,
		"index": i + 1, "action": a.Type, "trigger": src.Trigger,
		"authorized_by": src.Actor, "executed_as": "kms-compliance",
	}
	for _, k := range []string{"key_id", "cert_id", "template_id"} {
		if v := a.Parameters[k]; v != "" {
			details[k] = v
		}
	}
	var removed actionRemovedError
	switch {
	case errors.As(err, &removed):
		result, severity = route.ResultRefused, "warning"
		details["reason"] = reasonActionRemoved
	case err != nil:
		result, severity = route.ResultFailure, "warning"
	case outcome == outcomePendingApproval:
		result = "pending"
	}
	details["outcome"] = firstNonEmpty(outcome, result)
	details["severity"] = severity
	evt := pkgaudit.Event{
		TenantID: pb.TenantID, ActorID: src.Actor, TargetType: "playbook_run", TargetID: run.ID,
		Result: result, CorrelationID: run.ID, DurationMS: float64(took.Milliseconds()), Details: details,
	}
	if err != nil {
		evt.ErrorMessage = err.Error()
	}
	e.emit("playbook_action_executed", evt)
}

func (e *PlaybookExecutor) emitRun(pb Playbook, run PlaybookRun, src runSource) {
	result, severity := route.ResultFailure, "warning"
	switch run.Status {
	case runCompleted:
		result, severity = route.ResultSuccess, "info"
	case runPendingApproval:
		result, severity = "pending", "info"
	}
	e.emit("playbook_run_completed", pkgaudit.Event{
		TenantID: pb.TenantID, ActorID: src.Actor, TargetType: "playbook", TargetID: pb.ID,
		Result: result, CorrelationID: run.ID,
		Details: map[string]interface{}{
			"playbook_name": pb.Name, "run_id": run.ID, "status": run.Status,
			"actions_run": run.ActionsRun, "actions_total": len(pb.Actions),
			"trigger": src.Trigger, "subject": src.Subject, "event_target": src.EventID,
			"authorized_by": src.Actor, "severity": severity,
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
