package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
	"vecta-kms/pkg/ssrfguard"
	"vecta-kms/pkg/svctls"
)

// The playbook catalogue is the single list of what a playbook can react to
// and do. The API validates against it, the executor runs from it, and the
// dashboard renders it from GET /compliance/playbooks/catalog, so none of
// them can offer something the others don't back (docs/DECISIONS.md,
// 2026-09-28).

// TriggerSpec is an event a playbook can react to. Every subject is one a
// service really emits; TestTriggerSubjectsAreEmitted checks the source tree.
type TriggerSpec struct {
	Type     string   `json:"type"`
	Label    string   `json:"label"`
	Group    string   `json:"group"`
	Subjects []string `json:"subjects"`
	// SuccessOnly fires only on result "success": a refused rotate is not a
	// rotated key.
	SuccessOnly bool `json:"success_only,omitempty"`
	// Platform events carry no tenant. They fire the platform tenant's
	// playbooks.
	Platform bool `json:"platform,omitempty"`
}

var playbookTriggers = []TriggerSpec{
	{Type: "canary_tripped", Label: "Canary key referenced", Group: "Incident response", Subjects: []string{"audit.keycore.canary_tripped"}},
	{Type: "threat_signal_raised", Label: "Key threat signal raised", Group: "Incident response", Subjects: []string{"audit.keycore.threat_signal_raised"}},
	{Type: "threat_finding_raised", Label: "Posture threat finding raised", Group: "Incident response", Subjects: []string{"audit.posture.threat_finding_raised"}},
	{Type: "key_compromised", Label: "Key compromise reported", Group: "Incident response", Subjects: []string{"audit.key.compromise_detected"}},
	{Type: "key_created", Label: "Key created", Group: "Key lifecycle", Subjects: []string{"audit.key.create"}, SuccessOnly: true},
	{Type: "key_rotated", Label: "Key rotated", Group: "Key lifecycle", Subjects: []string{"audit.key.rotate"}, SuccessOnly: true},
	{Type: "key_destroyed", Label: "Key destroyed", Group: "Key lifecycle", Subjects: []string{"audit.key.destroyed"}, SuccessOnly: true},
	{Type: "key_access_refused", Label: "Key access refused", Group: "Key lifecycle", Subjects: []string{"audit.key.access_refused"}},
	{Type: "key_request_replay_detected", Label: "Key request replay detected", Group: "Key lifecycle", Subjects: []string{"audit.key.request_replay_detected"}},
	{Type: "cert_revoked", Label: "Certificate revoked", Group: "Certificates", Subjects: []string{"audit.cert.revoked"}, SuccessOnly: true},
	{Type: "cert_renewal_window_missed", Label: "Certificate renewal window missed", Group: "Certificates", Subjects: []string{"audit.cert.renewal_window_missed"}},
	{Type: "cert_mass_renewal_risk", Label: "Mass renewal risk detected", Group: "Certificates", Subjects: []string{"audit.cert.mass_renewal_risk_detected"}},
	{Type: "crl_generation_failed", Label: "CRL generation failed", Group: "Certificates", Subjects: []string{"audit.cert.crl_generation_failed"}},
	{Type: "login_failed", Label: "Login failed", Group: "Access", Subjects: []string{"audit.auth.login_failed"}},
	{Type: "account_locked", Label: "Account locked", Group: "Access", Subjects: []string{"audit.auth.account_locked"}},
	{Type: "dpop_replay_detected", Label: "DPoP proof replay detected", Group: "Access", Subjects: []string{"audit.auth.dpop_replay_detected"}},
	{Type: "posture_changed", Label: "Compliance posture score changed", Group: "Compliance", Subjects: []string{"audit.compliance.posture_changed"}},
	{Type: "service_health_degraded", Label: "Platform service unhealthy (watchdog incident)", Group: "Platform", Subjects: []string{"audit.health.incident"}, Platform: true},
}

// ActionSpec is a step a playbook can take. Permission is what the person who
// saves the playbook, and anyone who runs it by hand, must hold themselves:
// the executor acts as the compliance service identity, so without this check
// a playbook would lend that identity's reach to anyone who can write one.
type ActionSpec struct {
	Type       string   `json:"type"`
	Label      string   `json:"label"`
	Group      string   `json:"group"`
	Permission string   `json:"permission,omitempty"`
	Required   []string `json:"required,omitempty"`
	Optional   []string `json:"optional,omitempty"`
	// Secrets are parameters never returned by the API.
	Secrets []string `json:"secrets,omitempty"`
	// URLParam names the outbound endpoint parameter, if any.
	URLParam string `json:"url_param,omitempty"`
}

var playbookActions = []ActionSpec{
	{Type: "send_slack", Label: "Send Slack message", Group: "Notification", Required: []string{"webhook_url"}, Optional: []string{"message"}, Secrets: []string{"webhook_url"}, URLParam: "webhook_url"},
	{Type: "send_teams", Label: "Send Teams message", Group: "Notification", Required: []string{"webhook_url"}, Optional: []string{"message"}, Secrets: []string{"webhook_url"}, URLParam: "webhook_url"},
	{Type: "send_webhook", Label: "Call webhook", Group: "Notification", Required: []string{"url"}, Optional: []string{"method", "body", "headers"}, Secrets: []string{"headers"}, URLParam: "url"},
	{Type: "create_jira_ticket", Label: "Create Jira issue", Group: "Notification", Required: []string{"base_url", "project", "summary"}, Optional: []string{"description", "issuetype", "api_token"}, Secrets: []string{"api_token"}, URLParam: "base_url"},
	{Type: "create_servicenow_incident", Label: "Create ServiceNow incident", Group: "Notification", Required: []string{"instance_url", "short_description"}, Optional: []string{"description", "urgency", "impact", "caller_id", "auth_token"}, Secrets: []string{"auth_token"}, URLParam: "instance_url"},
	{Type: "create_audit_event", Label: "Record audit event", Group: "Notification", Optional: []string{"message"}},
	{Type: "rotate_key", Label: "Rotate key", Group: "Keys", Permission: "key.rotate", Required: []string{"key_id"}},
	{Type: "disable_key", Label: "Disable key", Group: "Keys", Permission: "key.disable", Required: []string{"key_id"}},
	{Type: "deactivate_key", Label: "Deactivate key", Group: "Keys", Permission: "key.deactivate", Required: []string{"key_id"}},
	{Type: "activate_key", Label: "Activate key", Group: "Keys", Permission: "key.activate", Required: []string{"key_id"}},
	{Type: "renew_certificate", Label: "Renew certificate", Group: "Certificates", Permission: "cert.renew", Required: []string{"cert_id"}},
	{Type: "revoke_certificate", Label: "Revoke certificate", Group: "Certificates", Permission: "cert.revoke", Required: []string{"cert_id"}, Optional: []string{"reason"}},
	{Type: "trigger_assessment", Label: "Run compliance assessment", Group: "Compliance", Permission: "compliance.assessment.run", Optional: []string{"template_id"}},
	{Type: "snapshot_posture", Label: "Snapshot compliance posture", Group: "Compliance", Permission: "compliance.posture.refresh"},
}

// legacyActionNames maps action names saved before 2.4.0-beta. They called
// PUT /keys/{id}/status, which doesn't exist, so none of them ever ran; the
// new names say what keycore does.
var legacyActionNames = map[string]string{
	"suspend_key": "disable_key",
	"revoke_key":  "deactivate_key",
	"enable_key":  "activate_key",
}

// commonParams apply to every action.
var commonParams = map[string]bool{"stop_on_failure": true}

const (
	maxPlaybookActions = 20
	maxActionDelay     = 3600
	redactedParam      = "********"
)

var (
	triggerByType = map[string]TriggerSpec{}
	actionByType  = map[string]ActionSpec{}
)

func init() {
	for _, t := range playbookTriggers {
		triggerByType[t.Type] = t
	}
	for _, a := range playbookActions {
		actionByType[a.Type] = a
	}
}

// Refusal reasons for playbook saves and runs.
const (
	reasonActionPermission = "action_permission_denied"
	reasonURLBlocked       = "url_blocked"
	reasonNotAuthorized    = "playbook_not_authorized"
	reasonActionRemoved    = "action_removed"
	reasonCooldown         = "cooldown"
	reasonStaleEvent       = "stale_event"
)

// validatePlaybook checks a definition against the catalogue. It doesn't
// check permissions (missingPermissions does).
func validatePlaybook(p Playbook) error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("name is required")
	}
	if _, ok := triggerByType[p.Trigger.Type]; !ok {
		return fmt.Errorf("unsupported trigger type %q", p.Trigger.Type)
	}
	if len(p.Actions) == 0 || len(p.Actions) > maxPlaybookActions {
		return fmt.Errorf("a playbook needs 1 to %d actions", maxPlaybookActions)
	}
	for i, a := range p.Actions {
		spec, ok := actionByType[a.Type]
		if !ok {
			return fmt.Errorf("action %d: unsupported action type %q", i+1, a.Type)
		}
		if a.DelaySeconds < 0 || a.DelaySeconds > maxActionDelay {
			return fmt.Errorf("action %d: delay_seconds must be 0 to %d", i+1, maxActionDelay)
		}
		allowed := map[string]bool{}
		for _, k := range append(append([]string{}, spec.Required...), spec.Optional...) {
			allowed[k] = true
		}
		for k := range a.Parameters {
			if !allowed[k] && !commonParams[k] {
				return fmt.Errorf("action %d (%s): unknown parameter %q", i+1, a.Type, k)
			}
		}
		for _, k := range spec.Required {
			if strings.TrimSpace(a.Parameters[k]) == "" {
				return fmt.Errorf("action %d (%s): missing required parameter %q", i+1, a.Type, k)
			}
		}
		if a.Type == "send_webhook" {
			switch strings.ToUpper(strings.TrimSpace(a.Parameters["method"])) {
			case "", "POST", "PUT", "PATCH":
			default:
				return fmt.Errorf("action %d (send_webhook): method must be POST, PUT or PATCH", i+1)
			}
			var headers map[string]string
			if h := strings.TrimSpace(a.Parameters["headers"]); h != "" && h != redactedParam && json.Unmarshal([]byte(h), &headers) != nil {
				return fmt.Errorf("action %d (send_webhook): headers must be a JSON object of strings", i+1)
			}
			if b := strings.TrimSpace(a.Parameters["body"]); b != "" && !json.Valid([]byte(b)) {
				return fmt.Errorf("action %d (send_webhook): body must be valid JSON", i+1)
			}
		}
	}
	return nil
}

// urlError is an outbound endpoint the platform refuses to call.
type urlError struct{ err error }

func (e urlError) Error() string { return e.err.Error() }

// validateOutboundURLs refuses endpoints a playbook may not call: anything
// but HTTPS, a platform service host (the compliance service's mTLS client
// certificate would be presented to it), and addresses ssrfguard blocks.
func validateOutboundURLs(p Playbook) error {
	for i, a := range p.Actions {
		spec := actionByType[a.Type]
		if spec.URLParam == "" {
			continue
		}
		if err := checkOutboundURL(a.Parameters[spec.URLParam]); err != nil {
			return urlError{fmt.Errorf("action %d (%s): %s: %w", i+1, a.Type, spec.URLParam, err)}
		}
	}
	return nil
}

func checkOutboundURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return errors.New("must be an absolute https URL")
	}
	if u.Scheme != "https" {
		return errors.New("must use https")
	}
	if svctls.IsInternalHost(u.Hostname()) {
		return fmt.Errorf("%s is a platform service, not an external endpoint", u.Hostname())
	}
	return ssrfguard.ValidateWebhookURL(u.String())
}

// missingPermissions returns the action permissions claims don't grant, in
// action order, without repeats.
func missingPermissions(claims *pkgauth.Claims, actions []PlaybookAction) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range actions {
		perm := actionByType[a.Type].Permission
		if perm == "" || seen[perm] {
			continue
		}
		seen[perm] = true
		if !route.Allowed(claims, perm) {
			out = append(out, perm)
		}
	}
	return out
}

// redactPlaybook blanks secret parameters for API responses.
func redactPlaybook(p Playbook) Playbook {
	actions := make([]PlaybookAction, len(p.Actions))
	for i, a := range p.Actions {
		params := make(map[string]string, len(a.Parameters))
		for k, v := range a.Parameters {
			params[k] = v
		}
		for _, k := range actionByType[a.Type].Secrets {
			if params[k] != "" {
				params[k] = redactedParam
			}
		}
		a.Parameters = params
		actions[i] = a
	}
	p.Actions = actions
	return p
}

// restoreSecrets puts back stored secret values the client sent as the
// redaction marker (it only ever saw the marker). A marker with no stored
// value at the same position and type is refused rather than saved.
func restoreSecrets(next []PlaybookAction, stored []PlaybookAction) error {
	for i := range next {
		for _, k := range actionByType[next[i].Type].Secrets {
			if next[i].Parameters[k] != redactedParam {
				continue
			}
			if i >= len(stored) || stored[i].Type != next[i].Type || stored[i].Parameters[k] == "" {
				return fmt.Errorf("action %d (%s): %q must be re-entered", i+1, next[i].Type, k)
			}
			next[i].Parameters[k] = stored[i].Parameters[k]
		}
	}
	return nil
}
