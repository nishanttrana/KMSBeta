package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
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

// customTrigger fires on any audit subject the playbook names.
const customTrigger = "custom_event"

var playbookTriggers = []TriggerSpec{
	{Type: "alert_raised", Label: "Alert raised (Alert Center)", Group: "Incident response", Subjects: []string{"audit.reporting.alert_created"}},
	{Type: "incident_opened", Label: "Incident opened", Group: "Incident response", Subjects: []string{"audit.reporting.incident_opened"}},
	{Type: "canary_tripped", Label: "Canary key referenced", Group: "Incident response", Subjects: []string{"audit.keycore.canary_tripped"}},
	{Type: "threat_signal_raised", Label: "Key threat signal raised", Group: "Incident response", Subjects: []string{"audit.keycore.threat_signal_raised"}},
	{Type: "threat_finding_raised", Label: "Posture threat finding raised", Group: "Incident response", Subjects: []string{"audit.posture.threat_finding_raised"}},
	{Type: "sustained_risk_detected", Label: "Sustained high-risk activity on a target", Group: "Incident response", Subjects: []string{"audit.security.sustained_risk_detected"}},
	{Type: "key_compromised", Label: "Key compromise reported", Group: "Incident response", Subjects: []string{"audit.key.compromise_detected"}},
	{Type: "audit_chain_broken", Label: "Audit trail tampering detected", Group: "Incident response", Subjects: []string{"audit.audit.chain_broken"}},
	{Type: "secret_exposed", Label: "Exposed secret discovered (code or upload)", Group: "Incident response", Subjects: []string{"audit.discovery.secret_exposed"}},
	{Type: "secret_access_rule_changed", Label: "Secret access rule or vault setting changed", Group: "Access", Subjects: []string{"audit.secrets.access_rule_created", "audit.secrets.access_rule_deleted", "audit.secrets.settings_updated", "audit.secrets.version_cap_set", "audit.secrets.version_cap_deleted"}, SuccessOnly: true},
	{Type: "secret_access_rule_stale", Label: "Secret access rule names a subject that no longer exists", Group: "Access", Subjects: []string{"audit.secrets.access_rule_subject_missing"}},
	{Type: "secret_destroyed", Label: "Secret destroyed", Group: "Access", Subjects: []string{"audit.secrets.destroyed", "audit.secrets.retention_purged"}, SuccessOnly: true},
	{Type: "key_created", Label: "Key created", Group: "Key lifecycle", Subjects: []string{"audit.key.create"}, SuccessOnly: true},
	{Type: "key_rotated", Label: "Key rotated", Group: "Key lifecycle", Subjects: []string{"audit.key.rotate"}, SuccessOnly: true},
	{Type: "key_destroyed", Label: "Key destroyed", Group: "Key lifecycle", Subjects: []string{"audit.key.destroyed"}, SuccessOnly: true},
	{Type: "key_exported", Label: "Key exported", Group: "Key lifecycle", Subjects: []string{"audit.key.export"}, SuccessOnly: true},
	{Type: "key_access_refused", Label: "Key access refused", Group: "Key lifecycle", Subjects: []string{"audit.key.access_refused"}},
	{Type: "key_request_replay_detected", Label: "Key request replay detected", Group: "Key lifecycle", Subjects: []string{"audit.key.request_replay_detected"}},
	{Type: "key_hsm_refused", Label: "HSM refused a key operation", Group: "Key lifecycle", Subjects: []string{"audit.key.hsm_refused"}},
	{Type: "crypto_policy_refused", Label: "Key operation refused by migration policy", Group: "Key lifecycle", Subjects: []string{"audit.key.crypto_policy_refused"}},
	{Type: "crypto_risk_decision_recorded", Label: "Crypto risk decision recorded (secure, accept, phase out)", Group: "Key lifecycle", Subjects: []string{"audit.key.caraf_decision_recorded"}, SuccessOnly: true},
	{Type: "key_access_policy_changed", Label: "Key access justification policy changed", Group: "Key lifecycle", Subjects: []string{"audit.keyaccess.settings_updated", "audit.keyaccess.code_upserted", "audit.keyaccess.code_deleted"}, SuccessOnly: true},
	{Type: "attestation_policy_changed", Label: "Attested key release policy changed", Group: "Key lifecycle", Subjects: []string{"audit.confidential.policy_updated"}, SuccessOnly: true},
	{Type: "crypto_policy_changed", Label: "Migration policy rule changed", Group: "Key lifecycle", Subjects: []string{"audit.key.agility_policy_rule_created", "audit.key.agility_policy_rule_updated", "audit.key.agility_policy_rule_deleted"}, SuccessOnly: true},
	{Type: "cert_revoked", Label: "Certificate revoked", Group: "Certificates", Subjects: []string{"audit.cert.revoked"}, SuccessOnly: true},
	{Type: "cert_renewal_window_missed", Label: "Certificate renewal window missed", Group: "Certificates", Subjects: []string{"audit.cert.renewal_window_missed"}},
	{Type: "cert_mass_renewal_risk", Label: "Mass renewal risk detected", Group: "Certificates", Subjects: []string{"audit.cert.mass_renewal_risk_detected"}},
	{Type: "crl_generation_failed", Label: "CRL generation failed", Group: "Certificates", Subjects: []string{"audit.cert.crl_generation_failed"}},
	{Type: "login_failed", Label: "Login failed", Group: "Access", Subjects: []string{"audit.auth.login_failed"}},
	{Type: "account_locked", Label: "Account locked", Group: "Access", Subjects: []string{"audit.auth.account_locked"}},
	{Type: "dpop_replay_detected", Label: "DPoP proof replay detected", Group: "Access", Subjects: []string{"audit.auth.dpop_replay_detected"}},
	{Type: "workload_svid_issued", Label: "Workload SVID issued", Group: "Access", Subjects: []string{"audit.workload.svid_issued"}, SuccessOnly: true},
	{Type: "workload_trust_changed", Label: "Workload identity trust changed (settings, federation)", Group: "Access", Subjects: []string{"audit.workload.settings_updated", "audit.workload.federation_bundle_upserted", "audit.workload.federation_bundle_deleted"}, SuccessOnly: true},
	{Type: "posture_changed", Label: "Compliance posture score changed", Group: "Compliance", Subjects: []string{"audit.compliance.posture_changed"}},
	{Type: "fips_mode_changed", Label: "Platform FIPS mode changed", Group: "Platform", Subjects: []string{"audit.governance.fips_mode_changed"}},
	{Type: "backup_restored", Label: "Backup restored", Group: "Platform", Subjects: []string{"audit.governance.backup_restored"}},
	{Type: "cluster_member_joined", Label: "Cluster member joined", Group: "Platform", Subjects: []string{"audit.cluster.member_joined"}},
	{Type: "service_health_degraded", Label: "Platform service unhealthy (watchdog incident)", Group: "Platform", Subjects: []string{"audit.health.incident"}, Platform: true},
	{Type: customTrigger, Label: "Any audit event (custom subject)", Group: "Custom"},
}

// ActionSpec is a step a playbook can take. Permission is what the person on
// whose authority it runs must hold: the executor acts as the compliance
// service identity, so without this check a playbook would lend that
// identity's reach to anyone who can write one.
type ActionSpec struct {
	Type       string   `json:"type"`
	Label      string   `json:"label"`
	Group      string   `json:"group"`
	Permission string   `json:"permission,omitempty"`
	Required   []string `json:"required,omitempty"`
	Optional   []string `json:"optional,omitempty"`
	// Connection is the connection type the action sends through.
	Connection string `json:"connection,omitempty"`
	// Approval "required" means every run pauses for a governance approval
	// before this action; others may opt in with require_approval.
	Approval string `json:"approval,omitempty"`
	// Delegated actions are executed by auth on behalf of the authorizing
	// person, after auth re-checks that person's current permission.
	Delegated bool `json:"delegated,omitempty"`
}

var playbookActions = []ActionSpec{
	{Type: "send_slack", Label: "Send Slack message", Group: "Notification", Connection: "slack", Required: []string{"connection_id"}, Optional: []string{"message"}},
	{Type: "send_teams", Label: "Send Teams message", Group: "Notification", Connection: "teams", Required: []string{"connection_id"}, Optional: []string{"message"}},
	{Type: "send_webhook", Label: "Call webhook", Group: "Notification", Connection: "webhook", Required: []string{"connection_id"}, Optional: []string{"method", "body"}},
	{Type: "create_jira_ticket", Label: "Create Jira issue", Group: "Notification", Connection: "jira", Required: []string{"connection_id", "project", "summary"}, Optional: []string{"description", "issuetype"}},
	{Type: "create_servicenow_incident", Label: "Create ServiceNow incident", Group: "Notification", Connection: "servicenow", Required: []string{"connection_id", "short_description"}, Optional: []string{"description", "urgency", "impact", "caller_id"}},
	{Type: "send_siem_alert", Label: "Raise SIEM alert", Group: "Notification", Connection: categorySIEM, Required: []string{"connection_id"}, Optional: []string{"title", "severity"}},
	{Type: "send_email", Label: "Email tenant users", Group: "Notification", Required: []string{"to", "subject"}, Optional: []string{"body"}},
	{Type: "create_audit_event", Label: "Record audit event", Group: "Notification", Optional: []string{"message"}},
	{Type: "rotate_key", Label: "Rotate key", Group: "Keys", Permission: "key.rotate", Required: []string{"key_id"}},
	{Type: "disable_key", Label: "Disable key", Group: "Keys", Permission: "key.disable", Required: []string{"key_id"}},
	{Type: "deactivate_key", Label: "Deactivate key", Group: "Keys", Permission: "key.deactivate", Required: []string{"key_id"}, Approval: "required"},
	{Type: "activate_key", Label: "Activate key", Group: "Keys", Permission: "key.activate", Required: []string{"key_id"}},
	{Type: "trigger_rotation_policy", Label: "Run rotation policy", Group: "Keys", Permission: "key.rotation.write", Required: []string{"policy_id"}},
	{Type: "renew_certificate", Label: "Renew certificate", Group: "Certificates", Permission: "cert.renew", Required: []string{"cert_id"}},
	{Type: "revoke_certificate", Label: "Revoke certificate", Group: "Certificates", Permission: "cert.revoke", Required: []string{"cert_id"}, Optional: []string{"reason"}, Approval: "required"},
	{Type: "disable_user", Label: "Disable user", Group: "Access", Permission: "auth.user.write", Required: []string{"user_id"}, Approval: "required", Delegated: true},
	{Type: "revoke_api_key", Label: "Revoke API key", Group: "Access", Permission: "auth.api_key.write", Required: []string{"api_key_id"}, Approval: "required", Delegated: true},
	{Type: "revoke_client", Label: "Revoke REST client", Group: "Access", Permission: "auth.client.write", Required: []string{"client_id"}, Approval: "required", Delegated: true},
	{Type: "acknowledge_alert", Label: "Acknowledge alert", Group: "Alerts & incidents", Permission: "reporting.write", Required: []string{"alert_id"}},
	{Type: "resolve_alert", Label: "Resolve alert", Group: "Alerts & incidents", Permission: "reporting.write", Required: []string{"alert_id"}, Optional: []string{"note"}},
	{Type: "set_incident_status", Label: "Set incident status", Group: "Alerts & incidents", Permission: "reporting.write", Required: []string{"incident_id", "status"}, Optional: []string{"notes"}},
	{Type: "assign_incident", Label: "Assign incident", Group: "Alerts & incidents", Permission: "reporting.write", Required: []string{"incident_id", "assigned_to"}},
	{Type: "generate_report", Label: "Generate report", Group: "Compliance", Permission: "reporting.write", Required: []string{"template_id"}, Optional: []string{"format"}},
	{Type: "trigger_assessment", Label: "Run compliance assessment", Group: "Compliance", Permission: "compliance.assessment.run", Optional: []string{"template_id"}},
	{Type: "snapshot_posture", Label: "Snapshot compliance posture", Group: "Compliance", Permission: "compliance.posture.refresh"},
	{Type: "run_posture_scan", Label: "Run posture scan", Group: "Compliance", Permission: "posture.write"},
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

// incidentStatuses are the reporting incident states set_incident_status may set.
var incidentStatuses = map[string]bool{"open": true, "investigating": true, "resolved": true, "closed": true}

const (
	maxPlaybookActions = 20
	maxActionDelay     = 3600
	maxThreshold       = 10000
	maxWindowSeconds   = 86400
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
	reasonActionPermission     = "action_permission_denied"
	reasonURLBlocked           = "url_blocked"
	reasonNotAuthorized        = "playbook_not_authorized"
	reasonActionRemoved        = "action_removed"
	reasonCooldown             = "cooldown"
	reasonThresholdUnavailable = "threshold_unavailable"
	reasonCooldownUnavailable  = "cooldown_unavailable"
	reasonStaleEvent           = "stale_event"
	reasonUserRequired         = "user_required"
	reasonAuthorityRevoked     = "authority_revoked"
	reasonAuthorityUnknown     = "authority_unverified"
)

// customSubjectRE: audit.<service>.<action>, optionally ending in ".*".
var customSubjectRE = regexp.MustCompile(`^audit\.[a-z0-9_-]+(\.[a-z0-9_.-]+)*(\.\*)?$`)

// subjectMatches reports whether an event subject matches a custom trigger's
// subject (exact, or a prefix ending in ".*").
func subjectMatches(pattern, subject string) bool {
	if p, ok := strings.CutSuffix(pattern, ".*"); ok {
		return strings.HasPrefix(subject, p+".")
	}
	return pattern == subject
}

// ownSubject reports subjects playbooks never react to: their own events.
func ownSubject(subject string) bool {
	return strings.HasPrefix(subject, "audit.compliance.playbook") || strings.HasPrefix(subject, "audit.compliance.connection")
}

// validatePlaybook checks a definition against the catalogue. It doesn't
// check permissions (missingPermissions does) or connections (the handler
// does, against the store).
func validatePlaybook(p Playbook) error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("name is required")
	}
	if err := validateTrigger(p.Trigger); err != nil {
		return err
	}
	if len(p.Actions) == 0 || len(p.Actions) > maxPlaybookActions {
		return fmt.Errorf("a playbook needs 1 to %d actions", maxPlaybookActions)
	}
	for i, a := range p.Actions {
		if err := validateAction(i, a); err != nil {
			return err
		}
	}
	return nil
}

func validateTrigger(t PlaybookTrigger) error {
	if _, ok := triggerByType[t.Type]; !ok {
		return fmt.Errorf("unsupported trigger type %q", t.Type)
	}
	switch {
	case t.Type == customTrigger && !customSubjectRE.MatchString(t.Subject):
		return errors.New("a custom trigger needs a subject like audit.key.rotate or audit.cert.*")
	case t.Type == customTrigger && ownSubject(t.Subject):
		return errors.New("a playbook can't trigger on playbook events")
	case t.Type != customTrigger && t.Subject != "":
		return errors.New("subject is only for custom_event triggers")
	}
	if err := validateFilters(t.Filters, "trigger"); err != nil {
		return err
	}
	if t.Threshold < 0 || t.Threshold > maxThreshold {
		return fmt.Errorf("threshold must be 0 to %d", maxThreshold)
	}
	if t.Threshold > 1 && (t.WindowSeconds < 1 || t.WindowSeconds > maxWindowSeconds) {
		return fmt.Errorf("a threshold above 1 needs window_seconds of 1 to %d", maxWindowSeconds)
	}
	if t.Threshold <= 1 && (t.WindowSeconds != 0 || t.GroupBy != "") {
		return errors.New("window_seconds and group_by apply only with a threshold above 1")
	}
	if t.GroupBy != "" && !validEventField(t.GroupBy) {
		return fmt.Errorf("group_by: unknown field %q", t.GroupBy)
	}
	return nil
}

func validateAction(i int, a PlaybookAction) error {
	spec, ok := actionByType[a.Type]
	if !ok {
		return fmt.Errorf("action %d: unsupported action type %q", i+1, a.Type)
	}
	if a.DelaySeconds < 0 || a.DelaySeconds > maxActionDelay {
		return fmt.Errorf("action %d: delay_seconds must be 0 to %d", i+1, maxActionDelay)
	}
	if err := validateFilters(a.Condition, fmt.Sprintf("action %d condition", i+1)); err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, k := range append(append([]string{}, spec.Required...), spec.Optional...) {
		allowed[k] = true
	}
	for k, v := range a.Parameters {
		if !allowed[k] && !commonParams[k] {
			return fmt.Errorf("action %d (%s): unknown parameter %q", i+1, a.Type, k)
		}
		if err := validateTemplates(v); err != nil {
			return fmt.Errorf("action %d (%s): %s: %w", i+1, a.Type, k, err)
		}
		if k == "connection_id" && hasTemplate(v) {
			return fmt.Errorf("action %d (%s): connection_id can't be a template", i+1, a.Type)
		}
	}
	for _, k := range spec.Required {
		if strings.TrimSpace(a.Parameters[k]) == "" {
			return fmt.Errorf("action %d (%s): missing required parameter %q", i+1, a.Type, k)
		}
	}
	p := a.Parameters
	switch a.Type {
	case "send_webhook":
		switch strings.ToUpper(strings.TrimSpace(p["method"])) {
		case "", "POST", "PUT", "PATCH":
		default:
			return fmt.Errorf("action %d (send_webhook): method must be POST, PUT or PATCH", i+1)
		}
		if b := strings.TrimSpace(p["body"]); b != "" && !hasTemplate(b) && !json.Valid([]byte(b)) {
			return fmt.Errorf("action %d (send_webhook): body must be valid JSON", i+1)
		}
	case "send_siem_alert":
		if sev := strings.ToLower(strings.TrimSpace(p["severity"])); sev != "" && !hasTemplate(sev) && !siemSeverities[sev] {
			return fmt.Errorf("action %d (send_siem_alert): severity must be info, low, warning, high or critical", i+1)
		}
	case "set_incident_status":
		if s := strings.ToLower(strings.TrimSpace(p["status"])); !hasTemplate(s) && !incidentStatuses[s] {
			return fmt.Errorf("action %d (set_incident_status): status must be open, investigating, resolved or closed", i+1)
		}
	case "send_email":
		if err := validateRecipients(p["to"]); err != nil {
			return fmt.Errorf("action %d (send_email): %w", i+1, err)
		}
	}
	return nil
}

var (
	emailRE = regexp.MustCompile(`^[^@\s,]+@[^@\s,]+\.[^@\s,]+$`)
	roleRE  = regexp.MustCompile(`^role:[a-z0-9_-]{1,64}$`)
)

// validateRecipients accepts a comma list of tenant user emails and
// role:<name> entries. Governance sends only to users of the tenant.
func validateRecipients(to string) error {
	items := strings.Split(to, ",")
	if len(items) > 20 {
		return errors.New("at most 20 recipients")
	}
	for _, r := range items {
		r = strings.ToLower(strings.TrimSpace(r))
		if !emailRE.MatchString(r) && !roleRE.MatchString(r) {
			return fmt.Errorf("recipient %q must be an email or role:<name>", r)
		}
	}
	return nil
}

var siemSeverities = map[string]bool{"info": true, "low": true, "warning": true, "high": true, "critical": true}

// urlError is an outbound endpoint the platform refuses to call.
type urlError struct{ err error }

func (e urlError) Error() string { return e.err.Error() }

// checkOutboundURL refuses endpoints a playbook may not call: anything but
// HTTPS, a platform service host (the compliance service's mTLS client
// certificate would be presented to it), and addresses ssrfguard blocks.
func checkOutboundURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return urlError{errors.New("must be an absolute https URL")}
	}
	if u.Scheme != "https" {
		return urlError{errors.New("must use https")}
	}
	if svctls.IsInternalHost(u.Hostname()) {
		return urlError{fmt.Errorf("%s is a platform service, not an external endpoint", u.Hostname())}
	}
	if err := ssrfguard.ValidateWebhookURL(u.String()); err != nil {
		return urlError{err}
	}
	return nil
}

// requiredPermissions lists the permissions pb's actions need, in order,
// without repeats.
func requiredPermissions(actions []PlaybookAction) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range actions {
		if perm := actionByType[a.Type].Permission; perm != "" && !seen[perm] {
			seen[perm] = true
			out = append(out, perm)
		}
	}
	return out
}

// missingPermissions returns the action permissions claims don't grant.
func missingPermissions(claims *pkgauth.Claims, actions []PlaybookAction) []string {
	var out []string
	for _, perm := range requiredPermissions(actions) {
		if !route.Allowed(claims, perm) {
			out = append(out, perm)
		}
	}
	return out
}

// gated reports whether action a pauses for a governance approval.
func gated(a PlaybookAction) bool {
	return actionByType[a.Type].Approval == "required" || a.RequireApproval
}
