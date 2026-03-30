package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// RunContext carries contextual data passed between actions during a playbook run.
type RunContext struct {
	PlaybookID   string
	RunID        string
	TenantID     string
	TriggerEvent string
}

// ActionResult records the outcome of a single action execution.
type ActionResult struct {
	Index   int           `json:"index"`
	Type    string        `json:"type"`
	Status  string        `json:"status"`
	Error   string        `json:"error,omitempty"`
	Elapsed time.Duration `json:"elapsed_ms"`
}

// PlaybookExecutor handles real execution of playbook actions via HTTP calls
// to internal microservices and external webhooks.
type PlaybookExecutor struct {
	store      Store
	keycoreURL string
	certsURL   string
	policyURL  string
	auditURL   string
	authURL    string
	events     EventPublisher
	http       *http.Client
	logger     *log.Logger
}

// NewPlaybookExecutor creates an executor wired to all service endpoints.
func NewPlaybookExecutor(
	store Store,
	keycoreURL, certsURL, policyURL, auditURL string,
	events EventPublisher,
	logger *log.Logger,
) *PlaybookExecutor {
	authURL := envOr("AUTH_URL", "http://127.0.0.1:8020")
	return &PlaybookExecutor{
		store:      store,
		keycoreURL: strings.TrimRight(keycoreURL, "/"),
		certsURL:   strings.TrimRight(certsURL, "/"),
		policyURL:  strings.TrimRight(policyURL, "/"),
		auditURL:   strings.TrimRight(auditURL, "/"),
		authURL:    strings.TrimRight(authURL, "/"),
		events:     events,
		http:       &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
	}
}

// ExecutePlaybook runs all actions in a playbook sequentially, recording results.
func (e *PlaybookExecutor) ExecutePlaybook(ctx context.Context, playbook Playbook, triggerEvent string) (*PlaybookRun, error) {
	run := PlaybookRun{
		ID:           newID("pbrun"),
		PlaybookID:   playbook.ID,
		TenantID:     playbook.TenantID,
		TriggerEvent: triggerEvent,
		Status:       "running",
		ActionsRun:   0,
	}

	created, err := e.store.CreatePlaybookRun(ctx, run)
	if err != nil {
		return nil, fmt.Errorf("failed to create playbook run record: %w", err)
	}

	runCtx := RunContext{
		PlaybookID:   playbook.ID,
		RunID:        created.ID,
		TenantID:     playbook.TenantID,
		TriggerEvent: triggerEvent,
	}

	var (
		results      []ActionResult
		actionsRun   int
		hadFailure   bool
		outputLines  []string
	)

	for i, action := range playbook.Actions {
		// Respect DelaySeconds with context awareness
		if action.DelaySeconds > 0 {
			delay := time.Duration(action.DelaySeconds) * time.Second
			e.logger.Printf("run=%s action[%d]=%s delaying %ds", created.ID, i, action.Type, action.DelaySeconds)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				e.logger.Printf("run=%s cancelled during delay for action[%d]", created.ID, i)
				created.Status = "cancelled"
				created.ActionsRun = actionsRun
				created.Output = strings.Join(outputLines, "\n")
				now := time.Now().UTC()
				created.CompletedAt = &now
				_, _ = e.store.UpdatePlaybookRun(ctx, created)
				return &created, ctx.Err()
			}
		}

		start := time.Now()
		e.logger.Printf("run=%s executing action[%d] type=%s", created.ID, i, action.Type)
		execErr := e.executeAction(ctx, action, runCtx)
		elapsed := time.Since(start)
		actionsRun++

		result := ActionResult{
			Index:   i + 1,
			Type:    action.Type,
			Elapsed: elapsed,
		}

		if execErr != nil {
			result.Status = "failed"
			result.Error = execErr.Error()
			hadFailure = true
			outputLines = append(outputLines,
				fmt.Sprintf("[%d] action=%s status=FAILED error=%q elapsed=%s", i+1, action.Type, execErr.Error(), elapsed.Round(time.Millisecond)))
			e.logger.Printf("run=%s action[%d]=%s FAILED: %v", created.ID, i, action.Type, execErr)

			// Check for stop_on_failure parameter
			if action.Parameters["stop_on_failure"] == "true" {
				outputLines = append(outputLines,
					fmt.Sprintf("[%d] stop_on_failure=true, halting playbook execution", i+1))
				e.logger.Printf("run=%s halting: action[%d] has stop_on_failure=true", created.ID, i)
				break
			}
		} else {
			result.Status = "success"
			outputLines = append(outputLines,
				fmt.Sprintf("[%d] action=%s status=OK elapsed=%s", i+1, action.Type, elapsed.Round(time.Millisecond)))
			e.logger.Printf("run=%s action[%d]=%s OK elapsed=%s", created.ID, i, action.Type, elapsed.Round(time.Millisecond))
		}
		results = append(results, result)
	}

	// Determine final status
	now := time.Now().UTC()
	created.ActionsRun = actionsRun
	created.Output = strings.Join(outputLines, "\n")
	created.CompletedAt = &now
	if hadFailure && actionsRun < len(playbook.Actions) {
		created.Status = "failed"
	} else if hadFailure {
		created.Status = "partial_failure"
	} else {
		created.Status = "completed"
	}

	updated, err := e.store.UpdatePlaybookRun(ctx, created)
	if err != nil {
		e.logger.Printf("run=%s failed to update run record: %v", created.ID, err)
		return &created, nil
	}

	_ = e.store.IncrementPlaybookRunCount(ctx, playbook.TenantID, playbook.ID, now)

	// Publish audit event for the completed run
	if e.events != nil {
		payload, _ := json.Marshal(map[string]interface{}{
			"playbook_id":   playbook.ID,
			"playbook_name": playbook.Name,
			"run_id":        updated.ID,
			"status":        updated.Status,
			"actions_run":   updated.ActionsRun,
			"trigger_event": triggerEvent,
			"tenant_id":     playbook.TenantID,
		})
		_ = e.events.Publish(ctx, "audit.compliance.playbook_executed", payload)
	}

	return &updated, nil
}

// executeAction dispatches a single action by type and makes the real HTTP call.
func (e *PlaybookExecutor) executeAction(ctx context.Context, action PlaybookAction, runCtx RunContext) error {
	switch action.Type {

	// ── Notification Actions ────────────────────────────────────────────────────

	case "send_email":
		return e.actionSendEmail(ctx, action.Parameters, runCtx)
	case "send_slack":
		return e.actionSendSlack(ctx, action.Parameters)
	case "send_teams":
		return e.actionSendTeams(ctx, action.Parameters)
	case "send_webhook":
		return e.actionSendWebhook(ctx, action.Parameters)
	case "send_pagerduty":
		return e.actionSendPagerDuty(ctx, action.Parameters)
	case "create_jira_ticket":
		return e.actionCreateJiraTicket(ctx, action.Parameters)
	case "create_servicenow_incident":
		return e.actionCreateServiceNowIncident(ctx, action.Parameters)

	// ── Key Operations ──────────────────────────────────────────────────────────

	case "rotate_key":
		return e.actionRotateKey(ctx, action.Parameters, runCtx)
	case "suspend_key":
		return e.actionSetKeyStatus(ctx, action.Parameters, runCtx, "suspended")
	case "revoke_key":
		return e.actionSetKeyStatus(ctx, action.Parameters, runCtx, "revoked")
	case "enable_key":
		return e.actionSetKeyStatus(ctx, action.Parameters, runCtx, "active")
	case "destroy_key":
		return e.actionDestroyKey(ctx, action.Parameters, runCtx)

	// ── Certificate Actions ─────────────────────────────────────────────────────

	case "renew_certificate":
		return e.actionRenewCertificate(ctx, action.Parameters, runCtx)
	case "revoke_certificate":
		return e.actionRevokeCertificate(ctx, action.Parameters, runCtx)

	// ── Access Control Actions ──────────────────────────────────────────────────

	case "disable_user":
		return e.actionDisableUser(ctx, action.Parameters, runCtx)
	case "revoke_api_key":
		return e.actionRevokeAPIKey(ctx, action.Parameters, runCtx)

	// ── Compliance Actions ──────────────────────────────────────────────────────

	case "trigger_assessment":
		return e.actionTriggerAssessment(ctx, action.Parameters, runCtx)
	case "generate_evidence_report":
		return e.actionGenerateEvidenceReport(ctx, action.Parameters, runCtx)
	case "snapshot_posture":
		return e.actionSnapshotPosture(ctx, action.Parameters, runCtx)

	// ── Infrastructure Actions ──────────────────────────────────────────────────

	case "create_backup":
		return e.actionCreateBackup(ctx, action.Parameters, runCtx)

	// ── Legacy/alias actions (log-only) ─────────────────────────────────────────

	case "send_alert", "create_audit_event", "disable_access", "notify_soc":
		e.logger.Printf("run=%s legacy action=%s treated as audit log", runCtx.RunID, action.Type)
		if e.events != nil {
			payload, _ := json.Marshal(map[string]interface{}{
				"action":     action.Type,
				"parameters": action.Parameters,
				"run_id":     runCtx.RunID,
				"tenant_id":  runCtx.TenantID,
			})
			return e.events.Publish(ctx, "audit.compliance.playbook_action", payload)
		}
		return nil

	default:
		return fmt.Errorf("unsupported action type: %s", action.Type)
	}
}

// ── Notification Action Implementations ─────────────────────────────────────

func (e *PlaybookExecutor) actionSendEmail(ctx context.Context, params map[string]string, runCtx RunContext) error {
	for _, required := range []string{"to", "subject", "body"} {
		if strings.TrimSpace(params[required]) == "" {
			return fmt.Errorf("send_email: missing required param %q", required)
		}
	}
	// POST to governance SMTP endpoint
	governanceURL := envOr("GOVERNANCE_URL", "http://127.0.0.1:8050")
	payload := map[string]string{
		"to":        params["to"],
		"subject":   params["subject"],
		"body":      params["body"],
		"tenant_id": runCtx.TenantID,
	}
	return e.doPost(ctx, governanceURL+"/governance/notify", payload, nil)
}

func (e *PlaybookExecutor) actionSendSlack(ctx context.Context, params map[string]string) error {
	webhookURL := strings.TrimSpace(params["webhook_url"])
	if webhookURL == "" {
		return fmt.Errorf("send_slack: missing required param \"webhook_url\"")
	}
	message := params["message"]
	if message == "" {
		message = "Playbook action triggered"
	}
	payload := map[string]interface{}{
		"text": message,
		"blocks": []map[string]interface{}{
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": message,
				},
			},
		},
	}
	return e.doPost(ctx, webhookURL, payload, nil)
}

func (e *PlaybookExecutor) actionSendTeams(ctx context.Context, params map[string]string) error {
	webhookURL := strings.TrimSpace(params["webhook_url"])
	if webhookURL == "" {
		return fmt.Errorf("send_teams: missing required param \"webhook_url\"")
	}
	message := params["message"]
	if message == "" {
		message = "Playbook action triggered"
	}
	// Microsoft Teams Adaptive Card format
	payload := map[string]interface{}{
		"type":    "message",
		"attachments": []map[string]interface{}{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]interface{}{
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"type":    "AdaptiveCard",
					"version": "1.4",
					"body": []map[string]interface{}{
						{
							"type": "TextBlock",
							"text": message,
							"wrap": true,
						},
					},
				},
			},
		},
	}
	return e.doPost(ctx, webhookURL, payload, nil)
}

func (e *PlaybookExecutor) actionSendWebhook(ctx context.Context, params map[string]string) error {
	targetURL := strings.TrimSpace(params["url"])
	if targetURL == "" {
		return fmt.Errorf("send_webhook: missing required param \"url\"")
	}
	method := strings.ToUpper(strings.TrimSpace(params["method"]))
	if method == "" {
		method = http.MethodPost
	}

	var bodyReader io.Reader
	if body := params["body"]; body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return fmt.Errorf("send_webhook: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Parse custom headers from params["headers"] as JSON object
	if rawHeaders := params["headers"]; rawHeaders != "" {
		var headers map[string]string
		if err := json.Unmarshal([]byte(rawHeaders), &headers); err == nil {
			for k, v := range headers {
				req.Header.Set(k, v)
			}
		}
	}

	resp, err := e.http.Do(req)
	if err != nil {
		return fmt.Errorf("send_webhook: request failed: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("send_webhook: HTTP %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (e *PlaybookExecutor) actionSendPagerDuty(ctx context.Context, params map[string]string) error {
	routingKey := strings.TrimSpace(params["routing_key"])
	if routingKey == "" {
		return fmt.Errorf("send_pagerduty: missing required param \"routing_key\"")
	}
	summary := params["summary"]
	if summary == "" {
		summary = "KMS playbook alert"
	}
	severity := params["severity"]
	if severity == "" {
		severity = "critical"
	}
	payload := map[string]interface{}{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"payload": map[string]interface{}{
			"summary":  summary,
			"severity": severity,
			"source":   "kms-compliance",
		},
	}
	return e.doPost(ctx, "https://events.pagerduty.com/v2/enqueue", payload, nil)
}

func (e *PlaybookExecutor) actionCreateJiraTicket(ctx context.Context, params map[string]string) error {
	baseURL := strings.TrimRight(strings.TrimSpace(params["base_url"]), "/")
	if baseURL == "" {
		return fmt.Errorf("create_jira_ticket: missing required param \"base_url\"")
	}
	for _, required := range []string{"project", "summary"} {
		if strings.TrimSpace(params[required]) == "" {
			return fmt.Errorf("create_jira_ticket: missing required param %q", required)
		}
	}
	issueType := params["issuetype"]
	if issueType == "" {
		issueType = "Task"
	}
	payload := map[string]interface{}{
		"fields": map[string]interface{}{
			"project": map[string]string{
				"key": params["project"],
			},
			"summary":     params["summary"],
			"description": params["description"],
			"issuetype": map[string]string{
				"name": issueType,
			},
		},
	}
	headers := map[string]string{}
	if auth := params["api_token"]; auth != "" {
		headers["Authorization"] = "Basic " + auth
	}
	return e.doPost(ctx, baseURL+"/rest/api/2/issue", payload, headers)
}

func (e *PlaybookExecutor) actionCreateServiceNowIncident(ctx context.Context, params map[string]string) error {
	instanceURL := strings.TrimRight(strings.TrimSpace(params["instance_url"]), "/")
	if instanceURL == "" {
		return fmt.Errorf("create_servicenow_incident: missing required param \"instance_url\"")
	}
	shortDesc := params["short_description"]
	if shortDesc == "" {
		return fmt.Errorf("create_servicenow_incident: missing required param \"short_description\"")
	}
	urgency := params["urgency"]
	if urgency == "" {
		urgency = "2"
	}
	impact := params["impact"]
	if impact == "" {
		impact = "2"
	}
	payload := map[string]interface{}{
		"short_description": shortDesc,
		"urgency":           urgency,
		"impact":            impact,
		"description":       params["description"],
		"caller_id":         params["caller_id"],
	}
	headers := map[string]string{}
	if auth := params["auth_token"]; auth != "" {
		headers["Authorization"] = "Bearer " + auth
	}
	return e.doPost(ctx, instanceURL+"/api/now/table/incident", payload, headers)
}

// ── Key Operation Implementations ───────────────────────────────────────────

func (e *PlaybookExecutor) actionRotateKey(ctx context.Context, params map[string]string, runCtx RunContext) error {
	keyID := strings.TrimSpace(params["key_id"])
	if keyID == "" {
		return fmt.Errorf("rotate_key: missing required param \"key_id\"")
	}
	url := fmt.Sprintf("%s/keys/%s/rotate", e.keycoreURL, keyID)
	body := map[string]string{"tenant_id": runCtx.TenantID}
	return e.doPost(ctx, url, body, map[string]string{"X-Tenant-ID": runCtx.TenantID})
}

func (e *PlaybookExecutor) actionSetKeyStatus(ctx context.Context, params map[string]string, runCtx RunContext, status string) error {
	keyID := strings.TrimSpace(params["key_id"])
	if keyID == "" {
		return fmt.Errorf("%s_key: missing required param \"key_id\"", status)
	}
	url := fmt.Sprintf("%s/keys/%s/status", e.keycoreURL, keyID)
	body := map[string]string{"status": status}
	return e.doPut(ctx, url, body, map[string]string{"X-Tenant-ID": runCtx.TenantID})
}

func (e *PlaybookExecutor) actionDestroyKey(ctx context.Context, params map[string]string, runCtx RunContext) error {
	keyID := strings.TrimSpace(params["key_id"])
	if keyID == "" {
		return fmt.Errorf("destroy_key: missing required param \"key_id\"")
	}
	url := fmt.Sprintf("%s/keys/%s/destroy", e.keycoreURL, keyID)
	body := map[string]string{"tenant_id": runCtx.TenantID}
	return e.doPost(ctx, url, body, map[string]string{"X-Tenant-ID": runCtx.TenantID})
}

// ── Certificate Action Implementations ──────────────────────────────────────

func (e *PlaybookExecutor) actionRenewCertificate(ctx context.Context, params map[string]string, runCtx RunContext) error {
	certID := strings.TrimSpace(params["cert_id"])
	if certID == "" {
		return fmt.Errorf("renew_certificate: missing required param \"cert_id\"")
	}
	url := fmt.Sprintf("%s/certificates/%s/renew", e.certsURL, certID)
	body := map[string]string{"tenant_id": runCtx.TenantID}
	return e.doPost(ctx, url, body, map[string]string{"X-Tenant-ID": runCtx.TenantID})
}

func (e *PlaybookExecutor) actionRevokeCertificate(ctx context.Context, params map[string]string, runCtx RunContext) error {
	certID := strings.TrimSpace(params["cert_id"])
	if certID == "" {
		return fmt.Errorf("revoke_certificate: missing required param \"cert_id\"")
	}
	url := fmt.Sprintf("%s/certificates/%s/revoke", e.certsURL, certID)
	reason := params["reason"]
	if reason == "" {
		reason = "playbook_action"
	}
	body := map[string]string{"tenant_id": runCtx.TenantID, "reason": reason}
	return e.doPost(ctx, url, body, map[string]string{"X-Tenant-ID": runCtx.TenantID})
}

// ── Access Control Action Implementations ───────────────────────────────────

func (e *PlaybookExecutor) actionDisableUser(ctx context.Context, params map[string]string, runCtx RunContext) error {
	userID := strings.TrimSpace(params["user_id"])
	if userID == "" {
		return fmt.Errorf("disable_user: missing required param \"user_id\"")
	}
	url := fmt.Sprintf("%s/auth/users/%s/status", e.authURL, userID)
	body := map[string]string{"status": "disabled"}
	return e.doPut(ctx, url, body, map[string]string{"X-Tenant-ID": runCtx.TenantID})
}

func (e *PlaybookExecutor) actionRevokeAPIKey(ctx context.Context, params map[string]string, runCtx RunContext) error {
	apiKeyID := strings.TrimSpace(params["api_key_id"])
	if apiKeyID == "" {
		return fmt.Errorf("revoke_api_key: missing required param \"api_key_id\"")
	}
	url := fmt.Sprintf("%s/auth/api-keys/%s", e.authURL, apiKeyID)
	return e.doDelete(ctx, url, map[string]string{"X-Tenant-ID": runCtx.TenantID})
}

// ── Compliance Action Implementations ───────────────────────────────────────

func (e *PlaybookExecutor) actionTriggerAssessment(ctx context.Context, params map[string]string, runCtx RunContext) error {
	// POST to self (compliance service) to trigger an assessment
	complianceURL := envOr("COMPLIANCE_URL", "http://127.0.0.1:8110")
	body := map[string]string{
		"tenant_id":   runCtx.TenantID,
		"template_id": params["template_id"],
	}
	return e.doPost(ctx, complianceURL+"/compliance/assess", body, map[string]string{"X-Tenant-ID": runCtx.TenantID})
}

func (e *PlaybookExecutor) actionGenerateEvidenceReport(ctx context.Context, params map[string]string, runCtx RunContext) error {
	complianceURL := envOr("COMPLIANCE_URL", "http://127.0.0.1:8110")
	body := map[string]string{
		"tenant_id":    runCtx.TenantID,
		"framework_id": params["framework_id"],
	}
	return e.doPost(ctx, complianceURL+"/compliance/evidence/report", body, map[string]string{"X-Tenant-ID": runCtx.TenantID})
}

func (e *PlaybookExecutor) actionSnapshotPosture(ctx context.Context, params map[string]string, runCtx RunContext) error {
	complianceURL := envOr("COMPLIANCE_URL", "http://127.0.0.1:8110")
	body := map[string]string{
		"tenant_id": runCtx.TenantID,
		"refresh":   "true",
	}
	return e.doPost(ctx, complianceURL+"/compliance/posture", body, map[string]string{"X-Tenant-ID": runCtx.TenantID})
}

// ── Infrastructure Action Implementations ───────────────────────────────────

func (e *PlaybookExecutor) actionCreateBackup(ctx context.Context, params map[string]string, runCtx RunContext) error {
	backupURL := envOr("BACKUP_URL", "http://127.0.0.1:8090")
	body := map[string]string{
		"tenant_id": runCtx.TenantID,
		"label":     params["label"],
	}
	return e.doPost(ctx, backupURL+"/backup/snapshot", body, map[string]string{"X-Tenant-ID": runCtx.TenantID})
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

func (e *PlaybookExecutor) doPost(ctx context.Context, url string, payload interface{}, headers map[string]string) error {
	return e.doRequest(ctx, http.MethodPost, url, payload, headers)
}

func (e *PlaybookExecutor) doPut(ctx context.Context, url string, payload interface{}, headers map[string]string) error {
	return e.doRequest(ctx, http.MethodPut, url, payload, headers)
}

func (e *PlaybookExecutor) doDelete(ctx context.Context, url string, headers map[string]string) error {
	return e.doRequest(ctx, http.MethodDelete, url, nil, headers)
}

func (e *PlaybookExecutor) doRequest(ctx context.Context, method string, url string, payload interface{}, headers map[string]string) error {
	var bodyReader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal payload: %w", err)
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := e.http.Do(req)
	if err != nil {
		return fmt.Errorf("request to %s failed: %w", url, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("HTTP %d from %s: %s", resp.StatusCode, url, string(body))
	}
	return nil
}
