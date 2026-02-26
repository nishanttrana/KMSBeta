package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	approvalDeliveryModeNotify  = "notify"
	approvalDeliveryModeKMSOnly = "kms_only"

	webhookChannelSlack = "slack"
	webhookChannelTeams = "teams"
)

func normalizeApprovalDeliveryMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "notify", "notification", "notifications":
		return approvalDeliveryModeNotify
	case "kms_only", "dashboard_only", "kms", "kms-only":
		return approvalDeliveryModeKMSOnly
	default:
		return ""
	}
}

func normalizeGovernanceSettings(in GovernanceSettings, strict bool) (GovernanceSettings, error) {
	modeInput := strings.TrimSpace(strings.ToLower(in.ApprovalDeliveryMode))
	mode := normalizeApprovalDeliveryMode(modeInput)
	if mode == "" {
		if strict {
			return GovernanceSettings{}, errors.New("approval_delivery_mode must be notify or kms_only")
		}
		mode = approvalDeliveryModeNotify
	}
	in.ApprovalDeliveryMode = mode
	in.ApprovalExpiryMinutes = clamp(in.ApprovalExpiryMinutes, 1, 1440)
	in.ExpiryCheckIntervalSeconds = clamp(in.ExpiryCheckIntervalSeconds, 5, 3600)
	if in.DeliveryWebhookTimeoutSec <= 0 {
		in.DeliveryWebhookTimeoutSec = 5
	}
	in.DeliveryWebhookTimeoutSec = clamp(in.DeliveryWebhookTimeoutSec, 1, 60)

	in.SMTPHost = strings.TrimSpace(in.SMTPHost)
	in.SMTPPort = strings.TrimSpace(in.SMTPPort)
	if in.SMTPPort == "" {
		in.SMTPPort = "587"
	}
	in.SMTPUsername = strings.TrimSpace(in.SMTPUsername)
	in.SMTPFrom = strings.TrimSpace(in.SMTPFrom)
	in.SlackWebhookURL = strings.TrimSpace(in.SlackWebhookURL)
	in.TeamsWebhookURL = strings.TrimSpace(in.TeamsWebhookURL)

	// Dashboard queue is always enabled because approvals are finalized in KMS.
	in.NotifyDashboard = true

	if mode == approvalDeliveryModeKMSOnly {
		in.NotifyEmail = false
		in.NotifySlack = false
		in.NotifyTeams = false
		in.ChallengeResponseEnabled = false
	} else {
		if strict && modeInput == approvalDeliveryModeNotify && !in.NotifyEmail && !in.NotifySlack && !in.NotifyTeams {
			return GovernanceSettings{}, errors.New("at least one notification channel must be enabled for notify mode")
		}
		if !in.NotifyEmail && !in.NotifySlack && !in.NotifyTeams {
			// Backward compatibility for older clients that did not send channel settings.
			in.NotifyEmail = true
		}
		if in.NotifySlack && in.SlackWebhookURL == "" {
			if strict {
				return GovernanceSettings{}, errors.New("slack_webhook_url is required when Slack notifications are enabled")
			}
			in.NotifySlack = false
		}
		if in.NotifyTeams && in.TeamsWebhookURL == "" {
			if strict {
				return GovernanceSettings{}, errors.New("teams_webhook_url is required when Teams notifications are enabled")
			}
			in.NotifyTeams = false
		}
		if in.ChallengeResponseEnabled && !in.NotifyEmail {
			if strict {
				return GovernanceSettings{}, errors.New("challenge-response requires email notifications")
			}
			in.ChallengeResponseEnabled = false
		}
	}
	if strings.TrimSpace(in.UpdatedBy) == "" {
		in.UpdatedBy = "system"
	} else {
		in.UpdatedBy = strings.TrimSpace(in.UpdatedBy)
	}
	return in, nil
}

func normalizeWebhookChannel(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case webhookChannelSlack:
		return webhookChannelSlack
	case webhookChannelTeams:
		return webhookChannelTeams
	default:
		return ""
	}
}

func (s *Service) sendConfiguredWebhooks(ctx context.Context, settings GovernanceSettings, req ApprovalRequest, approvers []string) {
	if settings.ApprovalDeliveryMode != approvalDeliveryModeNotify {
		return
	}
	if settings.NotifySlack {
		if err := s.sendSlackApprovalNotification(ctx, settings, req, approvers); err != nil {
			_ = s.publishAudit(ctx, "audit.governance.webhook_failed", req.TenantID, map[string]interface{}{
				"request_id": req.ID,
				"channel":    webhookChannelSlack,
				"error":      err.Error(),
			})
		} else {
			_ = s.publishAudit(ctx, "audit.governance.webhook_sent", req.TenantID, map[string]interface{}{
				"request_id": req.ID,
				"channel":    webhookChannelSlack,
			})
		}
	}
	if settings.NotifyTeams {
		if err := s.sendTeamsApprovalNotification(ctx, settings, req, approvers); err != nil {
			_ = s.publishAudit(ctx, "audit.governance.webhook_failed", req.TenantID, map[string]interface{}{
				"request_id": req.ID,
				"channel":    webhookChannelTeams,
				"error":      err.Error(),
			})
		} else {
			_ = s.publishAudit(ctx, "audit.governance.webhook_sent", req.TenantID, map[string]interface{}{
				"request_id": req.ID,
				"channel":    webhookChannelTeams,
			})
		}
	}
}

func (s *Service) sendSlackApprovalNotification(ctx context.Context, settings GovernanceSettings, req ApprovalRequest, approvers []string) error {
	if strings.TrimSpace(settings.SlackWebhookURL) == "" {
		return errors.New("slack webhook is not configured")
	}
	payload := map[string]interface{}{
		"text":          s.approvalNotificationText(req),
		"vecta_context": s.approvalNotificationContext(req, approvers),
	}
	return s.postWebhookJSON(ctx, settings.SlackWebhookURL, settings.DeliveryWebhookTimeoutSec, payload)
}

func (s *Service) sendTeamsApprovalNotification(ctx context.Context, settings GovernanceSettings, req ApprovalRequest, approvers []string) error {
	if strings.TrimSpace(settings.TeamsWebhookURL) == "" {
		return errors.New("teams webhook is not configured")
	}
	ctxData := s.approvalNotificationContext(req, approvers)
	facts := []map[string]string{
		{"name": "Tenant", "value": req.TenantID},
		{"name": "Action", "value": req.Action},
		{"name": "Target", "value": fmt.Sprintf("%s:%s", req.TargetType, req.TargetID)},
		{"name": "Requester", "value": firstNonEmpty(req.RequesterEmail, req.RequesterID)},
		{"name": "Request ID", "value": req.ID},
		{"name": "Expires", "value": req.ExpiresAt.UTC().Format(time.RFC3339)},
	}
	if urlValue := strings.TrimSpace(fmt.Sprintf("%v", ctxData["request_url"])); urlValue != "" {
		facts = append(facts, map[string]string{"name": "Request URL", "value": urlValue})
	}
	payload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"summary":    "Vecta KMS approval required",
		"themeColor": "0078D7",
		"title":      "Vecta KMS Approval Required",
		"text":       s.approvalNotificationText(req),
		"sections": []map[string]interface{}{
			{
				"facts": facts,
			},
		},
		"vecta_context": ctxData,
	}
	return s.postWebhookJSON(ctx, settings.TeamsWebhookURL, settings.DeliveryWebhookTimeoutSec, payload)
}

func (s *Service) approvalNotificationContext(req ApprovalRequest, approvers []string) map[string]interface{} {
	requestURL := ""
	base := strings.TrimRight(strings.TrimSpace(s.baseURL), "/")
	if base != "" {
		requestURL = fmt.Sprintf("%s/governance/requests/%s?tenant_id=%s", base, url.PathEscape(req.ID), url.QueryEscape(req.TenantID))
	}
	return map[string]interface{}{
		"event":              "governance.approval_required",
		"request_id":         req.ID,
		"tenant_id":          req.TenantID,
		"policy_id":          req.PolicyID,
		"action":             req.Action,
		"target_type":        req.TargetType,
		"target_id":          req.TargetID,
		"requester_id":       req.RequesterID,
		"requester_email":    req.RequesterEmail,
		"required_approvals": req.RequiredApprovals,
		"current_approvals":  req.CurrentApprovals,
		"current_denials":    req.CurrentDenials,
		"expires_at":         req.ExpiresAt.UTC().Format(time.RFC3339),
		"approvers":          approvers,
		"request_url":        requestURL,
	}
}

func (s *Service) approvalNotificationText(req ApprovalRequest) string {
	return fmt.Sprintf(
		"Approval required: %s on %s:%s (tenant=%s, request_id=%s, expires=%s)",
		req.Action,
		req.TargetType,
		req.TargetID,
		req.TenantID,
		req.ID,
		req.ExpiresAt.UTC().Format(time.RFC3339),
	)
}

func (s *Service) postWebhookJSON(ctx context.Context, targetURL string, timeoutSeconds int, payload map[string]interface{}) error {
	targetURL = strings.TrimSpace(targetURL)
	if targetURL == "" {
		return errors.New("webhook URL is required")
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errors.New("webhook URL must use http or https")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	timeout := time.Duration(clamp(timeoutSeconds, 1, 60)) * time.Second
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		msg := strings.TrimSpace(string(raw))
		if msg == "" {
			msg = "empty response body"
		}
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, msg)
	}
	return nil
}

func (s *Service) TestWebhook(ctx context.Context, tenantID string, channel string, overrideURL string) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return errors.New("tenant_id is required")
	}
	normalizedChannel := normalizeWebhookChannel(channel)
	if normalizedChannel == "" {
		return errors.New("channel must be slack or teams")
	}
	settings, err := s.GetSettings(ctx, tenantID)
	if err != nil {
		return err
	}
	targetURL := strings.TrimSpace(overrideURL)
	switch normalizedChannel {
	case webhookChannelSlack:
		targetURL = firstNonEmpty(targetURL, settings.SlackWebhookURL)
	case webhookChannelTeams:
		targetURL = firstNonEmpty(targetURL, settings.TeamsWebhookURL)
	}
	if strings.TrimSpace(targetURL) == "" {
		return fmt.Errorf("%s webhook is not configured", normalizedChannel)
	}
	notification := map[string]interface{}{
		"event":     "governance.webhook_test",
		"tenant_id": tenantID,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
		"channel":   normalizedChannel,
	}
	var payload map[string]interface{}
	if normalizedChannel == webhookChannelTeams {
		payload = map[string]interface{}{
			"@type":      "MessageCard",
			"@context":   "http://schema.org/extensions",
			"summary":    "Vecta KMS webhook test",
			"themeColor": "06d6e0",
			"title":      "Vecta KMS Webhook Test",
			"text":       fmt.Sprintf("Governance %s webhook connectivity test for tenant %s.", normalizedChannel, tenantID),
			"vecta_test": notification,
		}
	} else {
		payload = map[string]interface{}{
			"text":       fmt.Sprintf("Vecta KMS governance %s webhook connectivity test (tenant=%s).", normalizedChannel, tenantID),
			"vecta_test": notification,
		}
	}
	if err := s.postWebhookJSON(ctx, targetURL, settings.DeliveryWebhookTimeoutSec, payload); err != nil {
		return err
	}
	_ = s.publishAudit(ctx, "audit.governance.webhook_tested", tenantID, map[string]interface{}{
		"channel": normalizedChannel,
	})
	return nil
}
