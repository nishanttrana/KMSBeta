package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"vecta-kms/pkg/ssrfguard"
)

var eventPatternRE = regexp.MustCompile(`^audit(\.[a-z0-9_]+)+(\.\*)?$|^audit\.\*$|^\*$`)

// reservedWebhookHeaders are set by the platform and can't be overridden.
var reservedWebhookHeaders = map[string]bool{
	"Content-Type": true, "Content-Length": true, "Host": true, "User-Agent": true,
	"X-Kms-Signature": true, "X-Kms-Event-Type": true, "X-Kms-Event-Id": true,
}

// webhookSelfPrefix marks the audit service's own delivery events. They are
// never delivered, or each delivery would trigger another.
const webhookSelfPrefix = "audit.audit.webhook_"

// eventMatches reports whether a subscription pattern selects an action:
// "*", an exact action ("audit.key.rotate") or a prefix ("audit.key.*").
func eventMatches(patterns []string, action string) bool {
	for _, p := range patterns {
		switch {
		case p == "*":
			return true
		case strings.HasSuffix(p, ".*"):
			if strings.HasPrefix(action, strings.TrimSuffix(p, "*")) {
				return true
			}
		case p == action:
			return true
		}
	}
	return false
}

func validateWebhookURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" {
		return errors.New("webhook URL must be https")
	}
	if err := ssrfguard.ValidateWebhookURL(raw); err != nil {
		return fmt.Errorf("webhook URL blocked: %w", err)
	}
	return nil
}

func validateWebhookEvents(events []string) error {
	if len(events) == 0 {
		return errors.New("events is required: *, an audit action (audit.key.rotate) or a prefix (audit.key.*)")
	}
	for _, e := range events {
		if !eventPatternRE.MatchString(e) {
			return fmt.Errorf("event %q is not an audit action or prefix (e.g. audit.key.*)", e)
		}
	}
	return nil
}

// publicWebhook is the API view: the secret is reduced to has_secret and
// header values (tokens, API keys) are blanked. Both are write-only.
func publicWebhook(w Webhook) Webhook {
	w.HasSecret = w.HasSecret || w.Secret != ""
	w.Secret = ""
	w.Headers = headerNames(w.Headers)
	return w
}

// formatWebhookPayload renders one audit event for the webhook's format.
func formatWebhookPayload(format string, ev AuditEvent) ([]byte, error) {
	switch format {
	case "json":
		return json.Marshal(map[string]interface{}{"event_type": ev.Action, "event": ev})
	case "splunk_hec":
		return json.Marshal(map[string]interface{}{
			"time": ev.Timestamp.Unix(), "host": ev.NodeID, "source": "vecta-kms",
			"sourcetype": "vecta:audit", "event": ev,
		})
	case "datadog":
		msg, err := json.Marshal(ev)
		if err != nil {
			return nil, err
		}
		return json.Marshal([]map[string]interface{}{{
			"ddsource": "vecta-kms", "service": ev.Service, "hostname": ev.NodeID,
			"ddtags":  fmt.Sprintf("tenant:%s,action:%s,result:%s", ev.TenantID, ev.Action, ev.Result),
			"message": string(msg),
		}})
	case "teams":
		text, err := formatWebhookPayload("slack", ev)
		if err != nil {
			return nil, err
		}
		var m map[string]string
		_ = json.Unmarshal(text, &m)
		return json.Marshal(map[string]interface{}{"type": "message", "attachments": []map[string]interface{}{{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"content": map[string]interface{}{
				"$schema": "https://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
				"body": []map[string]interface{}{{"type": "TextBlock", "text": m["text"], "wrap": true}},
			},
		}}})
	case "slack":
		target := ev.TargetType
		if ev.TargetID != "" {
			target += " " + ev.TargetID
		}
		return json.Marshal(map[string]string{"text": fmt.Sprintf("Vecta KMS: %s (%s) tenant %s, actor %s, target %s",
			ev.Action, ev.Result, ev.TenantID, firstNonEmptyString(ev.ActorID, "system"), firstNonEmptyString(strings.TrimSpace(target), "-"))})
	}
	return nil, fmt.Errorf("unsupported webhook format %q", format)
}

func firstNonEmptyString(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
