package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

var errNotFound = errors.New("not found")

type serviceError struct {
	Code       string
	Message    string
	HTTPStatus int
}

func (e serviceError) Error() string {
	if strings.TrimSpace(e.Message) == "" {
		return e.Code
	}
	return e.Message
}

func newServiceError(status int, code string, message string) serviceError {
	return serviceError{Code: strings.TrimSpace(code), Message: strings.TrimSpace(message), HTTPStatus: status}
}

func httpStatusForErr(err error) int {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		return svcErr.HTTPStatus
	}
	if errors.Is(err, errNotFound) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

func newID(prefix string) string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return prefix + "_" + hex.EncodeToString(buf)
}

func mustJSON(v interface{}, fallback string) string {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 {
		return fallback
	}
	return string(raw)
}

func parseJSONArrayString(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []string{}
	}
	var items []interface{}
	_ = json.Unmarshal([]byte(raw), &items)
	out := make([]string, 0, len(items))
	for _, item := range items {
		switch v := item.(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				out = append(out, strings.TrimSpace(v))
			}
		}
	}
	sort.Strings(out)
	return uniqueStrings(out)
}

func parseJSONObjectString(raw string) map[string]interface{} {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]interface{}{}
	}
	var out map[string]interface{}
	_ = json.Unmarshal([]byte(raw), &out)
	if out == nil {
		return map[string]interface{}{}
	}
	return out
}

func parseTimeValue(v interface{}) time.Time {
	switch item := v.(type) {
	case time.Time:
		return item.UTC()
	case string:
		return parseTimeString(item)
	case []byte:
		return parseTimeString(string(item))
	default:
		return time.Time{}
	}
}

func parseTimeString(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func nullableTime(v time.Time) interface{} {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
}

func boolValue(v interface{}) bool {
	switch item := v.(type) {
	case bool:
		return item
	case int64:
		return item != 0
	case int:
		return item != 0
	case []byte:
		return boolValue(string(item))
	case string:
		switch strings.ToLower(strings.TrimSpace(item)) {
		case "1", "t", "true", "yes", "y", "on":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func uniqueStrings(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.ToLower(strings.TrimSpace(item))
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func containsScope(list []string, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	for _, item := range list {
		needle := strings.ToLower(strings.TrimSpace(item))
		if needle == "*" || needle == value {
			return true
		}
	}
	return false
}

func defaultSettings(tenantID string) KeyAccessSettings {
	return KeyAccessSettings{
		TenantID:                  strings.TrimSpace(tenantID),
		Enabled:                   false,
		Mode:                      "enforce",
		DefaultAction:             "deny",
		RequireJustificationCode:  true,
		RequireJustificationText:  false,
	}
}

func normalizeSettings(in KeyAccessSettings) KeyAccessSettings {
	out := in
	out.TenantID = strings.TrimSpace(out.TenantID)
	switch strings.ToLower(strings.TrimSpace(out.Mode)) {
	case "audit":
		out.Mode = "audit"
	default:
		out.Mode = "enforce"
	}
	switch strings.ToLower(strings.TrimSpace(out.DefaultAction)) {
	case "allow", "approval":
		out.DefaultAction = strings.ToLower(strings.TrimSpace(out.DefaultAction))
	default:
		out.DefaultAction = "deny"
	}
	out.ApprovalPolicyID = strings.TrimSpace(out.ApprovalPolicyID)
	out.UpdatedBy = strings.TrimSpace(out.UpdatedBy)
	return out
}

func normalizeRule(in KeyAccessRule) KeyAccessRule {
	out := in
	out.ID = strings.TrimSpace(out.ID)
	if out.ID == "" {
		out.ID = newID("kaj")
	}
	out.TenantID = strings.TrimSpace(out.TenantID)
	out.Code = strings.ToUpper(strings.TrimSpace(out.Code))
	out.Label = strings.TrimSpace(out.Label)
	out.Description = strings.TrimSpace(out.Description)
	switch strings.ToLower(strings.TrimSpace(out.Action)) {
	case "allow", "approval":
		out.Action = strings.ToLower(strings.TrimSpace(out.Action))
	default:
		out.Action = "deny"
	}
	out.Services = uniqueStrings(out.Services)
	out.Operations = uniqueStrings(out.Operations)
	out.ApprovalPolicyID = strings.TrimSpace(out.ApprovalPolicyID)
	out.UpdatedBy = strings.TrimSpace(out.UpdatedBy)
	return out
}

func normalizeEvaluation(in EvaluateKeyAccessInput) EvaluateKeyAccessInput {
	out := in
	out.TenantID = strings.TrimSpace(out.TenantID)
	out.Service = strings.ToLower(strings.TrimSpace(out.Service))
	out.Connector = strings.TrimSpace(out.Connector)
	out.Operation = strings.ToLower(strings.TrimSpace(out.Operation))
	out.KeyID = strings.TrimSpace(out.KeyID)
	out.ResourceID = strings.TrimSpace(out.ResourceID)
	out.TargetType = strings.TrimSpace(out.TargetType)
	out.RequestID = strings.TrimSpace(out.RequestID)
	out.RequesterID = strings.TrimSpace(out.RequesterID)
	out.RequesterEmail = strings.TrimSpace(out.RequesterEmail)
	out.RequesterIP = strings.TrimSpace(out.RequesterIP)
	out.JustificationCode = strings.ToUpper(strings.TrimSpace(out.JustificationCode))
	out.JustificationText = strings.TrimSpace(out.JustificationText)
	if out.Metadata == nil {
		out.Metadata = map[string]interface{}{}
	}
	if out.TargetType == "" {
		out.TargetType = "external_key_access"
	}
	return out
}

func normalizeDecisionAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow", "approval":
		return strings.ToLower(strings.TrimSpace(action))
	default:
		return "deny"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func publishAudit(ctx context.Context, publisher EventPublisher, subject string, tenantID string, payload map[string]interface{}) error {
	if publisher == nil || strings.TrimSpace(subject) == "" {
		return nil
	}
	if payload == nil {
		payload = map[string]interface{}{}
	}
	if strings.TrimSpace(tenantID) != "" && payload["tenant_id"] == nil {
		payload["tenant_id"] = strings.TrimSpace(tenantID)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return publisher.Publish(ctx, subject, raw)
}

func trimLimit(raw string, max int) string {
	raw = strings.TrimSpace(raw)
	if max <= 0 || len(raw) <= max {
		return raw
	}
	return raw[:max]
}

func strconvItoa(v int) string { return strconv.Itoa(v) }
