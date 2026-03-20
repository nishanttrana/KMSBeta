package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"
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

func nowUTC() time.Time { return time.Now().UTC() }

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
		v := strings.TrimSpace(firstString(item))
		if v != "" {
			out = append(out, v)
		}
	}
	return uniqueStrings(out)
}

func parseJSONObjectString(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]string{}
	}
	var items map[string]interface{}
	_ = json.Unmarshal([]byte(raw), &items)
	out := map[string]string{}
	for k, v := range items {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		out[k] = strings.TrimSpace(firstString(v))
	}
	return out
}

func parseSpec(raw string) map[string]interface{} {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]interface{}{}
	}
	out := map[string]interface{}{}
	_ = json.Unmarshal([]byte(raw), &out)
	if out == nil {
		return map[string]interface{}{}
	}
	return out
}

func firstString(values ...interface{}) string {
	for _, v := range values {
		switch item := v.(type) {
		case string:
			if strings.TrimSpace(item) != "" {
				return strings.TrimSpace(item)
			}
		case []byte:
			if strings.TrimSpace(string(item)) != "" {
				return strings.TrimSpace(string(item))
			}
		}
	}
	return ""
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

func uniqueStrings(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
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

func uniqueLabelMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range in {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		out[trimmedKey] = strings.TrimSpace(value)
	}
	return out
}

var slugPattern = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(raw string) string {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	normalized = slugPattern.ReplaceAllString(normalized, "-")
	normalized = strings.Trim(normalized, "-")
	if normalized == "" {
		return "resource"
	}
	return normalized
}

func renderPattern(pattern string, tenantID string, serviceName string, resourceType string, resourceRef string) string {
	pattern = strings.TrimSpace(pattern)
	slug := slugify(resourceRef)
	if pattern == "" {
		return ""
	}
	replacer := strings.NewReplacer(
		"{{tenant}}", strings.TrimSpace(tenantID),
		"{{service}}", strings.TrimSpace(serviceName),
		"{{resource_type}}", strings.TrimSpace(resourceType),
		"{{resource_ref}}", strings.TrimSpace(resourceRef),
		"{{resource_slug}}", slug,
	)
	return strings.TrimSpace(replacer.Replace(pattern))
}

func defaultSettings(tenantID string) AutokeySettings {
	return AutokeySettings{
		TenantID:              strings.TrimSpace(tenantID),
		Enabled:               false,
		Mode:                  "enforce",
		RequireApproval:       true,
		RequireJustification:  true,
		AllowTemplateOverride: true,
		DefaultRotationDays:   90,
	}
}

func normalizeSettings(in AutokeySettings) AutokeySettings {
	out := in
	out.TenantID = strings.TrimSpace(out.TenantID)
	switch strings.ToLower(strings.TrimSpace(out.Mode)) {
	case "audit":
		out.Mode = "audit"
	default:
		out.Mode = "enforce"
	}
	if out.DefaultRotationDays <= 0 {
		out.DefaultRotationDays = 90
	}
	out.DefaultPolicyID = strings.TrimSpace(out.DefaultPolicyID)
	out.UpdatedBy = strings.TrimSpace(out.UpdatedBy)
	return out
}

func normalizeTemplate(in AutokeyTemplate) AutokeyTemplate {
	out := in
	out.ID = strings.TrimSpace(out.ID)
	if out.ID == "" {
		out.ID = newID("aktpl")
	}
	out.TenantID = strings.TrimSpace(out.TenantID)
	out.Name = strings.TrimSpace(out.Name)
	out.ServiceName = normalizeServiceName(out.ServiceName)
	out.ResourceType = normalizeResourceType(out.ResourceType)
	out.HandleNamePattern = strings.TrimSpace(out.HandleNamePattern)
	out.KeyNamePattern = strings.TrimSpace(out.KeyNamePattern)
	out.Algorithm = normalizeAlgorithm(out.Algorithm)
	out.KeyType = normalizeKeyType(out.KeyType, out.Algorithm)
	out.Purpose = normalizePurpose(out.Purpose, out.Algorithm)
	out.IVMode = normalizeIVMode(out.IVMode)
	out.Tags = uniqueStrings(out.Tags)
	out.Labels = uniqueLabelMap(out.Labels)
	out.ApprovalPolicyID = strings.TrimSpace(out.ApprovalPolicyID)
	out.Description = strings.TrimSpace(out.Description)
	out.UpdatedBy = strings.TrimSpace(out.UpdatedBy)
	if out.Name == "" {
		out.Name = strings.TrimSpace(out.ServiceName + " " + out.ResourceType)
	}
	if out.HandleNamePattern == "" {
		out.HandleNamePattern = "{{service}}/{{resource_type}}/{{resource_slug}}"
	}
	if out.KeyNamePattern == "" {
		out.KeyNamePattern = "ak-{{service}}-{{resource_slug}}"
	}
	if out.OpsLimitWindow == "" {
		out.OpsLimitWindow = "24h"
	}
	return out
}

func normalizeServicePolicy(in AutokeyServicePolicy) AutokeyServicePolicy {
	out := in
	out.TenantID = strings.TrimSpace(out.TenantID)
	out.ServiceName = normalizeServiceName(out.ServiceName)
	out.DisplayName = strings.TrimSpace(out.DisplayName)
	out.DefaultTemplateID = strings.TrimSpace(out.DefaultTemplateID)
	out.Algorithm = normalizeAlgorithm(out.Algorithm)
	out.KeyType = normalizeKeyType(out.KeyType, out.Algorithm)
	out.Purpose = normalizePurpose(out.Purpose, out.Algorithm)
	out.IVMode = normalizeIVMode(out.IVMode)
	out.Tags = uniqueStrings(out.Tags)
	out.Labels = uniqueLabelMap(out.Labels)
	out.ApprovalPolicyID = strings.TrimSpace(out.ApprovalPolicyID)
	out.Description = strings.TrimSpace(out.Description)
	out.UpdatedBy = strings.TrimSpace(out.UpdatedBy)
	out.OpsLimitWindow = strings.TrimSpace(out.OpsLimitWindow)
	if out.OpsLimitWindow == "" && out.OpsLimit > 0 {
		out.OpsLimitWindow = "24h"
	}
	if out.DisplayName == "" {
		out.DisplayName = strings.Title(strings.ReplaceAll(out.ServiceName, "-", " "))
	}
	return out
}

func normalizeRequestInput(in CreateAutokeyRequestInput) CreateAutokeyRequestInput {
	out := in
	out.TenantID = strings.TrimSpace(out.TenantID)
	out.ServiceName = normalizeServiceName(out.ServiceName)
	out.ResourceType = normalizeResourceType(out.ResourceType)
	out.ResourceRef = strings.TrimSpace(out.ResourceRef)
	out.TemplateID = strings.TrimSpace(out.TemplateID)
	out.HandleName = strings.TrimSpace(out.HandleName)
	out.KeyName = strings.TrimSpace(out.KeyName)
	out.RequestedAlgorithm = normalizeAlgorithm(out.RequestedAlgorithm)
	out.RequestedKeyType = normalizeKeyType(out.RequestedKeyType, out.RequestedAlgorithm)
	out.RequestedPurpose = normalizePurpose(out.RequestedPurpose, out.RequestedAlgorithm)
	out.Tags = uniqueStrings(out.Tags)
	out.Labels = uniqueLabelMap(out.Labels)
	out.Justification = strings.TrimSpace(out.Justification)
	out.RequesterID = strings.TrimSpace(out.RequesterID)
	out.RequesterEmail = strings.TrimSpace(out.RequesterEmail)
	out.RequesterIP = strings.TrimSpace(out.RequesterIP)
	return out
}

func normalizeServiceName(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.ReplaceAll(raw, "_", "-")
	switch raw {
	case "restapi":
		return "rest-api"
	case "paymentcrypto":
		return "payment"
	case "cloudkeycontrol":
		return "cloud"
	case "workloadidentity":
		return "workload"
	}
	return raw
}

func normalizeResourceType(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.ReplaceAll(raw, "_", "-")
	if raw == "" {
		return "resource"
	}
	return raw
}

func normalizeAlgorithm(raw string) string {
	raw = strings.ToUpper(strings.TrimSpace(raw))
	if raw == "" {
		return "AES-256"
	}
	return raw
}

func normalizeKeyType(raw string, algorithm string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw != "" {
		return raw
	}
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.Contains(alg, "RSA"), strings.Contains(alg, "ECDSA"), strings.Contains(alg, "ECDH"),
		strings.Contains(alg, "ED25519"), strings.Contains(alg, "ED448"), strings.Contains(alg, "X25519"),
		strings.Contains(alg, "X448"), strings.Contains(alg, "ML-KEM"), strings.Contains(alg, "ML-DSA"), strings.Contains(alg, "SLH-DSA"):
		return "asymmetric"
	default:
		return "symmetric"
	}
}

func normalizePurpose(raw string, algorithm string) string {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		return raw
	}
	alg := strings.ToUpper(strings.TrimSpace(algorithm))
	switch {
	case strings.Contains(alg, "HMAC"), strings.Contains(alg, "CMAC"), strings.Contains(alg, "GMAC"):
		return "mac"
	case strings.Contains(alg, "RSA"), strings.Contains(alg, "ECDSA"), strings.Contains(alg, "ED25519"), strings.Contains(alg, "ML-DSA"), strings.Contains(alg, "SLH-DSA"):
		return "sign-verify"
	case strings.Contains(alg, "ECDH"), strings.Contains(alg, "X25519"), strings.Contains(alg, "ML-KEM"):
		return "key-agreement"
	default:
		return "encrypt-decrypt"
	}
}

func normalizeIVMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "external", "deterministic":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "internal"
	}
}

func publishAudit(ctx context.Context, events EventPublisher, subject string, tenantID string, payload map[string]interface{}) error {
	if events == nil {
		return nil
	}
	if payload == nil {
		payload = map[string]interface{}{}
	}
	payload["tenant_id"] = strings.TrimSpace(tenantID)
	payload["timestamp"] = nowUTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return events.Publish(ctx, subject, raw)
}

func sha256Hex(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}
