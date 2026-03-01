package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

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
	return serviceError{
		Code:       strings.TrimSpace(code),
		Message:    strings.TrimSpace(message),
		HTTPStatus: status,
	}
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstString(values ...interface{}) string {
	for _, v := range values {
		switch x := v.(type) {
		case string:
			if strings.TrimSpace(x) != "" {
				return strings.TrimSpace(x)
			}
		case []byte:
			if strings.TrimSpace(string(x)) != "" {
				return strings.TrimSpace(string(x))
			}
		}
	}
	return ""
}

func mustJSON(v interface{}, fallback string) string {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 {
		return fallback
	}
	return string(raw)
}

func parseTimeValue(v interface{}) time.Time {
	switch x := v.(type) {
	case time.Time:
		return x.UTC()
	case string:
		return parseTimeString(x)
	case []byte:
		return parseTimeString(string(x))
	default:
		return time.Time{}
	}
}

func parseTimeString(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, f := range formats {
		if ts, err := time.Parse(f, v); err == nil {
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

func defaultString(v string, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
}

func extractInt(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case int32:
		return int(x)
	case int64:
		return int(x)
	case float64:
		return int(x)
	case float32:
		return int(x)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	default:
		return 0
	}
}

func extractBool(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return s == "true" || s == "1" || s == "yes"
	case int:
		return x != 0
	case float64:
		return x != 0
	default:
		return false
	}
}

func normalizeSeverity(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case severityCritical:
		return severityCritical
	case severityHigh:
		return severityHigh
	case severityWarning:
		return severityWarning
	default:
		return severityInfo
	}
}

func normalizeTelemetryLevel(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "critical":
		return "critical"
	case "warning", "warn":
		return "warning"
	case "info":
		return "info"
	default:
		return "error"
	}
}

func severityRank(v string) int {
	switch normalizeSeverity(v) {
	case severityCritical:
		return 4
	case severityHigh:
		return 3
	case severityWarning:
		return 2
	default:
		return 1
	}
}

func maxSeverity(a string, b string) string {
	if severityRank(a) >= severityRank(b) {
		return normalizeSeverity(a)
	}
	return normalizeSeverity(b)
}

func matchPattern(action string, pattern string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return false
	}
	if pattern == "*" || pattern == "*.*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(action, prefix)
	}
	return action == pattern
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
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

func atoi(v string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}

func severityDefaults() map[string]string {
	defaults := map[string]string{}
	add := func(sev string, patterns ...string) {
		for _, p := range patterns {
			defaults[strings.ToLower(strings.TrimSpace(p))] = sev
		}
	}
	add(severityCritical,
		"auth.login_failed#threshold",
		"auth.ip_blocked",
		"key.compromised",
		"key.destroyed",
		"fips.violation_blocked",
		"audit.chain_integrity_break",
		"cluster.node_failed",
		"cluster.failover_triggered",
		"mpc.dkg_failed",
		"ekm.agent_disconnected",
	)
	add(severityHigh,
		"key.exported",
		"policy.violated",
		"governance.quorum_denied",
		"cert.revoked",
		"audit.cert.revoked",
		"cloud.sync_failed",
		"dataprotect.detokenize",
		"payment.pin_translated",
	)
	add(severityWarning,
		"auth.login_failed",
		"auth.rate_limited",
		"key.rotated",
		"cert.expired",
		"cert.expiring",
		"audit.cert.expired",
		"audit.cert.expiring",
		"compliance.posture_changed",
		"sbom.cve_detected",
		"admin.config_changed",
	)
	add(severityInfo,
		"*.encrypt",
		"*.decrypt",
		"*.sign",
		"*.verify",
		"auth.login",
		"auth.logout",
		"key.created",
		"key.metadata_read",
		"cert.issued",
		"cert.downloaded",
		"reporting.*",
		"payment.*",
		"kmip.*",
		"pkcs11.*",
	)
	return defaults
}
