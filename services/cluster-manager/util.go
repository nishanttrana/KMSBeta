package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
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
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func randomHex(bytes int) string {
	if bytes <= 0 {
		bytes = 16
	}
	buf := make([]byte, bytes)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

func sha256Hex(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func mustJSON(v interface{}, fallback string) string {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 {
		return fallback
	}
	return string(raw)
}

func parseJSONObject(v string) map[string]interface{} {
	v = strings.TrimSpace(v)
	if v == "" {
		return map[string]interface{}{}
	}
	out := map[string]interface{}{}
	_ = json.Unmarshal([]byte(v), &out)
	if out == nil {
		return map[string]interface{}{}
	}
	return out
}

func parseJSONArrayString(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return []string{}
	}
	var raw []interface{}
	_ = json.Unmarshal([]byte(v), &raw)
	if raw == nil {
		return []string{}
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		s := strings.TrimSpace(firstString(item))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func firstString(values ...interface{}) string {
	for _, v := range values {
		switch x := v.(type) {
		case string:
			if strings.TrimSpace(x) != "" {
				return strings.TrimSpace(x)
			}
		case []byte:
			s := strings.TrimSpace(string(x))
			if s != "" {
				return s
			}
		}
	}
	return ""
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

func nullableTime(v time.Time) interface{} {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
}

func normalizeRole(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "leader":
		return "leader"
	case "follower":
		return "follower"
	default:
		return "follower"
	}
}

func normalizeNodeStatus(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "online", "running", "up", "healthy":
		return "online"
	case "degraded", "warning":
		return "degraded"
	case "down", "offline":
		return "down"
	default:
		return "unknown"
	}
}

func normalizeComponentName(v string) string {
	key := strings.ToLower(strings.TrimSpace(v))
	switch key {
	case "auth", "authentication":
		return "auth"
	case "keycore", "keys", "key-management":
		return "keycore"
	case "audit", "auditlog":
		return "audit"
	case "policy", "policies":
		return "policy"
	case "gov", "governance":
		return "governance"
	case "byok", "cloud_byok":
		return "byok"
	case "hyok", "hyok_proxy":
		return "hyok"
	case "payment", "payment_crypto":
		return "payment"
	case "dataprotect", "data_protection", "field_encryption":
		return "dataprotect"
	case "ekm", "enterprise_key_management":
		return "ekm"
	case "kmip", "kmip_server":
		return "kmip"
	case "certs", "certificates":
		return "certs"
	case "secrets", "vault":
		return "secrets"
	case "qkd":
		return "qkd"
	case "mpc", "mpc_engine":
		return "mpc"
	case "cluster", "clustering":
		return "cluster"
	case "compliance", "compliance_dashboard":
		return "compliance"
	case "reporting", "reporting_alerting", "alerts":
		return "reporting"
	case "sbom", "sbom_cbom", "cbom":
		return "sbom"
	case "pqc", "pqc_migration", "post_quantum":
		return "pqc"
	case "discovery", "crypto_discovery":
		return "discovery"
	case "ai", "ai_llm":
		return "ai"
	case "posture", "security_posture":
		return "posture"
	case "qrng", "qrng_entropy":
		return "qrng"
	case "cloud", "cloud_key_control":
		return "cloud"
	default:
		return ""
	}
}

func normalizeComponents(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		k := normalizeComponentName(item)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func componentDisplayName(component string) string {
	switch normalizeComponentName(component) {
	case "auth":
		return "Auth"
	case "keycore":
		return "KeyCore"
	case "audit":
		return "Audit"
	case "policy":
		return "Policy"
	case "governance":
		return "Gov"
	case "byok":
		return "BYOK"
	case "hyok":
		return "HYOK"
	case "payment":
		return "Payment"
	case "dataprotect":
		return "DataProtect"
	case "ekm":
		return "EKM"
	case "kmip":
		return "KMIP"
	case "certs":
		return "Certs"
	case "secrets":
		return "Secrets"
	case "qkd":
		return "QKD"
	case "mpc":
		return "MPC"
	case "cluster":
		return "Cluster"
	case "compliance":
		return "Compliance"
	case "reporting":
		return "Reporting"
	case "sbom":
		return "SBOM"
	case "pqc":
		return "PQC"
	case "discovery":
		return "Discovery"
	case "ai":
		return "AI"
	case "posture":
		return "Posture"
	case "qrng":
		return "QRNG"
	case "cloud":
		return "Cloud"
	default:
		return strings.TrimSpace(component)
	}
}

func defaultIfEmpty(v string, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
}
