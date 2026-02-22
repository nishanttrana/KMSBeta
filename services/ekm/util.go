package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

func normalizeDBEngine(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "mssql", "sqlserver", "sql-server":
		return "mssql"
	case "oracle":
		return "oracle"
	case "postgres", "postgresql":
		return "postgresql"
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func isSQLServerEngine(v string) bool {
	e := normalizeDBEngine(v)
	return e == "mssql"
}

func normalizeRole(v string) string {
	role := strings.ToLower(strings.TrimSpace(v))
	switch role {
	case "", "ekm-agent", "ekm-client":
		return "ekm-agent"
	case "ekm-admin", "ekm-service":
		return role
	default:
		return role
	}
}

func normalizeAgentStatus(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", AgentStatusConnected:
		return AgentStatusConnected
	case AgentStatusDegraded:
		return AgentStatusDegraded
	case AgentStatusDisconnected:
		return AgentStatusDisconnected
	default:
		return ""
	}
}

func normalizeTDEState(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "unknown":
		return "unknown"
	case "enabled":
		return "enabled"
	case "disabled":
		return "disabled"
	case "encrypting":
		return "encrypting"
	case "paused":
		return "paused"
	default:
		return "unknown"
	}
}

func defaultInt(v int, d int) int {
	if v <= 0 {
		return d
	}
	return v
}

func defaultString(v string, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
}

func validJSONOr(v string, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	if json.Valid([]byte(v)) {
		return v
	}
	return fallback
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
	}
	for _, f := range formats {
		if ts, err := time.Parse(f, v); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func boolValue(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case int:
		return x != 0
	case []byte:
		s := strings.TrimSpace(string(x))
		return s == "1" || strings.EqualFold(s, "true")
	case string:
		s := strings.TrimSpace(x)
		return s == "1" || strings.EqualFold(s, "true")
	default:
		return false
	}
}

func nullableTime(v time.Time) interface{} {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
}

func shouldAuto(ptr *bool, fallback bool) bool {
	if ptr == nil {
		return fallback
	}
	return *ptr
}

func firstString(values ...interface{}) string {
	for _, v := range values {
		switch x := v.(type) {
		case string:
			if strings.TrimSpace(x) != "" {
				return strings.TrimSpace(x)
			}
		}
	}
	return ""
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
	default:
		return 0
	}
}

func parseVersionID(v string) int {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V"))
	if v == "" {
		return 0
	}
	n := 0
	for i := 0; i < len(v); i++ {
		ch := v[i]
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

func buildPublicKeyFallback(tenantID string, keyID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(tenantID) + ":" + strings.TrimSpace(keyID)))
	return "EKM-PUBLIC-" + hex.EncodeToString(sum[:16])
}

func heartbeatTimeout(agent Agent) time.Duration {
	base := defaultInt(agent.HeartbeatIntervalSec, DefaultHeartbeatSec)
	timeout := time.Duration(base*3) * time.Second
	if timeout < 45*time.Second {
		return 45 * time.Second
	}
	if timeout > 10*time.Minute {
		return 10 * time.Minute
	}
	return timeout
}

func httpStatusForErr(err error) int {
	var svcErr serviceError
	switch {
	case errors.As(err, &svcErr):
		return svcErr.HTTPStatus
	case errors.Is(err, errNotFound):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

func normalizeTargetOS(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "windows", "win", "windows-server":
		return "windows"
	case "linux", "linux-x64", "linux-amd64":
		return "linux"
	default:
		return ""
	}
}

func parseJSONMap(v string) map[string]interface{} {
	out := map[string]interface{}{}
	if strings.TrimSpace(v) == "" {
		return out
	}
	_ = json.Unmarshal([]byte(v), &out)
	return out
}

func mapStringAny(m map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if v, ok := m[k]; ok {
			switch x := v.(type) {
			case string:
				if strings.TrimSpace(x) != "" {
					return strings.TrimSpace(x)
				}
			case fmt.Stringer:
				s := strings.TrimSpace(x.String())
				if s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func mapFloatAny(m map[string]interface{}, keys ...string) float64 {
	for _, k := range keys {
		if v, ok := m[strings.TrimSpace(k)]; ok {
			switch x := v.(type) {
			case float64:
				return x
			case float32:
				return float64(x)
			case int:
				return float64(x)
			case int32:
				return float64(x)
			case int64:
				return float64(x)
			case json.Number:
				if f, err := x.Float64(); err == nil {
					return f
				}
			case string:
				s := strings.TrimSpace(x)
				if s == "" {
					continue
				}
				if f, err := strconv.ParseFloat(s, 64); err == nil {
					return f
				}
			}
		}
	}
	return 0
}

func mapInt64Any(m map[string]interface{}, keys ...string) int64 {
	for _, k := range keys {
		if v, ok := m[strings.TrimSpace(k)]; ok {
			switch x := v.(type) {
			case int64:
				return x
			case int:
				return int64(x)
			case int32:
				return int64(x)
			case float64:
				return int64(x)
			case float32:
				return int64(x)
			case json.Number:
				if n, err := x.Int64(); err == nil {
					return n
				}
			case string:
				s := strings.TrimSpace(x)
				if s == "" {
					continue
				}
				if n, err := strconv.ParseInt(s, 10, 64); err == nil {
					return n
				}
			}
		}
	}
	return 0
}
