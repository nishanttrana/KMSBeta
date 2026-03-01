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

func nowUTC() time.Time {
	return time.Now().UTC()
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

func statusToSeverity(result string) string {
	switch strings.ToLower(strings.TrimSpace(result)) {
	case "failure", "failed", "error":
		return severityHigh
	case "denied", "blocked":
		return severityCritical
	default:
		return severityInfo
	}
}

func defaultString(v string, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
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
		case json.Number:
			if strings.TrimSpace(x.String()) != "" {
				return strings.TrimSpace(x.String())
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

func parseFloat(v interface{}) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f
	default:
		return 0
	}
}

func parseInt(v interface{}) int {
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
	case json.Number:
		i, _ := x.Int64()
		return int(i)
	case string:
		i, _ := strconv.Atoi(strings.TrimSpace(x))
		return i
	default:
		return 0
	}
}

func parseBool(v interface{}) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return s == "1" || s == "true" || s == "yes"
	default:
		return false
	}
}

func mustJSON(v interface{}, fallback string) string {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 {
		return fallback
	}
	return string(raw)
}

func parseJSONMap(raw string) map[string]interface{} {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return map[string]interface{}{}
	}
	out := map[string]interface{}{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return map[string]interface{}{}
	}
	return out
}

func clampRisk(n int) int {
	if n < 0 {
		return 0
	}
	if n > 100 {
		return 100
	}
	return n
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func requestID(r *http.Request) string {
	reqID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
	if reqID == "" {
		reqID = newID("req")
	}
	return reqID
}

func tenantFromRequest(r *http.Request) string {
	return firstNonEmpty(
		r.URL.Query().Get("tenant_id"),
		r.Header.Get("X-Tenant-ID"),
	)
}

func mustTenant(r *http.Request, reqID string, w http.ResponseWriter) string {
	tenantID := strings.TrimSpace(tenantFromRequest(r))
	if tenantID == "" {
		writeErr(w, http.StatusBadRequest, "tenant_required", "tenant_id is required", reqID, "")
		return ""
	}
	return tenantID
}

func decodeJSON(r *http.Request, out interface{}) error {
	if r.Body == nil {
		return errors.New("request body is required")
	}
	defer r.Body.Close() //nolint:errcheck
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeErr(w http.ResponseWriter, status int, code string, message string, reqID string, tenantID string) {
	writeJSON(w, status, map[string]interface{}{
		"error": map[string]interface{}{
			"code":       defaultString(code, "internal_error"),
			"message":    defaultString(message, "request failed"),
			"request_id": reqID,
			"tenant_id":  tenantID,
		},
	})
}

func slaForSeverity(sev string, base time.Time) time.Time {
	switch normalizeSeverity(sev) {
	case severityCritical:
		return base.Add(4 * time.Hour)
	case severityHigh:
		return base.Add(12 * time.Hour)
	case severityWarning:
		return base.Add(24 * time.Hour)
	default:
		return base.Add(72 * time.Hour)
	}
}

func fingerprint(parts ...string) string {
	h := strings.Join(parts, "|")
	if strings.TrimSpace(h) == "" {
		return newID("fp")
	}
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(h)))))
	return sum
}
