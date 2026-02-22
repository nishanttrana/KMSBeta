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

func parseDateParam(v string) time.Time {
	return parseTimeString(v)
}

func defaultString(v string, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return strings.TrimSpace(v)
}

func clampScore(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func pct(part int, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(part) * 100 / float64(total)
}

func round2(v float64) float64 {
	if v == 0 {
		return 0
	}
	n, _ := strconv.ParseFloat(strconv.FormatFloat(v, 'f', 2, 64), 64)
	return n
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
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	default:
		return 0
	}
}

func extractFloat(v interface{}) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f
	default:
		return 0
	}
}

func extractBool(v interface{}) bool {
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
		s := strings.TrimSpace(strings.ToLower(x))
		return s == "true" || s == "1" || s == "yes"
	default:
		return false
	}
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

func parseStringSliceJSON(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func mustJSON(v interface{}, fallback string) string {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 {
		return fallback
	}
	return string(raw)
}

func normalizeFrameworkID(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "pci", "pci-dss", "pci-dss-4", "pci-dss-4.0":
		return frameworkPCIDSS
	case "fips", "fips-140", "fips-140-3":
		return frameworkFIPS
	case "nist", "nist-800-57":
		return frameworkNIST
	case "eidas":
		return frameworkEIDAS
	default:
		return strings.ToLower(strings.TrimSpace(v))
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

func atoi(v string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(v))
	return n
}
