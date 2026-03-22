package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strings"
	"time"
)

var errNotFound = errors.New("not found")

type serviceError struct {
	Status  int
	Code    string
	Message string
}

func (e serviceError) Error() string {
	if strings.TrimSpace(e.Message) != "" {
		return e.Message
	}
	return e.Code
}

func newServiceError(status int, code string, message string) error {
	return serviceError{Status: status, Code: strings.TrimSpace(code), Message: strings.TrimSpace(message)}
}

func httpStatusForErr(err error) int {
	var svcErr serviceError
	if errors.As(err, &svcErr) {
		if svcErr.Status > 0 {
			return svcErr.Status
		}
	}
	if errors.Is(err, errNotFound) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

func firstNonEmpty(values ...string) string {
	for _, item := range values {
		item = strings.TrimSpace(item)
		if item != "" {
			return item
		}
	}
	return ""
}

func trimLimit(value string, n int) string {
	value = strings.TrimSpace(value)
	if n <= 0 || len(value) <= n {
		return value
	}
	return strings.TrimSpace(value[:n])
}

func newID(prefix string) string {
	sum := sha256.Sum256([]byte(prefix + "|" + time.Now().UTC().Format(time.RFC3339Nano)))
	return strings.TrimSpace(prefix) + "_" + hex.EncodeToString(sum[:8])
}

func mustJSON(value interface{}, fallback string) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return fallback
	}
	return string(raw)
}

func parseJSONArrayString(raw string) []string {
	items := []string{}
	if err := json.Unmarshal([]byte(firstNonEmpty(raw, "[]")), &items); err != nil {
		return []string{}
	}
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func parseJSONObjectString(raw string) map[string]interface{} {
	out := map[string]interface{}{}
	if err := json.Unmarshal([]byte(firstNonEmpty(raw, "{}")), &out); err != nil {
		return map[string]interface{}{}
	}
	return out
}

func parseTimeValue(value interface{}) time.Time {
	switch v := value.(type) {
	case time.Time:
		return v.UTC()
	case string:
		parsed, _ := time.Parse(time.RFC3339, strings.TrimSpace(v))
		return parsed.UTC()
	default:
		return time.Time{}
	}
}

func normalizeStringList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, item := range values {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func sha256Hex(values ...string) string {
	h := sha256.New()
	for _, item := range values {
		_, _ = h.Write([]byte(item))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func matchesPatternList(patterns []string, value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if strings.EqualFold(pattern, value) {
			return true
		}
		ok, err := path.Match(pattern, value)
		if err == nil && ok {
			return true
		}
	}
	return false
}
