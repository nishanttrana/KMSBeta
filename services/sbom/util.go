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

func mustJSON(v interface{}, fallback string) string {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 {
		return fallback
	}
	return string(raw)
}

func nullableTime(v time.Time) interface{} {
	if v.IsZero() {
		return nil
	}
	return v.UTC()
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
			s := strings.TrimSpace(string(x))
			if s != "" {
				return s
			}
		}
	}
	return ""
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
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return s == "true" || s == "1" || s == "yes"
	default:
		return false
	}
}

func pct(part int, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(part) * 100 / float64(total)
}

func round2(v float64) float64 {
	n, _ := strconv.ParseFloat(strconv.FormatFloat(v, 'f', 2, 64), 64)
	return n
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

func normalizeAlgorithm(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		return "UNKNOWN"
	}
	return v
}

func isPQCAlgorithm(alg string) bool {
	switch {
	case strings.Contains(alg, "ML-KEM"),
		strings.Contains(alg, "KYBER"),
		strings.Contains(alg, "ML-DSA"),
		strings.Contains(alg, "DILITHIUM"),
		strings.Contains(alg, "FALCON"),
		strings.Contains(alg, "SPHINCS"),
		strings.Contains(alg, "SLH-DSA"):
		return true
	default:
		return false
	}
}

func isDeprecatedAlgorithm(alg string) bool {
	switch {
	case strings.Contains(alg, "3DES"),
		strings.Contains(alg, "DES"),
		strings.Contains(alg, "RC4"),
		strings.Contains(alg, "SHA-1"),
		strings.Contains(alg, "RSA-1024"):
		return true
	default:
		return false
	}
}

func inferBits(alg string) int {
	switch {
	case strings.Contains(alg, "AES-256"):
		return 256
	case strings.Contains(alg, "AES-192"):
		return 192
	case strings.Contains(alg, "AES-128"):
		return 128
	case strings.Contains(alg, "RSA-4096"):
		return 4096
	case strings.Contains(alg, "RSA-3072"):
		return 3072
	case strings.Contains(alg, "RSA-2048"):
		return 2048
	case strings.Contains(alg, "ML-KEM-1024"), strings.Contains(alg, "ML-DSA-87"):
		return 1024
	case strings.Contains(alg, "ML-KEM-768"), strings.Contains(alg, "ML-DSA-65"):
		return 768
	case strings.Contains(alg, "ML-KEM-512"), strings.Contains(alg, "ML-DSA-44"):
		return 512
	default:
		return 256
	}
}

func readinessStatus(pct float64) string {
	switch {
	case pct >= 80:
		return "ready"
	case pct >= 50:
		return "in_progress"
	default:
		return "not_ready"
	}
}

func compareSemver(a string, b string) int {
	a = trimSemverPrefix(a)
	b = trimSemverPrefix(b)
	ap := strings.Split(a, ".")
	bp := strings.Split(b, ".")
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		ai := 0
		bi := 0
		if i < len(ap) {
			ai = parseSemverPart(ap[i])
		}
		if i < len(bp) {
			bi = parseSemverPart(bp[i])
		}
		if ai < bi {
			return -1
		}
		if ai > bi {
			return 1
		}
	}
	return 0
}

func trimSemverPrefix(v string) string {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if idx := strings.IndexAny(v, "+-"); idx >= 0 {
		v = v[:idx]
	}
	return v
}

func parseSemverPart(v string) int {
	n := 0
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			break
		}
		n = n*10 + int(v[i]-'0')
	}
	return n
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

func extractErrorMessage(v map[string]interface{}) string {
	errAny, ok := v["error"]
	if !ok {
		return "request failed"
	}
	errMap, ok := errAny.(map[string]interface{})
	if !ok {
		return "request failed"
	}
	msg, _ := errMap["message"].(string)
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return "request failed"
	}
	return msg
}
