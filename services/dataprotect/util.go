package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
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

func mustJSON(v interface{}, fallback string) string {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) == 0 {
		return fallback
	}
	return string(raw)
}

func parseJSONArrayString(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return []string{}
	}
	var raw []interface{}
	_ = json.Unmarshal([]byte(v), &raw)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		s := strings.TrimSpace(firstString(item))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
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

func atoi(v string) int {
	n := 0
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return n
		}
		n = n*10 + int(v[i]-'0')
	}
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

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func containsString(items []string, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	for _, it := range items {
		if strings.ToLower(strings.TrimSpace(it)) == needle {
			return true
		}
	}
	return false
}

func hashHex(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func b64(v []byte) string {
	return base64.StdEncoding.EncodeToString(v)
}

func b64d(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return []byte{}, nil
	}
	return base64.StdEncoding.DecodeString(v)
}

func randBytes(n int) []byte {
	out := make([]byte, n)
	_, _ = rand.Read(out)
	return out
}

func hmacSHA256(key []byte, values ...string) []byte {
	m := hmac.New(sha256.New, key)
	for _, v := range values {
		_, _ = m.Write([]byte(v))
		_, _ = m.Write([]byte{0})
	}
	out := m.Sum(nil)
	return out
}

func keyFromHash(material []byte, purpose string) []byte {
	sum := hmacSHA256(material, "dataprotect", purpose)
	k := make([]byte, 32)
	copy(k, sum[:32])
	pkgcrypto.Zeroize(sum)
	return k
}

func zeroizeAll(items ...[]byte) {
	for _, it := range items {
		pkgcrypto.Zeroize(it)
	}
}

func normalizeTokenFormat(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "random", "format_preserving", "deterministic", "irreversible":
		return v
	default:
		return "random"
	}
}

func normalizeTokenMode(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "vaultless":
		return "vaultless"
	default:
		return "vault"
	}
}

func normalizeMaskPattern(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "full", "partial_last4", "partial_first2", "hash", "substitute", "nullify", "date_shift", "shuffle":
		return v
	default:
		return "full"
	}
}

func normalizeRedactAction(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "remove", "replace_placeholder", "hash":
		return v
	default:
		return "replace_placeholder"
	}
}

func normalizeFieldAlgorithm(v string, searchable bool) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if searchable {
		return "AES-SIV"
	}
	switch v {
	case "AES-GCM", "AES-SIV", "CHACHA20-POLY1305":
		return v
	default:
		return "AES-GCM"
	}
}

func maskString(v string, pattern string, consistent bool, seed []byte) string {
	switch normalizeMaskPattern(pattern) {
	case "full":
		return strings.Repeat("*", max(4, len(v)))
	case "partial_last4":
		if len(v) <= 4 {
			return strings.Repeat("*", len(v))
		}
		return strings.Repeat("*", len(v)-4) + v[len(v)-4:]
	case "partial_first2":
		if len(v) <= 2 {
			return strings.Repeat("*", len(v))
		}
		return v[:2] + strings.Repeat("*", len(v)-2)
	case "hash":
		return "hash_" + hashHex(v)[:16]
	case "substitute":
		return "MASKED"
	case "nullify":
		return ""
	case "date_shift":
		ts := parseTimeString(v)
		if ts.IsZero() {
			return v
		}
		delta := 7
		if consistent && len(seed) > 0 {
			delta = int(seed[0]%28) + 1
		}
		return ts.AddDate(0, 0, delta).Format(time.RFC3339)
	case "shuffle":
		if len(v) <= 1 {
			return v
		}
		runes := []rune(v)
		out := make([]rune, len(runes))
		copy(out, runes)
		for i := len(out) - 1; i > 0; i-- {
			j := i % (i + 1)
			if consistent && len(seed) > 0 {
				j = int(seed[i%len(seed)]) % (i + 1)
			}
			out[i], out[j] = out[j], out[i]
		}
		return string(out)
	default:
		return strings.Repeat("*", max(4, len(v)))
	}
}

func max(a int, b int) int {
	if a > b {
		return a
	}
	return b
}

func getPathValue(doc map[string]interface{}, path string) (interface{}, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false
	}
	path = strings.TrimPrefix(path, "$.")
	parts := strings.Split(path, ".")
	var cur interface{} = doc
	for _, p := range parts {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		next, ok := m[p]
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

func setPathValue(doc map[string]interface{}, path string, value interface{}) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	path = strings.TrimPrefix(path, "$.")
	parts := strings.Split(path, ".")
	cur := doc
	for i := 0; i < len(parts)-1; i++ {
		key := parts[i]
		next, ok := cur[key]
		if !ok {
			tmp := map[string]interface{}{}
			cur[key] = tmp
			cur = tmp
			continue
		}
		m, ok := next.(map[string]interface{})
		if !ok {
			return false
		}
		cur = m
	}
	cur[parts[len(parts)-1]] = value
	return true
}

func cloneMap(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return map[string]interface{}{}
	}
	out := map[string]interface{}{}
	for k, v := range in {
		switch x := v.(type) {
		case map[string]interface{}:
			out[k] = cloneMap(x)
		case []interface{}:
			tmp := make([]interface{}, 0, len(x))
			for _, it := range x {
				if m, ok := it.(map[string]interface{}); ok {
					tmp = append(tmp, cloneMap(m))
				} else {
					tmp = append(tmp, it)
				}
			}
			out[k] = tmp
		default:
			out[k] = x
		}
	}
	return out
}

var (
	regexEmail = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
	regexPhone = regexp.MustCompile(`\b(?:\+?\d{1,2}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){1}\d{3}[-.\s]?\d{4}\b`)
	regexSSN   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	regexPAN   = regexp.MustCompile(`\b\d{13,19}\b`)
	regexName  = regexp.MustCompile(`\b[A-Z][a-z]+ [A-Z][a-z]+\b`)
)

func sanitizeErrorMessage(v map[string]interface{}) string {
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
