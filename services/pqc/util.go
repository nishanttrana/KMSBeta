package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	pkgcrypto "vecta-kms/pkg/crypto"
	"vecta-kms/pkg/cryptocatalog"
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
	b := make([]byte, 8)
	_, _ = pkgcrypto.Reader.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
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
		return atoi(strings.TrimSpace(x))
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
	case float64:
		return x != 0
	case string:
		s := strings.ToLower(strings.TrimSpace(x))
		return s == "1" || s == "true" || s == "yes"
	default:
		return false
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
		return float64(atoi(strings.TrimSpace(x)))
	default:
		return 0
	}
}

func parseTimeString(v string) time.Time {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}
	}
	formats := []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"}
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

func parseStringIntMap(v string) map[string]int {
	v = strings.TrimSpace(v)
	if v == "" {
		return map[string]int{}
	}
	out := map[string]int{}
	_ = json.Unmarshal([]byte(v), &out)
	if out == nil {
		return map[string]int{}
	}
	return out
}

func parseRiskItems(v string) []AssetRisk {
	v = strings.TrimSpace(v)
	if v == "" {
		return []AssetRisk{}
	}
	items := []AssetRisk{}
	_ = json.Unmarshal([]byte(v), &items)
	if items == nil {
		return []AssetRisk{}
	}
	return items
}

func parseMigrationSteps(v string) []MigrationStep {
	v = strings.TrimSpace(v)
	if v == "" {
		return []MigrationStep{}
	}
	items := []MigrationStep{}
	_ = json.Unmarshal([]byte(v), &items)
	if items == nil {
		return []MigrationStep{}
	}
	return items
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		v := strings.ToLower(strings.TrimSpace(item))
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

func pct(n int, d int) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) * 100 / float64(d)
}

func round2(v float64) float64 {
	if v < 0 {
		return -round2(-v)
	}
	x := int(v*100 + 0.5)
	return float64(x) / 100
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

func normalizeAlgorithm(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		return "UNKNOWN"
	}
	return v
}

// Algorithm facts come from pkg/cryptocatalog, which cites the NIST table
// behind each one. Before 3.2.0-beta this service kept its own lists: RSA-4096
// and ECDSA were "strong", SLH-DSA was not post-quantum, and hybrids counted
// as pure PQC.

// isPQCAlgorithm: a post-quantum scheme (FIPS 203/204/205, SP 800-208) that
// is not a hybrid.
func isPQCAlgorithm(alg string) bool {
	e, ok := cryptocatalog.Lookup(alg)
	return ok && e.PostQuantum && !e.Hybrid
}

func isHybridAlgorithm(alg string) bool {
	e, ok := cryptocatalog.Lookup(alg)
	return ok && e.Hybrid
}

// isDeprecatedAlgorithm: NIST no longer allows it for new protection
// (disallowed, legacy use only, or not approved).
func isDeprecatedAlgorithm(alg string) bool {
	a := cryptocatalog.Assess(alg, time.Now())
	return a.Assessed && !a.Status.Protects() && a.Status != cryptocatalog.NotTabled
}

// algorithmQSL is 100 when the algorithm resists a quantum computer and NIST
// allows it for new protection today, else 0 (including when not assessed).
// It replaced hand-picked 35-100 scores that had no source.
func algorithmQSL(alg string) float64 {
	if cryptocatalog.Assess(alg, time.Now()).Ready {
		return 100
	}
	return 0
}

// classifyAlgorithm is vulnerable, weak, strong or unknown
// (cryptocatalog.Assess).
func classifyAlgorithm(alg string) string {
	return cryptocatalog.Assess(alg, time.Now()).Class
}

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
