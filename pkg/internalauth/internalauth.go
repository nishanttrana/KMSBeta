// Package internalauth gates service-to-service endpoints (reconciler →
// keycore / KMIP / policy / audit) behind a shared bearer secret. The
// secret is delivered via the INTERNAL_API_TOKEN environment variable on
// both ends; production deployments inject a per-cluster random value at
// startup and rotate via secret-management tooling.
//
// The middleware is fail-closed: when the server-side env var is empty,
// every request is refused with 503. This prevents a misconfigured node
// from quietly accepting unauthenticated traffic on routes that were
// previously open by accident.
package internalauth

import (
	"crypto/hmac"
	"net/http"
	"os"
	"strings"
)

// HeaderName is the canonical header the reconciler sends and the gated
// endpoints inspect. Bearer tokens via Authorization are also accepted so
// curl-based debugging stays ergonomic.
const HeaderName = "X-Internal-Token"

// EnvVar names the operator-set secret. The constant is exported so tests
// and orchestration tooling can reference one source of truth.
const EnvVar = "INTERNAL_API_TOKEN"

// RequireToken wraps a handler with a constant-time bearer-token check.
//
// Behaviour:
//   - Server side has no token configured → 503 "internal endpoint not
//     configured" (fail-closed; the deployment is incomplete).
//   - Request omits the token → 401 "missing internal token".
//   - Request supplies the wrong token → 403 "invalid internal token".
//   - Match → handler executes.
//
// The check uses hmac.Equal so the comparison is constant-time. The
// token is read from the environment on every call so rotation via
// process re-exec is enough; no in-process cache.
func RequireToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expected := strings.TrimSpace(os.Getenv(EnvVar))
		if expected == "" {
			writeJSONErr(w, http.StatusServiceUnavailable, "internal_unconfigured", "internal endpoint not configured")
			return
		}
		provided := strings.TrimSpace(r.Header.Get(HeaderName))
		if provided == "" {
			if bearer := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")); bearer != "" {
				provided = bearer
			}
		}
		if provided == "" {
			writeJSONErr(w, http.StatusUnauthorized, "missing_internal_token", "missing internal token")
			return
		}
		if !hmac.Equal([]byte(provided), []byte(expected)) {
			writeJSONErr(w, http.StatusForbidden, "invalid_internal_token", "invalid internal token")
			return
		}
		next(w, r)
	}
}

// AddTokenHeader attaches the internal token to an outbound request from
// the INTERNAL_API_TOKEN env var. Callers should invoke this on every
// reconciler-originated HTTP request; downstream endpoints will reject
// the call otherwise.
func AddTokenHeader(r *http.Request) {
	tok := strings.TrimSpace(os.Getenv(EnvVar))
	if tok != "" {
		r.Header.Set(HeaderName, tok)
	}
}

// writeJSONErr emits a tiny JSON error body. We deliberately avoid the
// per-service writeErr helpers so this package has no service-specific
// dependencies and can be imported from any side of the call.
func writeJSONErr(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Hand-written JSON to keep the dependency footprint zero; the
	// payload is small and trusted (no caller-controlled fields).
	_, _ = w.Write([]byte(`{"error":{"code":"` + code + `","message":"` + message + `"}}`))
}
