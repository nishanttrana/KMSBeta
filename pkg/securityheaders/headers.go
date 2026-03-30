package securityheaders

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

// Wrap returns middleware that sets security headers on every HTTP response.
// It covers OWASP recommendations for X-Content-Type-Options, X-Frame-Options,
// Content-Security-Policy, Strict-Transport-Security, Cache-Control,
// Referrer-Policy, Permissions-Policy, and X-Request-ID propagation.
func Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'self'")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		h.Set("Cache-Control", "no-store")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		// Propagate or generate X-Request-ID for traceability.
		reqID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if reqID == "" {
			reqID = generateRequestID()
		}
		h.Set("X-Request-ID", reqID)

		next.ServeHTTP(w, r)
	})
}

func generateRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
