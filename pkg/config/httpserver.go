package config

import (
	"net/http"
	"time"

	pkgsecurityheaders "vecta-kms/pkg/securityheaders"
)

// NewHTTPServer creates a hardened HTTP server with proper timeouts.
// Security headers (OWASP A05) are applied automatically to every response
// via the securityheaders middleware, including X-Content-Type-Options,
// X-Frame-Options, CSP, HSTS, Cache-Control, Referrer-Policy,
// Permissions-Policy, and X-Request-ID propagation.
func NewHTTPServer(port string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              ":" + port,
		Handler:           pkgsecurityheaders.Wrap(handler),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}
}
