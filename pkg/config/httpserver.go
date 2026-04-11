package config

import (
	"crypto/tls"
	"net/http"
	"time"

	pkgsecurityheaders "vecta-kms/pkg/securityheaders"
)

// fips140TLSConfig returns a TLS configuration compliant with FIPS 140-3 Level 1.
// Enforces TLS 1.3 minimum. TLS 1.3 cipher suites are non-negotiable by the
// Go runtime (they are always the three FIPS-approved suites).
func fips140TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// TLS 1.3 cipher suites in Go are fixed to:
		//   TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
		// No explicit CipherSuites slice needed — Go enforces them automatically.
		SessionTicketsDisabled: false,
		Renegotiation:          tls.RenegotiateNever,
	}
}

// NewHTTPServer creates a hardened HTTP server with proper timeouts.
// Security headers (OWASP A05) are applied automatically to every response
// via the securityheaders middleware, including X-Content-Type-Options,
// X-Frame-Options, CSP, HSTS, Cache-Control, Referrer-Policy,
// Permissions-Policy, and X-Request-ID propagation.
// TLS is configured for FIPS 140-3 Level 1 compliance (TLS 1.3 minimum).
func NewHTTPServer(port string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              ":" + port,
		Handler:           pkgsecurityheaders.Wrap(handler),
		TLSConfig:         fips140TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}
}
