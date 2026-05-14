package jwtauth

import (
	"log"
	"net/http"

	pkgauth "vecta-kms/pkg/auth"
)

// MustWrap is the single-call helper services use in main.go to require
// a valid Bearer token on every request. It:
//
//  1. loads the JWT parser via LoadParser(prefix, issuer, audience);
//  2. Fatalf's if the loader returns an error (malformed key);
//  3. Fatalf's if the parser is nil (env vars unset) — fail-closed at
//     startup, never silently disable auth;
//  4. returns the handler wrapped with pkgauth.HTTPMiddleware, which
//     returns 401 for any request that lacks a valid Bearer token.
//
// Logger is the service's standard *log.Logger; calling Fatalf there
// produces the same operational signal as any other startup failure.
func MustWrap(prefix, issuer, audience string, next http.Handler, logger *log.Logger) http.Handler {
	parser, err := LoadParser(Config{Prefix: prefix, Issuer: issuer, Audience: audience})
	if err != nil {
		logger.Fatalf("%s jwt parser init failed: %v", prefix, err)
	}
	if parser == nil {
		logger.Fatalf("%s_JWT_PUBLIC_KEY_PEM (or _B64) is required to start this service", prefix)
	}
	return pkgauth.HTTPMiddleware(next, parser)
}
