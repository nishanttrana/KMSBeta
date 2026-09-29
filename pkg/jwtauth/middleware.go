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

// PublicRouter is a handler that knows which requests reach a route that
// authenticates without a bearer token (*route.Router satisfies it).
type PublicRouter interface {
	http.Handler
	Public(r *http.Request) bool
}

// MustWrapRouter is MustWrap for a pkg/route router that has Public routes.
// A request without an Authorization header that the router sends to a
// Public route reaches it unauthenticated; the route's handler verifies its
// own credential (for example an SVID) and the kernel audits the call. Every
// other request, and any request that carries a token, needs a valid token.
func MustWrapRouter(prefix, issuer, audience string, rt PublicRouter, logger *log.Logger) http.Handler {
	authed := MustWrap(prefix, issuer, audience, rt, logger)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" && rt.Public(r) {
			rt.ServeHTTP(w, r)
			return
		}
		authed.ServeHTTP(w, r)
	})
}
