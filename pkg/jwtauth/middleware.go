package jwtauth

import (
	"log"
	"net/http"
	"strings"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
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

// PublicRouter is a pkg/route router: it knows which requests reach a
// Public route (*route.Router satisfies it).
type PublicRouter interface {
	http.Handler
	Public(r *http.Request) bool
	Routed(r *http.Request) bool
}

// MustWrapRouter is MustWrap for a service whose every route is on the
// pkg/route kernel. It verifies a bearer token when one is sent, but leaves
// the refusal to the kernel: a request without a token reaches the router
// with no claims, and one with a token that fails verification is marked
// (route.WithInvalidToken). The kernel then refuses it, on Public routes
// too for a bad token, and audits the refusal as audit.<service>.<action>
// with reason unauthenticated or invalid_token. Until 7.10.0-beta this
// middleware answered 401 itself and only the generic request log saw it.
// Never use it for a raw http.ServeMux, which has no kernel to refuse.
func MustWrapRouter(prefix, issuer, audience string, rt PublicRouter, logger *log.Logger) http.Handler {
	parser, err := LoadParser(Config{Prefix: prefix, Issuer: issuer, Audience: audience})
	if err != nil {
		logger.Fatalf("%s jwt parser init failed: %v", prefix, err)
	}
	if parser == nil {
		logger.Fatalf("%s_JWT_PUBLIC_KEY_PEM (or _B64) is required to start this service", prefix)
	}
	return wrapKernel(parser, rt)
}

func wrapKernel(parser func(string) (*pkgauth.Claims, error), rt PublicRouter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
		ctx := r.Context()
		claims, err := parser(raw)
		switch {
		case raw != "" && err == nil:
			ctx = pkgauth.ContextWithVerifiedToken(pkgauth.ContextWithClaims(ctx, claims), raw)
		case !rt.Routed(r):
			// No route, so no action to audit under; don't reveal which
			// paths or methods exist to an unauthenticated caller.
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		case raw != "":
			ctx = route.WithInvalidToken(ctx)
		}
		rt.ServeHTTP(w, r.WithContext(ctx))
	})
}
