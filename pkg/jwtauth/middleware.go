package jwtauth

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/route"
)

// MustWrap is the single-call helper a service still on a raw
// http.ServeMux uses in main.go to require a valid Bearer token on every
// request. It fails closed at startup (Fatalf) when the key is malformed or
// unset, and answers 401 to any request without a valid token. Each refusal
// is audited as audit.<service>.request_refused with reason unauthenticated
// or invalid_token (7.12.0-beta; before, only the generic request log saw
// it). A service on the route kernel uses MustWrapRouter instead, so the
// refusal is audited under the route's own action.
func MustWrap(prefix, issuer, audience string, next http.Handler, audit route.Emitter, logger *log.Logger) http.Handler {
	return wrapLegacy(mustParser(prefix, issuer, audience, logger), next, audit, logger)
}

func mustParser(prefix, issuer, audience string, logger *log.Logger) func(string) (*pkgauth.Claims, error) {
	parser, err := LoadParser(Config{Prefix: prefix, Issuer: issuer, Audience: audience})
	if err != nil {
		logger.Fatalf("%s jwt parser init failed: %v", prefix, err)
	}
	if parser == nil {
		logger.Fatalf("%s_JWT_PUBLIC_KEY_PEM (or _B64) is required to start this service", prefix)
	}
	return parser
}

func wrapLegacy(parser func(string) (*pkgauth.Claims, error), next http.Handler, audit route.Emitter, logger *log.Logger) http.Handler {
	if c, ok := audit.(*pkgaudit.Client); ok && c == nil {
		audit = nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
		reason := route.ReasonUnauthenticated
		if raw != "" {
			if claims, err := parser(raw); err == nil {
				next.ServeHTTP(w, r.WithContext(pkgauth.ContextWithVerifiedToken(pkgauth.ContextWithClaims(r.Context(), claims), raw)))
				return
			}
			reason = route.ReasonInvalidToken
		}
		if audit != nil {
			details := map[string]interface{}{"severity": "warning", "reason": reason}
			if t := strings.TrimSpace(firstNonEmpty(r.URL.Query().Get("tenant_id"), r.Header.Get("X-Tenant-ID"))); t != "" {
				details["requested_tenant"] = t
			}
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
			defer cancel()
			if err := audit.Emit(ctx, "request_refused", pkgaudit.Event{
				Result:        route.ResultRefused,
				StatusCode:    http.StatusUnauthorized,
				ErrorMessage:  "authentication required",
				SourceIP:      sourceIP(r),
				UserAgent:     r.UserAgent(),
				Method:        r.Method,
				Endpoint:      r.URL.Path,
				CorrelationID: firstNonEmpty(r.Header.Get("X-Correlation-ID"), r.Header.Get("X-Request-ID")),
				Details:       details,
			}); err != nil && logger != nil {
				logger.Printf("jwtauth: audit emit request_refused failed: %v", err)
			}
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

func sourceIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		first, _, _ := strings.Cut(fwd, ",")
		return strings.TrimSpace(first)
	}
	return r.RemoteAddr
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
	return wrapKernel(mustParser(prefix, issuer, audience, logger), rt)
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
