package main

import (
	"errors"
	"net/http"
	"strings"

	pkgauth "vecta-kms/pkg/auth"
)

// NewAuthenticatedHandler is the handler dataprotect serves. Until 7.2.0-beta
// the service booted with SkipJWT and no route verified a platform token, so
// anyone who reached /svc/dataprotect/ could tokenize, FPE-encrypt or
// decrypt with any key, and delegation (pkg/delegation) never engaged
// because no verified user token was in the context.
//
// Now every request needs a verified platform JWT, except the wrapper runtime
// routes, which a registered field-encryption wrapper calls with its own
// X-Wrapper-Token; the service verifies that token against the wrapper's
// registration (verifyWrapperAuthProfileToken). Every refusal is audited as
// audit.dataprotect.request_refused.
func NewAuthenticatedHandler(svc *Service, parser func(string) (*pkgauth.Claims, error)) (http.Handler, error) {
	if parser == nil {
		return nil, errors.New("dataprotect needs the platform JWT public key to verify callers")
	}
	h := NewHandler(svc)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(r.Header.Get("Authorization"))
		reason := "unauthenticated"
		switch {
		case raw != "":
			token, ok := strings.CutPrefix(raw, "Bearer ")
			if claims, err := parser(strings.TrimSpace(token)); ok && err == nil {
				ctx := pkgauth.ContextWithVerifiedToken(pkgauth.ContextWithClaims(r.Context(), claims), strings.TrimSpace(token))
				h.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			reason = "invalid_token"
		case wrapperAuthenticated(r):
			h.ServeHTTP(w, r)
			return
		}
		_ = svc.publishAudit(r.Context(), "audit.dataprotect.request_refused", tenantFromRequest(r), map[string]interface{}{
			"path":        r.URL.Path,
			"method":      r.Method,
			"result":      "refused",
			"reason":      reason,
			"severity":    "warning",
			"description": "dataprotect requires a verified platform token, or a wrapper token on the wrapper runtime routes",
		})
		writeErr(w, http.StatusUnauthorized, "unauthorized", "authentication required", requestID(r), "")
	}), nil
}

// wrapperAuthenticated reports whether a request without a platform token is
// a wrapper runtime call whose X-Wrapper-Token the service itself verifies.
// Registration (init/complete) is not among them: completing it asserts a
// governance approval, which only an authenticated operator can give.
func wrapperAuthenticated(r *http.Request) bool {
	if wrapperTokenFromRequest(r) == "" {
		return false
	}
	switch {
	case r.Method == http.MethodPost && (r.URL.Path == "/field-encryption/leases" || r.URL.Path == "/field-encryption/receipts"):
		return true
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/field-encryption/leases/") && strings.HasSuffix(r.URL.Path, "/renew"):
		return true
	case r.Method == http.MethodGet && r.URL.Path == "/field-protection/resolve":
		// The token is verified only against a named wrapper.
		id := strings.TrimSpace(r.URL.Query().Get("wrapper_id"))
		return id != "" && id != "*"
	}
	return false
}
