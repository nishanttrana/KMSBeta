package main

import (
	"net/http"
	"strings"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/tenantcheck"
)

// Cluster-manager authentication (docs/CLUSTERING.md).
//
// Cluster administration (join tokens, node roles and removal, profiles,
// joining this node to a cluster) is root-administrator only: it decides where
// key material and replicated data go. Node-to-node endpoints authenticate
// differently and stay outside the user JWT check:
//   - POST /cluster/join/exchange: the one-time join token secret;
//   - POST /cluster/sync/events: the X-Cluster-Signature HMAC;
//   - GET /healthz.
// Internal service identities (verified service JWTs) may read and write.

// publicClusterRoutes bypass the user JWT check (each authenticates itself).
var publicClusterRoutes = map[string]bool{
	"GET /healthz":                true,
	"POST /cluster/join/exchange": true,
	"POST /cluster/sync/events":   true,
}

func clusterRouteKey(r *http.Request) string { return r.Method + " " + r.URL.Path }

func claimsAreClusterAdmin(c *pkgauth.Claims) bool {
	if c == nil {
		return false
	}
	if tenantcheck.IsServicePrincipal(c) {
		return true
	}
	tenant := strings.TrimSpace(c.TenantID)
	if tenant != "" && !strings.EqualFold(tenant, "root") {
		return false
	}
	role := strings.ToLower(strings.TrimSpace(c.Role))
	if role == "admin" || role == "super-admin" {
		return true
	}
	for _, p := range c.Permissions {
		if strings.TrimSpace(p) == "*" {
			return true
		}
	}
	return false
}

// requireClusterAdmin runs after the JWT middleware has verified the token.
func requireClusterAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := pkgauth.ClaimsFromContext(r.Context())
		if !ok || !claimsAreClusterAdmin(claims) {
			writeErr(w, http.StatusForbidden, "forbidden", "cluster administration requires a root administrator", requestID(r), "")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// buildClusterHTTPHandler puts every route except the self-authenticating
// node-to-node ones behind JWT verification and the root-admin check.
func buildClusterHTTPHandler(handler http.Handler, parser func(string) (*pkgauth.Claims, error)) http.Handler {
	protected := pkgauth.HTTPMiddleware(requireClusterAdmin(handler), parser)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicClusterRoutes[clusterRouteKey(r)] {
			handler.ServeHTTP(w, r)
			return
		}
		protected.ServeHTTP(w, r)
	})
}
