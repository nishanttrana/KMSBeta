// Package tenantcheck provides helpers to validate that a tenant_id from an
// HTTP request (query param, header, or body) matches the tenant_id from the
// caller's JWT claims.  This prevents IDOR / broken access control where a
// caller supplies another tenant's ID.
package tenantcheck

import (
	"errors"
	"net/http"
	"os"
	"strings"

	pkgauth "vecta-kms/pkg/auth"
)

// ErrTenantMismatch is returned when the request tenant does not match the
// JWT claim tenant.
var ErrTenantMismatch = errors.New("tenant_id in request does not match authenticated tenant")

// ServicePermission is the permission carried by internal service-to-service
// JWTs (minted per service via pkg/servicetoken). A token holding it is a
// trusted internal principal that operates tenant-wide — it acts on behalf of
// whatever tenant the request specifies, so the tenant match is not enforced.
const ServicePermission = "service.internal"

// ServicePermissionReserved reports whether perm is the reserved internal
// service permission. It may only be minted by the auth service's bootstrap
// for kms-* service identities — never granted through an API (API keys,
// tenant roles, client-token scope requests).
func ServicePermissionReserved(perm string) bool {
	return strings.EqualFold(strings.TrimSpace(perm), ServicePermission)
}

// StripReserved returns perms without the reserved service permission.
func StripReserved(perms []string) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		if ServicePermissionReserved(p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// InternalServiceTenant is the tenant under which per-service identities are
// provisioned (INTERNAL_SERVICE_TENANT, default "root").
func InternalServiceTenant() string {
	if v := strings.TrimSpace(os.Getenv("INTERNAL_SERVICE_TENANT")); v != "" {
		return v
	}
	return "root"
}

// IsServicePrincipal reports whether the claims belong to an internal service
// identity. ALL of the following must hold (role alone is NOT sufficient —
// every external client-credentials JWT also carries role "client-service"):
//   - role "client-service" (issued by /auth/client-token)
//   - the reserved "service.internal" permission (only bootstrap grants it)
//   - client_id with the "kms-" service prefix
//   - tenant equal to the internal service tenant
func IsServicePrincipal(claims *pkgauth.Claims) bool {
	if claims == nil {
		return false
	}
	return IsServiceIdentity(claims.Role, claims.ClientID, claims.TenantID, claims.Permissions)
}

// IsServiceIdentity is the claim-field form of IsServicePrincipal, for callers
// that carry the fields in their own actor struct.
func IsServiceIdentity(role, clientID, tenantID string, permissions []string) bool {
	if !strings.EqualFold(strings.TrimSpace(role), "client-service") {
		return false
	}
	if !strings.HasPrefix(strings.TrimSpace(clientID), "kms-") {
		return false
	}
	if strings.TrimSpace(tenantID) != InternalServiceTenant() {
		return false
	}
	for _, p := range permissions {
		if ServicePermissionReserved(p) {
			return true
		}
	}
	return false
}

// Enforce compares the tenant_id from the HTTP request (query param or
// X-Tenant-ID header) against the tenant_id embedded in the JWT claims stored
// in the request context.  If the caller is authenticated and the request
// specifies a different tenant, it returns ErrTenantMismatch.
//
// If no JWT claims are in context (unauthenticated endpoint) or if the claim
// tenant is empty (super-admin / root token), the check is skipped.
func Enforce(r *http.Request, requestTenantID string) error {
	claims, ok := pkgauth.ClaimsFromContext(r.Context())
	if !ok || claims == nil {
		return nil // no auth context — skip
	}
	claimTenant := strings.TrimSpace(claims.TenantID)
	if claimTenant == "" {
		return nil // root / super-admin tokens have no tenant restriction
	}
	if IsServicePrincipal(claims) {
		return nil // internal service identity — trusted tenant-wide, acts for the request tenant
	}
	requestTenantID = strings.TrimSpace(requestTenantID)
	if requestTenantID == "" {
		return nil // no tenant specified in request
	}
	if !strings.EqualFold(claimTenant, requestTenantID) {
		return ErrTenantMismatch
	}
	return nil
}
