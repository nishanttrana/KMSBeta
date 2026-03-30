// Package tenantcheck provides helpers to validate that a tenant_id from an
// HTTP request (query param, header, or body) matches the tenant_id from the
// caller's JWT claims.  This prevents IDOR / broken access control where a
// caller supplies another tenant's ID.
package tenantcheck

import (
	"errors"
	"net/http"
	"strings"

	pkgauth "vecta-kms/pkg/auth"
)

// ErrTenantMismatch is returned when the request tenant does not match the
// JWT claim tenant.
var ErrTenantMismatch = errors.New("tenant_id in request does not match authenticated tenant")

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
	requestTenantID = strings.TrimSpace(requestTenantID)
	if requestTenantID == "" {
		return nil // no tenant specified in request
	}
	if !strings.EqualFold(claimTenant, requestTenantID) {
		return ErrTenantMismatch
	}
	return nil
}
