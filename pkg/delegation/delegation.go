// Package delegation lets a service that performs a user's request use a
// key in keycore as that user (docs/SECURITY/KEY_ACCESS_MODEL.md section 5).
//
// The service forwards the user's own verified token and the usage it is
// about to perform (for example fpe-encrypt). Keycore verifies the token
// itself, requires the caller to be a service identity in the same tenant,
// and decides key access for the user and that usage: the user's grants
// apply, not the service's tenant-wide trust. Without it, dataprotect,
// payment and certs used keys as themselves, so any user who could reach
// them could use any key in the tenant.
//
// A request with no user behind it (a scheduled job, an ACME or EST client)
// carries no user token, and Attach adds nothing.
package delegation

import (
	"context"
	"net/http"
	"strings"

	pkgauth "vecta-kms/pkg/auth"
	"vecta-kms/pkg/tenantcheck"
)

const (
	// HeaderToken carries the user's bearer token. It is a credential: it
	// travels only over internal mTLS and is never logged.
	HeaderToken = "X-Vecta-Delegated-Token"
	// HeaderUsage names the usage the service performs with the key.
	HeaderUsage = "X-Vecta-Key-Usage"
)

// Usages a service may perform for a user. Each is a grant operation in
// keycore and has an enforcement point in the service that names it.
var Usages = map[string]bool{
	"encrypt": true, "decrypt": true, "wrap": true, "unwrap": true, "export": true,
	"sign": true, "verify": true, "mac": true,
	"fpe-encrypt": true, "fpe-decrypt": true,
	"tokenize": true, "detokenize": true,
	"translate-wrap": true, "translate-unwrap": true,
	"translate-encrypt": true, "translate-decrypt": true,
	"certificate-sign": true, "crl-sign": true,
}

// Attach forwards ctx's verified user token and usage on req. It adds
// nothing when ctx carries no user (no token, or a service identity's), so
// the call is made as the service itself.
func Attach(ctx context.Context, req *http.Request, usage string) {
	raw, ok := pkgauth.VerifiedTokenFromContext(ctx)
	if !ok {
		return
	}
	claims, ok := pkgauth.ClaimsFromContext(ctx)
	if !ok || claims == nil || tenantcheck.IsServicePrincipal(claims) {
		return
	}
	req.Header.Set(HeaderToken, raw)
	req.Header.Set(HeaderUsage, strings.TrimSpace(usage))
}
