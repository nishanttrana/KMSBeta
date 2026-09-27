package main

import (
	"context"
	"crypto"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
)

// signsLocally reports whether a CA signs with a key held by this service.
// An HSM- or keycore-held CA key signs in keycore, which meters it.
func signsLocally(signer crypto.Signer) bool {
	_, inKeycore := signer.(*hsmSigner)
	return !inKeycore
}

// meteredIf marks an issuance or OCSP event as a metered operation when
// this service made the signature itself.
func meteredIf(local bool, details map[string]interface{}, op string, start time.Time) map[string]interface{} {
	if local {
		return pkgaudit.Metered(details, op, start)
	}
	return details
}

// signingFailed audits a signature this service attempted and could not
// make (audit.cert.<op>_failed), metered when the key is local.
func (s *Service) signingFailed(ctx context.Context, local bool, op, tenantID string, start time.Time, err error) {
	_ = s.publishAudit(ctx, "audit.cert."+op+"_failed", tenantID, meteredIf(local, map[string]interface{}{
		"result":   "failure",
		"error":    err.Error(),
		"severity": "warning",
	}, op, start))
}
