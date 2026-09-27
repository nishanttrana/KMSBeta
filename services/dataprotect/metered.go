package main

import (
	"context"
	"errors"
	"net/http"
	"time"

	pkgaudit "vecta-kms/pkg/audit"
)

// meterFailure audits a data-protection operation that did not complete,
// as audit.dataprotect.<op>_refused (permission, policy, preview, limits)
// or audit.dataprotect.<op>_failed, marked as a metered operation for the
// Operations metrics. A completed operation is audited, and metered, by
// its own event (tokenized, fpe_encrypted, …).
func (s *Service) meterFailure(ctx context.Context, op, tenantID string, start time.Time, err error) {
	if err == nil {
		return
	}
	result, reason, severity := "failure", "", "info"
	var se serviceError
	if errors.As(err, &se) {
		reason = se.Code
		if se.Code == "fpe_algorithm_refused" {
			return // refuseFPE already emitted the metered fpe_refused
		}
		switch se.HTTPStatus {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict, http.StatusTooManyRequests:
			result, severity = "refused", "warning"
		}
	}
	subject := "audit.dataprotect." + op + "_failed"
	if result == "refused" {
		subject = "audit.dataprotect." + op + "_refused"
	}
	_ = s.publishAudit(ctx, subject, tenantID, pkgaudit.Metered(map[string]interface{}{
		"result":   result,
		"reason":   reason,
		"error":    err.Error(),
		"severity": severity,
	}, op, start))
}
