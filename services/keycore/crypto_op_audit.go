package main

import (
	"context"
	"errors"
	"strings"
	"time"
)

// cryptoOpName is the operation a key call actually performed: the
// request's own operation (wrap, unwrap, mac, …) or the call's default.
// It names the audit action, so a wrap is never recorded as an encrypt.
func cryptoOpName(requested, fallback string) string {
	op := strings.ToLower(strings.TrimSpace(requested))
	if op == "" {
		op = fallback
	}
	return strings.ReplaceAll(op, "-", "_")
}

// cryptoOpOutcome classifies a key operation's error into the audit
// result and, for a refusal, its reason.
func cryptoOpOutcome(err error) (result, reason string) {
	var (
		approval approvalRequiredError
		denied   policyDeniedError
		fips     fipsModeViolationError
		access   *accessRefusal
		hsm      *hsmRefusal
	)
	switch {
	case err == nil:
		return "success", ""
	case errors.As(err, &approval):
		return "pending_approval", "approval_required"
	case errors.Is(err, errOpsLimit):
		return "refused", "ops_limit_reached"
	case errors.As(err, &denied):
		return "refused", "policy_denied"
	case errors.As(err, &fips):
		return "refused", "fips_mode_violation"
	case errors.As(err, &access):
		return "refused", access.reason
	case errors.As(err, &hsm):
		return "refused", hsm.Reason
	default:
		return "failure", ""
	}
}

// auditCryptoOp emits audit.key.<op> for every key operation — success,
// refusal or failure — with its measured duration. The audit service
// builds the Operations metrics from these events, so every counted
// operation and latency sample is one that actually ran.
func (s *Service) auditCryptoOp(ctx context.Context, op, tenantID, keyID string, start time.Time, err error, extra map[string]any) {
	result, reason := cryptoOpOutcome(err)
	data := map[string]any{
		"key_id":      keyID,
		"operation":   op,
		"result":      result,
		"duration_ms": float64(time.Since(start).Microseconds()) / 1000,
	}
	for k, v := range extra {
		data[k] = v
	}
	if reason != "" {
		data["reason"] = reason
	}
	if result == "refused" {
		data["severity"] = "warning"
	}
	if err != nil {
		data["error"] = err.Error()
	}
	_ = s.publishAudit(ctx, "audit.key."+op, tenantID, data)
}
