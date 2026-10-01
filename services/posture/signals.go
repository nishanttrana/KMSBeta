package main

import "strings"

// The posture signal catalogue: which audit events each signal counts.
//
// Signals match the exact audit subjects the platform emits, not name
// patterns. Many services publish events without a result (the audit service
// defaults it to "success"), so a failure is identified by its subject.
// TestSignalSubjectsAreEmitted fails when a subject listed here is not
// emitted anywhere in the repo, and a signal with no emitter is removed, not
// kept at a permanent zero.
var (
	failedAuthActions = []string{
		"audit.auth.login_failed",
		"audit.auth.mfa_failed",
		"audit.auth.sso_login_refused",
		"audit.auth.client_dpop_failed",
		"audit.auth.client_http_signature_failed",
		"audit.auth.mtls_binding_failed",
	}
	// Key operations the KMS refused or could not perform.
	failedCryptoActions = []string{
		"audit.key.access_refused",
		"audit.key.request_refused",
		"audit.key.crypto_policy_refused",
		"audit.key.derive_refused",
		"audit.key.hsm_refused",
		"audit.signing.sign_refused",
		"audit.hyok.request_denied",
		"audit.ekm.key_access_denied",
		"audit.cloud.key_access_denied",
	}
	keyDeleteActions      = []string{"audit.key.destroyed", "audit.key.version_deleted"}
	certDeleteActions     = []string{"audit.cert.deleted", "audit.cert.ca_deleted"}
	deniedApprovalActions = []string{"audit.governance.vote_denied", "audit.governance.quorum_denied"}
	connectorFailActions  = []string{
		"audit.cloud.sync_failed",
		"audit.ekm.agent_disconnected",
		"audit.ekm.bitlocker_client_disconnected",
		"audit.kmip.authorization_denied",
	}
	expiryActions          = []string{"audit.cert.expiring", "audit.cert.expired"}
	renewalMissedActions   = []string{"audit.cert.renewal_window_missed"}
	emergencyRotateActions = []string{"audit.cert.emergency_rotation_started"}
	massRenewalActions     = []string{"audit.cert.mass_renewal_risk_detected", "audit.cert.star_mass_rollout_risk_detected"}
	nonApprovedAlgoActions = []string{"audit.key.fips.violation_blocked"}
	receiptMissingActions  = []string{"audit.dataprotect.field_encryption.receipt_missing_detected"}
	interopActions         = []string{"audit.kmip.interop_validated"}
)

// Subjects whose events carry a measured duration, and the prefixes that
// place an event in an interface domain.
const (
	hsmActionPrefix       = "audit.hsm."
	byokActionPrefix      = "audit.cloud."
	hyokActionPrefix      = "audit.hyok."
	ekmActionPrefix       = "audit.ekm."
	kmipActionPrefix      = "audit.kmip."
	bitlockerActionPrefix = "audit.ekm.bitlocker_"
	sdkActionPrefix       = "audit.dataprotect.field_encryption."
	// dataprotect names its refusals and failures per operation
	// (audit.dataprotect.<op>_refused, ..._failed).
	dataprotectActionPrefix = "audit.dataprotect."
)

// Error codes posture assigns while normalizing an audit event
// (auditToNormalized), for conditions carried in the event's details.
const (
	codeTenantMismatch = "tenant_mismatch"
	codeNonApproved    = "fips_non_approved_algorithm"
	codeInteropFailed  = "kmip_interop_failed"
)

// refusedResults are a request the platform turned away: "refused" from the
// route kernel, "denied" from older emitters.
const sqlRefused = "result IN ('refused','denied')"

// sqlFailed is an event that records a failure: by result, or by a subject
// that names one.
const sqlFailed = "(result IN ('failure','failed','denied','error','refused')" +
	" OR action LIKE '%failed' OR action LIKE '%refused' OR action LIKE '%denied' OR action LIKE '%disconnected')"

// sqlIn renders "action IN (...)" from catalogue constants (never from input).
func sqlIn(actions []string) string {
	return "action IN ('" + strings.Join(actions, "','") + "')"
}

func sqlPrefix(prefix string) string {
	return "action LIKE '" + strings.ReplaceAll(prefix, "_", `\_`) + `%' ESCAPE '\'`
}

func sqlCount(cond string) string {
	return "COALESCE(SUM(CASE WHEN " + cond + " THEN 1 ELSE 0 END), 0)"
}

// sqlAvgLatency averages measured durations only: an event without one
// stores 0, which is "not measured", not "instant".
func sqlAvgLatency(cond string) string {
	return "COALESCE(AVG(CASE WHEN (" + cond + ") AND latency_ms > 0 THEN latency_ms ELSE NULL END), 0)"
}

// signalSummarySQL selects one SignalSummary, in the order scanSignalSummary
// reads it.
func signalSummarySQL() string {
	domain := func(match string, extraFailure ...string) []string {
		failed := sqlFailed
		for _, f := range extraFailure {
			failed = "(" + failed + " OR " + f + ")"
		}
		return []string{sqlCount(match), sqlCount("(" + match + ") AND " + failed), sqlAvgLatency(match)}
	}
	cols := []string{
		"COUNT(*)",
		sqlCount(sqlIn(failedAuthActions)),
		sqlCount(sqlIn(failedCryptoActions) + " OR (" + sqlPrefix(dataprotectActionPrefix) + " AND (action LIKE '%refused' OR action LIKE '%failed'))"),
		sqlCount(sqlRefused),
		sqlCount(sqlIn(keyDeleteActions)),
		sqlCount(sqlIn(certDeleteActions)),
		sqlCount(sqlIn(deniedApprovalActions)),
		sqlCount("error_code = '" + codeTenantMismatch + "'"),
		sqlCount(sqlIn(connectorFailActions)),
		sqlCount(sqlIn(expiryActions)),
		sqlCount(sqlIn(renewalMissedActions)),
		sqlCount(sqlIn(emergencyRotateActions)),
		sqlCount(sqlIn(massRenewalActions)),
		sqlCount(sqlIn(nonApprovedAlgoActions) + " OR error_code = '" + codeNonApproved + "'"),
		sqlAvgLatency(sqlPrefix(hsmActionPrefix)),
	}
	cols = append(cols, domain("service = 'cloud' OR "+sqlPrefix(byokActionPrefix))...)
	cols = append(cols, domain("service = 'hyok' OR "+sqlPrefix(hyokActionPrefix))...)
	cols = append(cols, domain("service = 'ekm' OR "+sqlPrefix(ekmActionPrefix))...)
	kmip := domain("service = 'kmip' OR "+sqlPrefix(kmipActionPrefix), "error_code = '"+codeInteropFailed+"'")
	cols = append(cols, kmip[0], kmip[1], sqlCount("error_code = '"+codeInteropFailed+"'"), kmip[2])
	cols = append(cols, domain(sqlPrefix(bitlockerActionPrefix))...)
	sdk := domain(sqlPrefix(sdkActionPrefix), sqlIn(receiptMissingActions), "action LIKE '%lease\\_revoked' ESCAPE '\\'")
	cols = append(cols, sdk[0], sdk[1], sqlCount(sqlIn(receiptMissingActions)), sdk[2])
	return "SELECT\n\t" + strings.Join(cols, ",\n\t") + "\nFROM posture_events_history\nWHERE tenant_id = $1\n  AND event_ts >= $2\n  AND event_ts < $3\n"
}

// signalCatalogueSubjects is every literal subject the catalogue names.
func signalCatalogueSubjects() []string {
	var out []string
	for _, l := range [][]string{failedAuthActions, failedCryptoActions, keyDeleteActions, certDeleteActions, deniedApprovalActions,
		connectorFailActions, expiryActions, renewalMissedActions, emergencyRotateActions, massRenewalActions, nonApprovedAlgoActions,
		receiptMissingActions, interopActions} {
		out = append(out, l...)
	}
	return out
}

// signalCataloguePrefixes is every subject prefix the catalogue names.
func signalCataloguePrefixes() []string {
	return []string{hsmActionPrefix, byokActionPrefix, hyokActionPrefix, ekmActionPrefix, kmipActionPrefix, bitlockerActionPrefix, sdkActionPrefix, dataprotectActionPrefix}
}
