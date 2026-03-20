package main

import "testing"

func TestAuditEventCatalogHasRequiredCoverage(t *testing.T) {
	if got := len(auditEventCatalog); got < 250 {
		t.Fatalf("expected at least 250 event types, got %d", got)
	}
}

func TestAuditEventCatalogClassification(t *testing.T) {
	if sev := classifySeverity("audit.key.destroyed", "success"); sev != "CRITICAL" {
		t.Fatalf("unexpected severity for key.destroyed: %s", sev)
	}
	if sev := classifySeverity("audit.auth.login_failed", "failure"); sev != "HIGH" {
		t.Fatalf("unexpected severity for auth.login_failed: %s", sev)
	}
	if sev := classifySeverity("audit.auth.mtls_binding_failed", "failure"); sev != "HIGH" {
		t.Fatalf("unexpected severity for auth.mtls_binding_failed: %s", sev)
	}
	if sev := classifySeverity("audit.auth.rest_client_security_viewed", "success"); sev != "LOW" {
		t.Fatalf("unexpected severity for auth.rest_client_security_viewed: %s", sev)
	}
	if cat := classifyCategory("audit.key.encrypt"); cat != "key" {
		t.Fatalf("unexpected category for key.encrypt: %s", cat)
	}
	if sev := classifySeverity("audit.key.request_replay_detected", "failure"); sev != "HIGH" {
		t.Fatalf("unexpected severity for key.request_replay_detected: %s", sev)
	}
	if sev := classifySeverity("audit.key.rest_unsigned_blocked", "failure"); sev != "MEDIUM" {
		t.Fatalf("unexpected severity for key.rest_unsigned_blocked: %s", sev)
	}
	if sev := classifySeverity("audit.payment.ap2_profile_updated", "success"); sev != "MEDIUM" {
		t.Fatalf("unexpected severity for payment.ap2_profile_updated: %s", sev)
	}
	if sev := classifySeverity("audit.payment.policy_updated", "success"); sev != "MEDIUM" {
		t.Fatalf("unexpected severity for payment.policy_updated: %s", sev)
	}
	if sev := classifySeverity("audit.payment.ap2_evaluated", "success"); sev != "LOW" {
		t.Fatalf("unexpected severity for payment.ap2_evaluated: %s", sev)
	}
	if cat := classifyCategory("audit.payment.ap2_evaluated"); cat != "payment" {
		t.Fatalf("unexpected category for payment.ap2_evaluated: %s", cat)
	}
	if sev := classifySeverity("audit.autokey.service_policy_upserted", "success"); sev != "MEDIUM" {
		t.Fatalf("unexpected severity for autokey.service_policy_upserted: %s", sev)
	}
	if sev := classifySeverity("audit.autokey.request_provisioned", "success"); sev != "HIGH" {
		t.Fatalf("unexpected severity for autokey.request_provisioned: %s", sev)
	}
	if sev := classifySeverity("audit.autokey.summary_viewed", "success"); sev != "LOW" {
		t.Fatalf("unexpected severity for autokey.summary_viewed: %s", sev)
	}
	if cat := classifyCategory("audit.autokey.request_pending_approval"); cat != "autokey" {
		t.Fatalf("unexpected category for autokey.request_pending_approval: %s", cat)
	}
	if sev := classifySeverity("audit.confidential.policy_updated", "success"); sev != "MEDIUM" {
		t.Fatalf("unexpected severity for confidential.policy_updated: %s", sev)
	}
	if sev := classifySeverity("audit.confidential.key_release_evaluated", "success"); sev != "HIGH" {
		t.Fatalf("unexpected severity for confidential.key_release_evaluated: %s", sev)
	}
	if cat := classifyCategory("audit.confidential.key_release_evaluated"); cat != "confidential" {
		t.Fatalf("unexpected category for confidential.key_release_evaluated: %s", cat)
	}
	if sev := classifySeverity("audit.pqc.policy_updated", "success"); sev != "MEDIUM" {
		t.Fatalf("unexpected severity for pqc.policy_updated: %s", sev)
	}
	if sev := classifySeverity("audit.pqc.inventory_viewed", "success"); sev != "LOW" {
		t.Fatalf("unexpected severity for pqc.inventory_viewed: %s", sev)
	}
	if cat := classifyCategory("audit.pqc.migration_report_viewed"); cat != "pqc" {
		t.Fatalf("unexpected category for pqc.migration_report_viewed: %s", cat)
	}
	if sev := classifySeverity("audit.workload.svid_issued", "success"); sev != "HIGH" {
		t.Fatalf("unexpected severity for workload.svid_issued: %s", sev)
	}
	if sev := classifySeverity("audit.workload.settings_updated", "success"); sev != "MEDIUM" {
		t.Fatalf("unexpected severity for workload.settings_updated: %s", sev)
	}
	if sev := classifySeverity("audit.workload.registrations_viewed", "success"); sev != "LOW" {
		t.Fatalf("unexpected severity for workload.registrations_viewed: %s", sev)
	}
	if sev := classifySeverity("audit.workload.issuance_history_viewed", "success"); sev != "LOW" {
		t.Fatalf("unexpected severity for workload.issuance_history_viewed: %s", sev)
	}
	if cat := classifyCategory("audit.workload.token_exchanged"); cat != "workload" {
		t.Fatalf("unexpected category for workload.token_exchanged: %s", cat)
	}
}
