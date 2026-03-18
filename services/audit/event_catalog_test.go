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
	if cat := classifyCategory("audit.key.encrypt"); cat != "key" {
		t.Fatalf("unexpected category for key.encrypt: %s", cat)
	}
	if sev := classifySeverity("audit.payment.ap2_profile_updated", "success"); sev != "MEDIUM" {
		t.Fatalf("unexpected severity for payment.ap2_profile_updated: %s", sev)
	}
	if sev := classifySeverity("audit.payment.ap2_evaluated", "success"); sev != "LOW" {
		t.Fatalf("unexpected severity for payment.ap2_evaluated: %s", sev)
	}
	if cat := classifyCategory("audit.payment.ap2_evaluated"); cat != "payment" {
		t.Fatalf("unexpected category for payment.ap2_evaluated: %s", cat)
	}
}
