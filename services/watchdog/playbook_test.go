package main

import (
	"strings"
	"testing"
)

// The watchdog alerts; it never claims a remediation it did not perform.
func TestIncidentsClaimOnlyAnAlert(t *testing.T) {
	for _, svc := range []string{"keycore", "policy", "audit", "certs"} {
		rec := recommendationFor(ServiceState{Service: svc})
		if rec == "" {
			t.Fatalf("%s: no recommendation", svc)
		}
		for _, claim := range []string{"page-oncall:", "freeze-mutations:", "trigger-reconciler:"} {
			if strings.Contains(rec, claim) {
				t.Fatalf("%s: %q reads as an executed action", svc, rec)
			}
		}
	}
}
