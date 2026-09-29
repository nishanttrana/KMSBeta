package main

import (
	"context"
	"errors"
	"testing"
)

// An operator can't return a compromised key to use: the refusal is
// audited and the key stays compromised. A table-allowed move goes through.
func TestSetKeyStatusEnforcesLifecycleTable(t *testing.T) {
	svc, _, rec := newSystemKeyTestService(t)
	ctx := context.Background()
	key, err := svc.CreateKey(adminCtx(), CreateKeyRequest{TenantID: "t1", Name: "lc", Algorithm: "AES-256", Purpose: "encrypt-decrypt", CreatedBy: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetKeyStatus(ctx, "t1", key.ID, "deactivated"); err != nil {
		t.Fatalf("active to deactivated: %v", err)
	}
	if rec.count("audit.key.deactivated") != 1 {
		t.Fatalf("deactivate not audited: %v", rec.subjects)
	}
	if err := svc.SetKeyStatus(ctx, "t1", key.ID, "compromised"); err != nil {
		t.Fatalf("deactivated to compromised: %v", err)
	}
	for _, to := range []string{"active", "suspended", "disabled", "deactivated"} {
		if err := svc.SetKeyStatus(ctx, "t1", key.ID, to); !errors.Is(err, errKeyTransitionRefused) {
			t.Errorf("compromised to %s: %v, want errKeyTransitionRefused", to, err)
		}
	}
	// POST /keys/{id}/activate (and playbook activate_key) is refused too.
	if _, err := svc.ConfigureKeyActivation(ctx, "t1", key.ID, "immediate", nil); !errors.Is(err, errKeyTransitionRefused) {
		t.Errorf("immediate activation of compromised key: %v", err)
	}
	if n := rec.count("audit.key.status_transition_refused"); n != 5 {
		t.Fatalf("%d refusal events, want 5", n)
	}
	if rec.count("audit.key.activation_updated") != 0 {
		t.Fatal("refused activation audited as audit.key.activation_updated")
	}
	if rec.count("audit.key.active") != 0 {
		t.Fatal("refused activation audited as audit.key.active")
	}
	got, err := svc.GetKey(ctx, "t1", key.ID)
	if err != nil || normalizeLifecycleStatus(got.Status) != StateCompromised {
		t.Fatalf("status after refusals: %q %v", got.Status, err)
	}
}
