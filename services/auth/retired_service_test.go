package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
)

// A removed service's identity doesn't outlive it: its API keys are deleted
// and its registration revoked at startup, audited once; a restart with
// nothing left to revoke emits nothing.
func TestBootstrapRetiresRemovedServiceIdentities(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	if err := store.CreateClientRegistration(ctx, ClientRegistration{
		ID: "kms-payment", TenantID: "root", ClientName: "kms-payment", ClientType: "service",
		InterfaceName: "rest", SubjectID: "kms-payment", RequestedRole: "service", Status: "approved", AuthMode: "api_key",
	}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("old kms-payment key"))
	if err := store.CreateAPIKey(ctx, APIKey{ID: NewID("akey"), TenantID: "root", ClientID: "kms-payment", KeyHash: sum[:],
		Name: "kms-payment service identity", Permissions: []string{"service.internal"}}); err != nil {
		t.Fatal(err)
	}

	audit := &captureAuthAudit{}
	retireRemovedServiceClients(ctx, store, "root", quietLogger(), audit)
	if _, err := store.GetAPIKeyByHash(ctx, "root", sum[:]); !errors.Is(err, errNotFound) {
		t.Fatalf("removed service's key survived: %v", err)
	}
	if reg, err := store.GetClientRegistration(ctx, "root", "kms-payment"); err != nil || reg.Status != "revoked" {
		t.Fatalf("registration not revoked: %+v %v", reg, err)
	}
	if audit.count("audit.auth.service_identity_retired") != 1 {
		t.Fatalf("retirement not audited once: %v", audit.subjects)
	}

	again := &captureAuthAudit{}
	retireRemovedServiceClients(ctx, store, "root", quietLogger(), again)
	if len(again.subjects) != 0 {
		t.Fatalf("a restart with nothing to revoke emitted %v", again.subjects)
	}
}
