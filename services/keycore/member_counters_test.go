package main

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"vecta-kms/pkg/clusterstate"
)

// asMember makes this process see its node as a cluster member.
func asMember(t *testing.T) {
	t.Helper()
	clusterstate.SetDefault(clusterstate.Static(clusterstate.State{
		NodeID: "node-2", Role: clusterstate.RoleFollower, PrimaryNodeID: "node-1",
		PrimaryURL: "https://primary:8210", ForwardCredential: "cred",
	}))
	t.Cleanup(func() { clusterstate.SetDefault(nil) })
}

// On a member, crypto operations must not write the replicated keys row; they
// count node-locally, and the key's limit still applies.
func TestMemberCountsOperationsNodeLocally(t *testing.T) {
	_, svc := newHandlerForTest(t)
	ctx := context.Background()
	key, err := svc.CreateKey(ctx, CreateKeyRequest{
		TenantID: "t1", Name: "limited", Algorithm: "AES-256", KeyType: "symmetric", Purpose: "encrypt",
		Owner: "ops", CreatedBy: "tester", OpsLimit: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	asMember(t)
	enc := func() error {
		_, err := svc.Encrypt(ctx, key.ID, EncryptRequest{TenantID: "t1", PlaintextB64: base64.StdEncoding.EncodeToString([]byte("x"))})
		return err
	}
	for i := 0; i < 3; i++ {
		if err := enc(); err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
	}
	if err := enc(); !errors.Is(err, errOpsLimit) {
		t.Fatalf("the ops limit must still apply on a member, got %v", err)
	}
	got, err := svc.store.GetKey(ctx, "t1", key.ID)
	if err != nil || got.OpsTotal != 0 {
		t.Fatalf("a member must not write counters into the replicated keys row: ops_total=%d %v", got.OpsTotal, err)
	}
	var local int
	if err := svc.store.(*SQLStore).db.SQL().QueryRow(`SELECT ops_total FROM key_op_counters WHERE tenant_id='t1' AND key_id=?`, key.ID).Scan(&local); err != nil || local != 3 {
		t.Fatalf("member operations must be counted node-locally: %d %v", local, err)
	}
}
