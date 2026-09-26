package main

import (
	"context"
	"testing"

	"vecta-kms/pkg/mek/mektest"
)

// A BitLocker recovery key escrowed by an earlier release under the public
// dev key is re-wrapped under the keycore master key and listed as exposed
// until a rotation escrows a new key for the volume.
func TestUpgradeMovesRecoveryKeysOffPublicKey(t *testing.T) {
	ctx := context.Background()
	_, store, keycore, pub := newEKMService(t)
	old := NewService(store, keycore, pub, mektest.PublicDevKey("ekm"))
	escrow := func(svc *Service, op, key string) {
		t.Helper()
		job, err := svc.QueueBitLockerOperation(ctx, "c1", BitLockerOperationRequest{TenantID: "t1", Operation: op, RequestedBy: "admin"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.SubmitBitLockerJobResult(ctx, "c1", job.ID, BitLockerJobResultRequest{
			TenantID: "t1", Status: "succeeded", RecoveryKey: key, VolumeMountPoint: "C:",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := old.RegisterBitLockerClient(ctx, RegisterBitLockerClientRequest{TenantID: "t1", ClientID: "c1", Name: "laptop", Host: "h1"}, "", ""); err != nil {
		t.Fatal(err)
	}
	escrow(old, "enable", "111111-222222-333333-444444-555555-666666-777777-888888")

	mektest.ApplySchema(t, store.db.SQL(), "ekm")
	k := mektest.Open(t, store.db.SQL(), "ekm", mektest.NewKeycore(t))
	svc := NewService(store, keycore, pub, k.Current())
	svc.SetKeyring(k)

	rec, err := store.GetLatestBitLockerRecoveryKey(ctx, "t1", "c1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decryptBitLockerRecoveryRecord(k.Current(), rec); err != nil || got == "" {
		t.Fatalf("recovery key after upgrade: %q %v", got, err)
	}
	if _, err := decryptBitLockerRecoveryRecord(mektest.PublicDevKey("ekm"), rec); err == nil {
		t.Fatal("the public dev key still opens a recovery key")
	}
	if open, _ := k.Exposures(ctx, "t1", true); len(open) != 1 || open[0].ItemID != rec.ID {
		t.Fatalf("exposure register: %+v", open)
	}
	escrow(svc, "rotate", "999999-888888-777777-666666-555555-444444-333333-222222")
	if open, _ := k.Exposures(ctx, "t1", true); len(open) != 0 {
		t.Fatalf("still exposed after rotation: %+v", open)
	}
}
