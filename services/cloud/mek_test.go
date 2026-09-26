package main

import (
	"context"
	"testing"

	"vecta-kms/pkg/mek/mektest"
)

// Credentials stored by an earlier release under the public dev key are
// re-wrapped under the keycore master key, listed as exposed, and the entry
// closes when the account is deleted.
func TestUpgradeMovesCloudCredentialsOffPublicKey(t *testing.T) {
	ctx := context.Background()
	_, store, keycore, pub := newCloudService(t)
	old := NewService(store, keycore, newMockProviderRegistry(), pub, mektest.PublicDevKey("cloud"))
	acc, err := old.RegisterAccount(ctx, RegisterCloudAccountRequest{
		TenantID: "t1", Provider: ProviderAWS, Name: "aws", DefaultRegion: "us-east-1",
		CredentialsJSON: `{"access_key":"AKIA","secret":"s3"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	mektest.ApplySchema(t, store.db.SQL(), "cloud")
	k := mektest.Open(t, store.db.SQL(), "cloud", mektest.NewKeycore(t))
	svc := NewService(store, keycore, newMockProviderRegistry(), pub, k.Current())
	svc.SetKeyring(k)

	row, err := store.GetAccount(ctx, "t1", acc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if creds, err := svc.decryptAccountCredentials(row); err != nil || creds["secret"] != "s3" {
		t.Fatalf("credentials after upgrade: %v %v", creds, err)
	}
	if _, err := old.decryptAccountCredentials(row); err == nil {
		t.Fatal("the public dev key still opens stored credentials")
	}
	if open, _ := k.Exposures(ctx, "t1", true); len(open) != 1 || open[0].ItemID != acc.ID {
		t.Fatalf("exposure register: %+v", open)
	}
	if _, err := svc.DeleteAccount(ctx, "t1", acc.ID); err != nil {
		t.Fatal(err)
	}
	if open, _ := k.Exposures(ctx, "t1", true); len(open) != 0 {
		t.Fatalf("still exposed after delete: %+v", open)
	}
}
