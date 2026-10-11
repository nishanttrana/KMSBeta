package main

import (
	"context"
	"testing"
)

func TestServiceImportRotateSyncAndInventory(t *testing.T) {
	svc, _, keycore, pub := newCloudService(t)
	ctx := context.Background()
	keycore.Seed("tenant-1", "key-1", "AES-256")

	account, err := svc.RegisterAccount(attachCtx("tenant-1"), RegisterCloudAccountRequest{
		TenantID:      "tenant-1",
		Provider:      ProviderAWS,
		Name:          "aws-prod",
		DefaultRegion: "us-east-1",
		ConnectionID:  "cred-aws",
	})
	if err != nil {
		t.Fatal(err)
	}
	if account.ID == "" {
		t.Fatalf("expected account id")
	}
	if pub.Count("audit.cloud.connector_configured") == 0 {
		t.Fatalf("expected connector_configured event")
	}

	if _, err := svc.SetRegionMapping(ctx, SetRegionMappingRequest{
		TenantID:    "tenant-1",
		Provider:    ProviderAWS,
		VectaRegion: "vecta-us-east",
		CloudRegion: "us-east-2",
	}); err != nil {
		t.Fatal(err)
	}

	// A key a release before 10.0.0-beta created natively in the cloud: it
	// is listed read-only as cloud-generated, and BYOK operations refuse it.
	legacy := CloudKeyBinding{ID: "cbk_legacy", TenantID: "tenant-1", KeyID: "key-1", Provider: ProviderAWS, AccountID: account.ID,
		CloudKeyID: "1234abcd-legacy", CloudKeyRef: "arn:aws:kms:us-east-2:111122223333:key/1234abcd-legacy", Region: "us-east-2",
		SyncStatus: "synced", MetadataJSON: "{}"}
	if err := svc.store.CreateBinding(ctx, legacy); err != nil {
		t.Fatal(err)
	}
	listed, err := svc.ListBYOK(ctx, "tenant-1")
	if err != nil || len(listed) != 1 || listed[0].Origin != OriginCloudGenerated || listed[0].CloudKeyID != legacy.CloudKeyID {
		t.Fatalf("legacy binding in the BYOK list: %v %+v", err, listed)
	}
	if _, _, err := svc.RunBYOK(ctx, "tenant-1", legacy.ID, OpRotate, "alice", BYOKOperationRequest{}); byokReason(err) != "not_found" {
		t.Fatalf("BYOK rotate of a cloud-generated key: %v", err)
	}

	job, err := svc.SyncCloudKeys(ctx, SyncCloudKeysRequest{
		TenantID:  "tenant-1",
		Provider:  ProviderAWS,
		AccountID: account.ID,
		Mode:      "full",
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != "completed" {
		t.Fatalf("unexpected sync job status: %+v", job)
	}

	items, err := svc.DiscoverInventory(ctx, DiscoverInventoryRequest{
		TenantID:  "tenant-1",
		AccountID: account.ID,
		Provider:  ProviderAWS,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 {
		t.Fatalf("expected inventory items")
	}

	delOut, err := svc.DeleteAccount(ctx, "tenant-1", account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if delOut.AccountID != account.ID || delOut.DeletedBindings < 1 {
		t.Fatalf("unexpected delete connector result: %+v", delOut)
	}
	if pub.Count("audit.cloud.connector_deleted") == 0 {
		t.Fatalf("expected connector_deleted event")
	}
	left, err := svc.ListAccounts(ctx, "tenant-1", ProviderAWS)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("expected connector removed, remaining=%d", len(left))
	}
}

func TestServiceValidation(t *testing.T) {
	svc, _, keycore, _ := newCloudService(t)
	ctx := context.Background()
	keycore.Seed("tenant-2", "key-2", "AES-256")

	if _, err := svc.RegisterAccount(ctx, RegisterCloudAccountRequest{
		TenantID: "tenant-2",
		Provider: "unknown",
		Name:     "bad",
	}); err == nil {
		t.Fatalf("expected unsupported provider error")
	}
	if _, err := svc.ListAccounts(ctx, "tenant-2", "not-a-provider"); err == nil {
		t.Fatalf("expected list validation error")
	}
	if _, err := svc.SyncCloudKeys(ctx, SyncCloudKeysRequest{
		TenantID: "tenant-2",
		Provider: "invalid",
	}); err == nil {
		t.Fatalf("expected sync validation error")
	}
	if _, err := svc.DiscoverInventory(ctx, DiscoverInventoryRequest{
		TenantID: "tenant-2",
		Provider: "invalid",
	}); err == nil {
		t.Fatalf("expected inventory validation error")
	}
}
