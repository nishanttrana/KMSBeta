package main

import (
	"context"
	"testing"
)

func TestServiceImportRotateSyncAndInventory(t *testing.T) {
	svc, _, keycore, pub := newCloudService(t)
	ctx := context.Background()
	keycore.Seed("tenant-1", "key-1", "AES-256")

	account, err := svc.RegisterAccount(ctx, RegisterCloudAccountRequest{
		TenantID:        "tenant-1",
		Provider:        ProviderAWS,
		Name:            "aws-prod",
		DefaultRegion:   "us-east-1",
		CredentialsJSON: `{"access_key":"abc","secret":"xyz"}`,
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

	binding, err := svc.ImportKeyToCloud(ctx, ImportKeyToCloudRequest{
		TenantID:    "tenant-1",
		KeyID:       "key-1",
		AccountID:   account.ID,
		VectaRegion: "vecta-us-east",
	})
	if err != nil {
		t.Fatal(err)
	}
	if binding.Region != "us-east-2" {
		t.Fatalf("expected mapped region us-east-2 got %s", binding.Region)
	}
	if binding.CloudKeyID == "" || binding.CloudKeyRef == "" {
		t.Fatalf("expected cloud binding identifiers: %+v", binding)
	}

	rotated, versionID, err := svc.RotateCloudKey(ctx, RotateCloudKeyRequest{
		TenantID:  "tenant-1",
		BindingID: binding.ID,
		Reason:    "scheduled",
	})
	if err != nil {
		t.Fatal(err)
	}
	if versionID == "" {
		t.Fatalf("expected version id after rotation")
	}
	if rotated.SyncStatus != "synced" {
		t.Fatalf("unexpected rotate result: %+v", rotated)
	}
	if pub.Count("audit.cloud.key_rotated") == 0 {
		t.Fatalf("expected key_rotated event")
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
