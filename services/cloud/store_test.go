package main

import (
	"context"
	"testing"
	"time"
)

func TestStoreAccountAndRegionMappingRoundTrip(t *testing.T) {
	_, store, _, _ := newCloudService(t)
	ctx := context.Background()
	account := CloudAccount{
		ID:                      "ca-1",
		TenantID:                "tenant-1",
		Provider:                ProviderAWS,
		Name:                    "aws-main",
		DefaultRegion:           "us-east-1",
		Status:                  "active",
		CredentialsWrappedDEK:   []byte("dek"),
		CredentialsWrappedDEKIV: []byte("dekiv"),
		CredentialsCiphertext:   []byte("cipher"),
		CredentialsDataIV:       []byte("iv"),
	}
	if err := store.CreateAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetAccount(ctx, "tenant-1", "ca-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Provider != ProviderAWS || got.Name != "aws-main" {
		t.Fatalf("unexpected account: %+v", got)
	}
	items, err := store.ListAccounts(ctx, "tenant-1", ProviderAWS)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 account got %d", len(items))
	}

	mapping := RegionMapping{
		TenantID:    "tenant-1",
		Provider:    ProviderAWS,
		VectaRegion: "vecta-us-east",
		CloudRegion: "us-east-2",
	}
	if err := store.SetRegionMapping(ctx, mapping); err != nil {
		t.Fatal(err)
	}
	gotMapping, err := store.GetRegionMapping(ctx, "tenant-1", ProviderAWS, "vecta-us-east")
	if err != nil {
		t.Fatal(err)
	}
	if gotMapping.CloudRegion != "us-east-2" {
		t.Fatalf("unexpected mapping: %+v", gotMapping)
	}
	mappings, err := store.ListRegionMappings(ctx, "tenant-1", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 1 {
		t.Fatalf("expected 1 mapping got %d", len(mappings))
	}
}

func TestStoreBindingAndSyncJobLifecycle(t *testing.T) {
	_, store, _, _ := newCloudService(t)
	ctx := context.Background()
	now := time.Now().UTC()
	binding := CloudKeyBinding{
		ID:           "cbk-1",
		TenantID:     "tenant-2",
		KeyID:        "key-1",
		Provider:     ProviderAzure,
		AccountID:    "acct-1",
		CloudKeyID:   "azure-key-1",
		CloudKeyRef:  "https://acct.vault.azure.net/keys/azure-key-1",
		Region:       "eastus",
		SyncStatus:   "synced",
		LastSyncedAt: now,
		MetadataJSON: `{"env":"prod"}`,
	}
	if err := store.CreateBinding(ctx, binding); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetBinding(ctx, "tenant-2", "cbk-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.CloudKeyID != "azure-key-1" {
		t.Fatalf("unexpected binding: %+v", got)
	}
	items, err := store.ListBindings(ctx, "tenant-2", ProviderAzure, "acct-1", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 binding got %d", len(items))
	}
	got.SyncStatus = "failed"
	got.MetadataJSON = `{"last_error":"forced"}`
	if err := store.UpdateBinding(ctx, got); err != nil {
		t.Fatal(err)
	}
	updated, err := store.GetBinding(ctx, "tenant-2", "cbk-1")
	if err != nil {
		t.Fatal(err)
	}
	if updated.SyncStatus != "failed" {
		t.Fatalf("expected failed sync status got %s", updated.SyncStatus)
	}

	job := SyncJob{
		ID:          "job-1",
		TenantID:    "tenant-2",
		Provider:    ProviderAzure,
		AccountID:   "acct-1",
		Mode:        "full",
		Status:      "running",
		StartedAt:   now,
		SummaryJSON: "{}",
	}
	if err := store.CreateSyncJob(ctx, job); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteSyncJob(ctx, "tenant-2", "job-1", "completed", `{"total":1,"success":1,"failed":0}`, ""); err != nil {
		t.Fatal(err)
	}
	out, err := store.GetSyncJob(ctx, "tenant-2", "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "completed" {
		t.Fatalf("unexpected sync job: %+v", out)
	}
}
