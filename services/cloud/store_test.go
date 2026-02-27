package main

import (
	"context"
	"errors"
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

func TestStoreDeleteAccountCascade(t *testing.T) {
	_, store, _, _ := newCloudService(t)
	ctx := context.Background()
	now := time.Now().UTC()

	account := CloudAccount{
		ID:                      "ca-del-1",
		TenantID:                "tenant-del-1",
		Provider:                ProviderAWS,
		Name:                    "aws-del",
		DefaultRegion:           "us-east-1",
		Status:                  "configured",
		CredentialsWrappedDEK:   []byte("dek"),
		CredentialsWrappedDEKIV: []byte("dekiv"),
		CredentialsCiphertext:   []byte("cipher"),
		CredentialsDataIV:       []byte("iv"),
	}
	if err := store.CreateAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	if err := store.SetRegionMapping(ctx, RegionMapping{
		TenantID:    "tenant-del-1",
		Provider:    ProviderAWS,
		VectaRegion: "vecta-us-east",
		CloudRegion: "us-east-1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateBinding(ctx, CloudKeyBinding{
		ID:           "bind-del-1",
		TenantID:     "tenant-del-1",
		KeyID:        "key-1",
		Provider:     ProviderAWS,
		AccountID:    "ca-del-1",
		CloudKeyID:   "aws-key-1",
		CloudKeyRef:  "arn:aws:kms:us-east-1:111111111111:key/abc",
		Region:       "us-east-1",
		SyncStatus:   "synced",
		LastSyncedAt: now,
		MetadataJSON: "{}",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSyncJob(ctx, SyncJob{
		ID:        "job-del-1",
		TenantID:  "tenant-del-1",
		Provider:  ProviderAWS,
		AccountID: "ca-del-1",
		Mode:      "full",
		Status:    "completed",
		StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	out, err := store.DeleteAccountCascade(ctx, "tenant-del-1", "ca-del-1")
	if err != nil {
		t.Fatal(err)
	}
	if out.DeletedBindings != 1 || out.DeletedSyncJobs != 1 {
		t.Fatalf("unexpected delete result: %+v", out)
	}
	if out.DeletedRegionMappings != 1 {
		t.Fatalf("expected provider mappings cleanup when last account removed: %+v", out)
	}
	if _, err := store.GetAccount(ctx, "tenant-del-1", "ca-del-1"); !errors.Is(err, errNotFound) {
		t.Fatalf("expected account to be deleted, got err=%v", err)
	}
	bindings, err := store.ListBindings(ctx, "tenant-del-1", ProviderAWS, "ca-del-1", "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 0 {
		t.Fatalf("expected no bindings after delete, got %d", len(bindings))
	}
}
