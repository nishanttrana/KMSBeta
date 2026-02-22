package main

import (
	"context"
	"testing"
	"time"
)

func TestStoreAgentRoundTrip(t *testing.T) {
	_, store, _, _ := newEKMService(t)
	ctx := context.Background()
	now := time.Now().UTC()
	agent := Agent{
		ID:                   "agent-1",
		TenantID:             "tenant-1",
		Name:                 "db-agent",
		Role:                 "ekm-agent",
		DBEngine:             "mssql",
		Host:                 "sql01",
		Version:              "1.0.0",
		Status:               AgentStatusConnected,
		TDEState:             "enabled",
		HeartbeatIntervalSec: 30,
		LastHeartbeatAt:      now,
		AssignedKeyID:        "key-1",
		AssignedKeyVersion:   "v1",
		ConfigVersion:        1,
		ConfigVersionAck:     0,
		MetadataJSON:         `{"env":"prod"}`,
		TLSClientCN:          "tenant-1:ekm-agent",
	}
	if err := store.UpsertAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetAgent(ctx, "tenant-1", "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "db-agent" || got.AssignedKeyID != "key-1" {
		t.Fatalf("unexpected agent: %+v", got)
	}
	items, err := store.ListAgents(ctx, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 agent got %d", len(items))
	}
	if err := store.BumpAgentConfigVersion(ctx, "tenant-1", "agent-1", "key-2", "v2"); err != nil {
		t.Fatal(err)
	}
	updated, err := store.GetAgent(ctx, "tenant-1", "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if updated.ConfigVersion != 2 || updated.AssignedKeyID != "key-2" {
		t.Fatalf("unexpected updated agent: %+v", updated)
	}
}

func TestStoreDatabaseAndKeyRoundTrip(t *testing.T) {
	_, store, _, _ := newEKMService(t)
	ctx := context.Background()
	key := TDEKeyRecord{
		ID:              "tde-1",
		TenantID:        "tenant-2",
		KeyCoreKeyID:    "tde-1",
		Name:            "tde-main",
		Algorithm:       "RSA-3072",
		Status:          "active",
		CurrentVersion:  "v1",
		PublicKey:       "PUBKEY",
		PublicKeyFormat: "opaque",
		CreatedBy:       "test",
	}
	if err := store.CreateTDEKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	dbi := DatabaseInstance{
		ID:           "db-1",
		TenantID:     "tenant-2",
		AgentID:      "agent-2",
		Name:         "database",
		Engine:       "mssql",
		Host:         "sql02",
		Port:         1433,
		DatabaseName: "MainDB",
		TDEEnabled:   true,
		TDEState:     "enabled",
		KeyID:        "tde-1",
		MetadataJSON: `{"team":"payments"}`,
		LastSeenAt:   time.Now().UTC(),
	}
	if err := store.UpsertDatabase(ctx, dbi); err != nil {
		t.Fatal(err)
	}
	gotDB, err := store.GetDatabase(ctx, "tenant-2", "db-1")
	if err != nil {
		t.Fatal(err)
	}
	if gotDB.KeyID != "tde-1" {
		t.Fatalf("unexpected database: %+v", gotDB)
	}
	dbs, err := store.ListDatabasesByKey(ctx, "tenant-2", "tde-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(dbs) != 1 {
		t.Fatalf("expected 1 database bound to key, got %d", len(dbs))
	}
	if err := store.UpdateTDEKeyRotation(ctx, "tenant-2", "tde-1", "v2", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	gotKey, err := store.GetTDEKey(ctx, "tenant-2", "tde-1")
	if err != nil {
		t.Fatal(err)
	}
	if gotKey.CurrentVersion != "v2" {
		t.Fatalf("unexpected key version: %+v", gotKey)
	}
	if err := store.RecordKeyAccess(ctx, KeyAccessLog{
		ID:        "acc-1",
		TenantID:  "tenant-2",
		KeyID:     "tde-1",
		AgentID:   "agent-2",
		Operation: "wrap",
		Status:    "success",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	logs, err := store.ListKeyAccessByAgent(ctx, "tenant-2", "agent-2", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || logs[0].Operation != "wrap" {
		t.Fatalf("unexpected logs: %+v", logs)
	}
}
