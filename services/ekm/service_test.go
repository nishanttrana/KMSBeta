package main

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestServiceRegisterAgentAutoProvisionAndHeartbeat(t *testing.T) {
	svc, store, _, pub := newEKMService(t)
	ctx := context.Background()

	agent, key, err := svc.RegisterAgent(ctx, RegisterAgentRequest{
		TenantID: "tenant-a",
		AgentID:  "agent-sql-1",
		Name:     "sql-agent-a",
		DBEngine: "mssql",
	}, "tenant-a:ekm-agent")
	if err != nil {
		t.Fatal(err)
	}
	if key == nil || key.ID == "" {
		t.Fatalf("expected auto provisioned key on SQL Server agent registration")
	}
	if agent.AssignedKeyID == "" {
		t.Fatalf("expected assigned key on agent: %+v", agent)
	}
	if pub.Count("audit.ekm.agent_registered") == 0 {
		t.Fatalf("expected agent_registered audit event")
	}
	if pub.Count("audit.ekm.tde_key_provisioned") == 0 {
		t.Fatalf("expected tde_key_provisioned audit event")
	}

	if _, err := svc.AgentHeartbeat(ctx, "agent-sql-1", AgentHeartbeatRequest{
		TenantID:         "tenant-a",
		Status:           "connected",
		TDEState:         "enabled",
		ActiveKeyID:      agent.AssignedKeyID,
		ActiveKeyVersion: agent.AssignedKeyVersion,
		ConfigVersionAck: 1,
	}, "tenant-a:ekm-agent"); err != nil {
		t.Fatal(err)
	}
	if pub.Count("audit.ekm.agent_heartbeat") == 0 {
		t.Fatalf("expected agent_heartbeat audit event")
	}

	stale, err := store.GetAgent(ctx, "tenant-a", "agent-sql-1")
	if err != nil {
		t.Fatal(err)
	}
	stale.Status = AgentStatusConnected
	stale.LastHeartbeatAt = time.Now().UTC().Add(-20 * time.Minute)
	if err := store.UpsertAgent(ctx, stale); err != nil {
		t.Fatal(err)
	}
	status, err := svc.GetAgentStatus(ctx, "tenant-a", "agent-sql-1")
	if err != nil {
		t.Fatal(err)
	}
	if status.Agent.Status != AgentStatusDisconnected {
		t.Fatalf("expected disconnected agent status, got %+v", status.Agent)
	}
	if pub.Count("audit.ekm.agent_disconnected") == 0 {
		t.Fatalf("expected agent_disconnected audit event")
	}
}

func TestServiceDatabaseAndWrapRotateFlow(t *testing.T) {
	svc, _, _, pub := newEKMService(t)
	ctx := context.Background()

	agent, _, err := svc.RegisterAgent(ctx, RegisterAgentRequest{
		TenantID: "tenant-b",
		AgentID:  "agent-sql-2",
		DBEngine: "mssql",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	dbi, key, err := svc.RegisterDatabase(ctx, RegisterDatabaseRequest{
		TenantID:     "tenant-b",
		DatabaseID:   "db-finance-1",
		AgentID:      agent.ID,
		Name:         "finance-db",
		Engine:       "mssql",
		TDEEnabled:   true,
		DatabaseName: "FinanceDB",
	})
	if err != nil {
		t.Fatal(err)
	}
	if dbi.KeyID == "" || key == nil || key.ID == "" {
		t.Fatalf("expected database auto-provisioned key: db=%+v key=%+v", dbi, key)
	}

	plainB64 := base64.StdEncoding.EncodeToString([]byte("0123456789ABCDEF0123456789ABCDEF"))
	wrapOut, err := svc.WrapDEK(ctx, dbi.KeyID, WrapDEKRequest{
		TenantID:     "tenant-b",
		PlaintextB64: plainB64,
		DatabaseID:   dbi.ID,
		AgentID:      agent.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if wrapOut.CiphertextB64 == "" {
		t.Fatalf("expected wrapped ciphertext")
	}

	unwrapOut, err := svc.UnwrapDEK(ctx, dbi.KeyID, UnwrapDEKRequest{
		TenantID:      "tenant-b",
		CiphertextB64: wrapOut.CiphertextB64,
		IVB64:         wrapOut.IVB64,
		DatabaseID:    dbi.ID,
		AgentID:       agent.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if unwrapOut.PlaintextB64 != plainB64 {
		t.Fatalf("unexpected unwrap plaintext: got=%s want=%s", unwrapOut.PlaintextB64, plainB64)
	}

	rot, err := svc.RotateTDEKey(ctx, dbi.KeyID, RotateTDEKeyRequest{
		TenantID: "tenant-b",
		Reason:   "scheduled",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rot.VersionID == "" {
		t.Fatalf("expected rotation version id")
	}
	if len(rot.AffectedAgentIDs) == 0 {
		t.Fatalf("expected at least one affected agent")
	}
	if pub.Count("audit.ekm.tde_key_rotated") == 0 {
		t.Fatalf("expected tde_key_rotated audit event")
	}
	if pub.Count("audit.ekm.agent_config_updated") == 0 {
		t.Fatalf("expected agent_config_updated audit event")
	}
	if pub.Count("audit.ekm.tde_key_accessed") == 0 {
		t.Fatalf("expected tde_key_accessed events")
	}

	health, err := svc.GetAgentHealth(ctx, "tenant-b", agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if health.Agent.ID != agent.ID {
		t.Fatalf("unexpected health payload: %+v", health)
	}

	logs, err := svc.ListAgentLogs(ctx, "tenant-b", agent.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 {
		t.Fatalf("expected agent logs after wrap/unwrap")
	}

	rotByAgent, err := svc.RotateAgentAssignedKey(ctx, "tenant-b", agent.ID, "manual")
	if err != nil {
		t.Fatal(err)
	}
	if rotByAgent.KeyID == "" || rotByAgent.VersionID == "" {
		t.Fatalf("unexpected agent rotate response: %+v", rotByAgent)
	}

	deployPkg, err := svc.BuildAgentDeployPackage(ctx, "tenant-b", agent.ID, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if deployPkg.TargetOS != "linux" || len(deployPkg.Files) < 3 {
		t.Fatalf("unexpected deploy package: %+v", deployPkg)
	}
	linuxFiles := map[string]bool{}
	for _, file := range deployPkg.Files {
		linuxFiles[file.Path] = true
	}
	if !linuxFiles["heartbeat.sh"] || !linuxFiles["install.sh"] {
		t.Fatalf("linux package should include linux scripts: %+v", deployPkg.Files)
	}
	if linuxFiles["heartbeat.ps1"] || linuxFiles["install.ps1"] {
		t.Fatalf("linux package must not include windows scripts: %+v", deployPkg.Files)
	}

	winPkg, err := svc.BuildAgentDeployPackage(ctx, "tenant-b", agent.ID, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if winPkg.TargetOS != "windows" || len(winPkg.Files) < 3 {
		t.Fatalf("unexpected windows deploy package: %+v", winPkg)
	}
	winFiles := map[string]bool{}
	for _, file := range winPkg.Files {
		winFiles[file.Path] = true
	}
	if !winFiles["heartbeat.ps1"] || !winFiles["install.ps1"] {
		t.Fatalf("windows package should include windows scripts: %+v", winPkg.Files)
	}
	if winFiles["heartbeat.sh"] || winFiles["install.sh"] {
		t.Fatalf("windows package must not include linux scripts: %+v", winPkg.Files)
	}
}

func TestServiceDeleteAgentCascadeAndAudit(t *testing.T) {
	svc, store, keycore, pub := newEKMService(t)
	ctx := context.Background()

	agent, _, err := svc.RegisterAgent(ctx, RegisterAgentRequest{
		TenantID: "tenant-del",
		AgentID:  "agent-del-1",
		Name:     "delete-me",
		DBEngine: "mssql",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	dbi, _, err := svc.RegisterDatabase(ctx, RegisterDatabaseRequest{
		TenantID:     "tenant-del",
		DatabaseID:   "db-del-1",
		AgentID:      agent.ID,
		Name:         "db-delete-me",
		Engine:       "mssql",
		TDEEnabled:   true,
		DatabaseName: "DeleteDB",
	})
	if err != nil {
		t.Fatal(err)
	}
	plainB64 := base64.StdEncoding.EncodeToString([]byte("0123456789ABCDEF0123456789ABCDEF"))
	if _, err := svc.WrapDEK(ctx, dbi.KeyID, WrapDEKRequest{
		TenantID:     "tenant-del",
		PlaintextB64: plainB64,
		DatabaseID:   dbi.ID,
		AgentID:      agent.ID,
	}); err != nil {
		t.Fatal(err)
	}

	out, err := svc.DeleteAgent(ctx, "tenant-del", agent.ID, "test-cleanup")
	if err != nil {
		t.Fatal(err)
	}
	if out.AgentID != agent.ID {
		t.Fatalf("unexpected delete response: %+v", out)
	}
	if out.DeletedDatabase < 1 {
		t.Fatalf("expected deleted databases count > 0, got %+v", out)
	}
	if out.DeletedKeys < 1 {
		t.Fatalf("expected deleted keys count > 0, got %+v", out)
	}
	if out.DeletedLogs < 1 {
		t.Fatalf("expected deleted logs count > 0, got %+v", out)
	}

	_, err = store.GetAgent(ctx, "tenant-del", agent.ID)
	if !errors.Is(err, errNotFound) {
		t.Fatalf("expected agent not found after delete, got err=%v", err)
	}
	dbItems, err := store.ListDatabases(ctx, "tenant-del", agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(dbItems) != 0 {
		t.Fatalf("expected no database rows after delete, got=%d", len(dbItems))
	}
	for _, keyID := range out.DeletedKeyIDs {
		if _, err := store.GetTDEKey(ctx, "tenant-del", keyID); !errors.Is(err, errNotFound) {
			t.Fatalf("expected key record deleted for %s, got err=%v", keyID, err)
		}
		if _, err := keycore.GetKey(ctx, "tenant-del", keyID); err == nil {
			t.Fatalf("expected keycore key deleted for %s", keyID)
		}
	}
	if pub.Count("audit.ekm.tde_key_deleted") == 0 {
		t.Fatalf("expected tde_key_deleted audit event")
	}
	if pub.Count("audit.ekm.database_deleted") == 0 {
		t.Fatalf("expected database_deleted audit event")
	}
	if pub.Count("audit.ekm.agent_deleted") == 0 {
		t.Fatalf("expected agent_deleted audit event")
	}
}
