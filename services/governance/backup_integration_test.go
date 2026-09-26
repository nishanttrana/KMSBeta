package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/mek"
)

// Backup/restore against real Postgres: the engine reads information_schema
// and restores with TRUNCATE ... CASCADE, which SQLite cannot exercise. Runs
// when VECTA_TEST_POSTGRES_DSN points at a disposable database (CI job
// "integration-postgres"); the database is overwritten.

func newIntegrationGovernance(t *testing.T) (*Service, *capturePublisher) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("VECTA_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set VECTA_TEST_POSTGRES_DSN to a disposable Postgres database to run backup integration tests")
	}
	ctx := context.Background()
	conn, err := pkgdb.Open(ctx, pkgdb.Config{PostgresDSN: dsn, MaxOpen: 4, MaxIdle: 2})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.RunMigrations(ctx, "migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	if _, err := conn.SQL().ExecContext(ctx, `TRUNCATE TABLE approval_policies RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	pub := &capturePublisher{}
	// Other packages' integration tests share this database, so catalogued
	// master-key tables may exist; a pass-through stands in for the services.
	return NewService(NewSQLStore(conn), pub, &mockEmailSender{}, &mockCallbackExecutor{}, "http://localhost:8050",
		WithBackupRewrapper(passThroughRewrapper{})), pub
}

type passThroughRewrapper struct{}

func (passThroughRewrapper) Rewrap(_ context.Context, _ string, req mek.RewrapRequest) ([]mek.RewrapResult, error) {
	out := make([]mek.RewrapResult, len(req.Entries))
	for i, e := range req.Entries {
		out[i] = mek.RewrapResult{IV: e.IV, DEK: e.DEK, Status: "current"}
	}
	return out, nil
}

type backupFiles struct {
	artifactName, artifactB64, keyName, keyB64 string
}

// downloadBackup fetches the two files a customer downloads for a backup.
func downloadBackup(t *testing.T, svc *Service, tenantID, backupID string) backupFiles {
	t.Helper()
	ctx := context.Background()
	art, err := svc.GetBackupArtifactDownload(ctx, tenantID, backupID)
	if err != nil {
		t.Fatalf("artifact download: %v", err)
	}
	key, err := svc.GetBackupKeyDownload(ctx, tenantID, backupID)
	if err != nil {
		t.Fatalf("key download: %v", err)
	}
	keyRaw, err := json.Marshal(key["key_package"])
	if err != nil {
		t.Fatal(err)
	}
	return backupFiles{
		artifactName: art["file_name"].(string), artifactB64: art["content_base64"].(string),
		keyName: key["file_name"].(string), keyB64: base64.StdEncoding.EncodeToString(keyRaw),
	}
}

func (f backupFiles) restore(svc *Service, tenantID string) (RestoreBackupResult, error) {
	return svc.RestoreBackup(context.Background(), RestoreBackupInput{
		TenantID: tenantID, ArtifactFileName: f.artifactName, ArtifactContentBase: f.artifactB64,
		KeyFileName: f.keyName, KeyContentBase: f.keyB64, CreatedBy: "integration-test",
	})
}

// mutateEnvelope decodes the artifact envelope, applies fn, re-encodes it.
func (f backupFiles) mutateEnvelope(t *testing.T, fn func(map[string]interface{})) backupFiles {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(f.artifactB64)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]interface{}{}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	fn(env)
	out, _ := json.Marshal(env)
	f.artifactB64 = base64.StdEncoding.EncodeToString(out)
	return f
}

func policyNames(t *testing.T, svc *Service, tenantID string) map[string]bool {
	t.Helper()
	items, err := svc.ListPolicies(context.Background(), tenantID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, p := range items {
		out[p.Name] = true
	}
	return out
}

func createNamedPolicy(t *testing.T, svc *Service, tenantID, name string) ApprovalPolicy {
	t.Helper()
	p, err := svc.CreatePolicy(context.Background(), ApprovalPolicy{
		TenantID: tenantID, Name: name, Scope: "key_operation", TriggerActions: []string{"key.destroy"},
		RequiredApprovals: 1, TotalApprovers: 1, ApproverRoles: []string{"admin"}, Status: "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A system backup captures real rows, is encrypted, and restores them exactly:
// rows deleted after the backup come back, rows added after it are removed.
func TestBackupRestoreRoundTripPostgres(t *testing.T) {
	svc, pub := newIntegrationGovernance(t)
	ctx := context.Background()
	kept := createNamedPolicy(t, svc, "t-bk", "before-backup")

	noHSM := false
	job, err := svc.CreateBackup(ctx, CreateBackupInput{TenantID: "root", Scope: "system", CreatedBy: "it", BindToHSM: &noHSM})
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != "completed" || job.RowCountTotal == 0 || job.TableCount == 0 || job.EncryptionAlgorithm != "AES-256-GCM" {
		t.Fatalf("backup job must reflect real captured data: %+v", job)
	}
	files := downloadBackup(t, svc, "root", job.ID)

	if err := svc.DeletePolicy(ctx, "t-bk", kept.ID); err != nil {
		t.Fatal(err)
	}
	createNamedPolicy(t, svc, "t-bk", "after-backup")

	res, err := files.restore(svc, "root")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.RowsRestored == 0 || res.TablesProcessed == 0 {
		t.Fatalf("restore must report real work: %+v", res)
	}
	names := policyNames(t, svc, "t-bk")
	if !names["before-backup"] || names["after-backup"] {
		t.Fatalf("restore must return the database to the backup's contents, got %v", names)
	}
	for _, ev := range []string{"audit.governance.backup_created", "audit.governance.backup_restored"} {
		if len(pub.events[ev]) != 1 {
			t.Fatalf("expected one %s audit event, got %d", ev, len(pub.events[ev]))
		}
	}
}

// Integrity: a modified ciphertext, a wrong key, or an envelope whose scope
// was changed (AAD binding) must all be refused without touching data.
func TestBackupRestoreRefusesTamperingPostgres(t *testing.T) {
	svc, pub := newIntegrationGovernance(t)
	ctx := context.Background()
	createNamedPolicy(t, svc, "t-tamper", "original")
	noHSM := false
	job, err := svc.CreateBackup(ctx, CreateBackupInput{TenantID: "root", Scope: "system", CreatedBy: "it", BindToHSM: &noHSM})
	if err != nil {
		t.Fatal(err)
	}
	files := downloadBackup(t, svc, "root", job.ID)
	createNamedPolicy(t, svc, "t-tamper", "sentinel-after-backup")

	flipped := files.mutateEnvelope(t, func(env map[string]interface{}) {
		ct, _ := base64.StdEncoding.DecodeString(env["ciphertext_base64"].(string))
		ct[len(ct)/2] ^= 0x01
		env["ciphertext_base64"] = base64.StdEncoding.EncodeToString(ct)
	})
	rescoped := files.mutateEnvelope(t, func(env map[string]interface{}) {
		env["scope"] = "tenant"
		env["target_tenant_id"] = "t-tamper"
	})
	wrongKey := files
	wrongKey.keyB64 = base64.StdEncoding.EncodeToString([]byte(`{"mode":"software","backup_key_b64":"` +
		base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")) + `"}`))
	wrongName := files
	wrongName.artifactName = "backup.zip"

	for name, f := range map[string]backupFiles{
		"flipped ciphertext bit": flipped, "changed scope (AAD)": rescoped, "wrong key": wrongKey, "wrong file type": wrongName,
	} {
		if _, err := f.restore(svc, "root"); err == nil {
			t.Fatalf("%s: restore must be refused", name)
		}
	}
	if names := policyNames(t, svc, "t-tamper"); !names["sentinel-after-backup"] || !names["original"] {
		t.Fatalf("refused restores must not modify data, got %v", names)
	}
	refused := pub.events["audit.governance.backup_restore_refused"]
	if len(refused) != 4 || len(pub.events["audit.governance.backup_restored"]) != 0 {
		t.Fatalf("every refused restore must be audited (want 4 refusals, 0 restores), got %d / %d",
			len(refused), len(pub.events["audit.governance.backup_restored"]))
	}
	if data, _ := refused[0]["data"].(map[string]interface{}); data["reason"] == "" || data["result"] != "refused" {
		t.Fatalf("refusal audit must carry the reason: %+v", refused[0])
	}
}
