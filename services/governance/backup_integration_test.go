package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	pkgdb "vecta-kms/pkg/db"
	"vecta-kms/pkg/hsm"
	"vecta-kms/pkg/hsmconnector/softhsmtest"
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

// takeBackup creates a backup and returns the two files a customer keeps:
// the key file, returned once at creation, and the artifact download.
func takeBackup(t *testing.T, svc *Service, in CreateBackupInput) (BackupJob, backupFiles) {
	t.Helper()
	job, keyFiles, err := svc.CreateBackup(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := keyFiles[0]
	art, err := svc.GetBackupArtifactDownload(context.Background(), in.TenantID, job.ID)
	if err != nil {
		t.Fatalf("artifact download: %v", err)
	}
	return job, backupFiles{
		artifactName: art["file_name"].(string), artifactB64: art["content_base64"].(string),
		keyName: keyFile.FileName, keyB64: keyFile.ContentBase64,
	}
}

func systemBackup() CreateBackupInput {
	noHSM := false
	return CreateBackupInput{TenantID: "root", Scope: "system", CreatedBy: "it", BindToHSM: &noHSM}
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

	job, files := takeBackup(t, svc, systemBackup())
	if job.Status != "completed" || job.RowCountTotal == 0 || job.TableCount == 0 || job.EncryptionAlgorithm != "AES-256-GCM" {
		t.Fatalf("backup job must reflect real captured data: %+v", job)
	}

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
	createNamedPolicy(t, svc, "t-tamper", "original")
	_, files := takeBackup(t, svc, systemBackup())
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

// The platform never stores a software-mode backup key: the row holds only
// its fingerprint, and a key download is refused (410) and audited. The key
// file returned at creation is what restores it.
func TestSoftwareBackupKeyNotRetainedPostgres(t *testing.T) {
	svc, pub := newIntegrationGovernance(t)
	ctx := context.Background()
	createNamedPolicy(t, svc, "t-key", "kept")
	job, files := takeBackup(t, svc, systemBackup())

	keyRaw, _ := base64.StdEncoding.DecodeString(files.keyB64)
	var keyFile map[string]interface{}
	if err := json.Unmarshal(keyRaw, &keyFile); err != nil {
		t.Fatal(err)
	}
	keyB64, _ := keyFile["backup_key_b64"].(string)
	if keyB64 == "" || keyFile["backup_id"] != job.ID {
		t.Fatalf("key file: %s", keyRaw)
	}
	var row string
	db := svc.store.(*SQLStore).db.SQL()
	if err := db.QueryRow(`SELECT key_package_json::text FROM governance_backup_jobs WHERE id=$1`, job.ID).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(row, keyB64) || strings.Contains(row, "backup_key_b64") || !strings.Contains(row, `"key_retained": false`) {
		t.Fatalf("stored package: %s", row)
	}

	if _, err := svc.GetBackupKeyDownload(ctx, "root", job.ID, "admin"); !errors.Is(err, errBackupKeyNotRetained) {
		t.Fatalf("key download: %v, want errBackupKeyNotRetained", err)
	}
	refused := pub.events["audit.governance.backup_key_download_refused"]
	if len(refused) != 1 {
		t.Fatalf("key download refusal not audited: %d", len(refused))
	}
	if data, _ := refused[0]["data"].(map[string]interface{}); data["reason"] != "key_not_retained" || data["result"] != "refused" {
		t.Fatalf("refusal audit: %+v", refused[0])
	}

	if _, err := files.restore(svc, "root"); err != nil {
		t.Fatalf("restore with the key file from creation: %v", err)
	}
}

// Migrations 013 and 014 remove keys stored before: plaintext software keys
// and hsm_bound packages wrapped with a secret-derived key (v1 raw SHA-256,
// v2 HKDF). Packages wrapped by the HSM stay.
func TestMigrationScrubsStoredBackupKeysPostgres(t *testing.T) {
	svc, _ := newIntegrationGovernance(t)
	db := svc.store.(*SQLStore).db.SQL()
	legacy := map[string]string{
		"bkp_legacy_sw":  `{"version":1,"mode":"software","backup_key_b64":"c2VjcmV0","backup_key_sha256":"x"}`,
		"bkp_legacy_hsm": `{"version":1,"mode":"hsm_bound","key_derivation":"v1","wrapped_key_b64":"d3JhcHBlZA==","wrap_nonce_b64":"bg==","wrap_aad_b64":"YQ=="}`,
		"bkp_legacy_v2":  `{"version":2,"mode":"hsm_bound","key_derivation":"v2","key_retained":true,"wrapped_key_b64":"d3JhcHBlZA=="}`,
		"bkp_current":    `{"version":3,"mode":"hsm_bound","key_wrap":"hsm_tenant_key","key_retained":true,"wrapped_key_b64":"d3JhcHBlZA=="}`,
	}
	if _, err := db.Exec(`DELETE FROM governance_backup_jobs WHERE id IN ('bkp_legacy_sw','bkp_legacy_hsm','bkp_legacy_v2','bkp_current')`); err != nil {
		t.Fatal(err)
	}
	insert := func(id string) {
		if _, err := db.Exec(`INSERT INTO governance_backup_jobs (id, tenant_id, scope, status, backup_format, encryption_algorithm,
			ciphertext_sha256, artifact_ciphertext, artifact_nonce, artifact_size_bytes, row_count_total, table_count, hsm_bound, key_package_json)
			VALUES ($1,'root','system','completed','json.gz+aes256gcm','AES-256-GCM','x','\x00','\x00',1,1,1,false,$2::jsonb)`, id, legacy[id]); err != nil {
			t.Fatal(err)
		}
	}
	migrate := func(f string) {
		migration, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(migration)); err != nil {
			t.Fatal(err)
		}
	}
	// In the order they can exist: v1 and v2 packages before 013 ran, and
	// HSM-wrapped ones only after 013 (the release that adds them adds 014).
	insert("bkp_legacy_sw")
	insert("bkp_legacy_hsm")
	insert("bkp_legacy_v2")
	migrate("migrations/013_backup_keys_not_retained.sql")
	insert("bkp_current")
	migrate("migrations/014_backup_keys_hsm_wrapped.sql")
	for id := range legacy {
		var row string
		if err := db.QueryRow(`SELECT key_package_json::text FROM governance_backup_jobs WHERE id=$1`, id).Scan(&row); err != nil {
			t.Fatal(err)
		}
		var pkg map[string]interface{}
		_ = json.Unmarshal([]byte(row), &pkg)
		if id == "bkp_current" {
			if !backupKeyRetained(pkg) {
				t.Fatalf("migration touched an HSM-wrapped package: %s", row)
			}
			continue
		}
		if _, ok := pkg["backup_key_b64"]; ok || pkg["wrapped_key_b64"] != nil || pkg["key_retained"] != false {
			t.Fatalf("%s not scrubbed: %s", id, row)
		}
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM information_schema.columns WHERE table_name='governance_backup_jobs' AND column_name='mek_reprotected_at'`).Scan(&n)
	if n != 0 {
		t.Fatal("mek_reprotected_at not dropped")
	}
}

// An HSM-bound backup end to end on Postgres: the backup key is wrapped by
// the tenant's key in a real PKCS#11 HSM (SoftHSM2), the wrapped key file can
// be downloaded again (audited), and the backup restores only while that
// HSM is reachable.
func TestHSMBoundBackupPostgres(t *testing.T) {
	svc, pub := newIntegrationGovernance(t)
	db := svc.store.(*SQLStore).db.SQL()
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS auth_hsm_provider_configs (
			tenant_id TEXT PRIMARY KEY, provider_name TEXT NOT NULL DEFAULT '', library_path TEXT NOT NULL DEFAULT '',
			slot_id TEXT NOT NULL DEFAULT '', partition_label TEXT NOT NULL DEFAULT '', token_label TEXT NOT NULL DEFAULT '',
			enabled BOOLEAN NOT NULL DEFAULT FALSE)`,
		`DELETE FROM auth_hsm_provider_configs WHERE tenant_id='root'`,
		`INSERT INTO auth_hsm_provider_configs (tenant_id, provider_name, token_label, enabled) VALUES ('root','softhsm2','vecta-test',TRUE)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	srv := softhsmtest.Start(t, "kms-governance", "root")
	svc.hsm = hsm.New(srv.URL)
	createNamedPolicy(t, svc, "t-hsm-bk", "kept")
	bind := true
	job, files := takeBackup(t, svc, CreateBackupInput{TenantID: "root", Scope: "system", CreatedBy: "it", BindToHSM: &bind})
	if !job.HSMBound {
		t.Fatalf("backup not HSM-bound: %+v", job)
	}
	var row string
	if err := db.QueryRow(`SELECT key_package_json::text FROM governance_backup_jobs WHERE id=$1`, job.ID).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(row, `"key_wrap": "hsm_tenant_key"`) || strings.Contains(row, "backup_key_b64") {
		t.Fatalf("stored package: %s", row)
	}
	again, err := svc.GetBackupKeyDownload(context.Background(), "root", job.ID, "admin")
	if err != nil || again.ContentBase64 == "" {
		t.Fatalf("key download: %v", err)
	}
	if len(pub.events["audit.governance.backup_key_downloaded"]) != 1 {
		t.Fatal("key download not audited")
	}
	redownloaded := files
	redownloaded.keyB64 = again.ContentBase64
	if _, err := redownloaded.restore(svc, "root"); err != nil {
		t.Fatalf("restore with the re-downloaded key file: %v", err)
	}
	// Without the HSM the backup can't be opened.
	down := httptest.NewServer(http.NotFoundHandler())
	down.Close()
	svc.hsm = hsm.New(down.URL)
	if _, err := files.restore(svc, "root"); err == nil {
		t.Fatal("an HSM-bound backup restored without the HSM")
	}
}
