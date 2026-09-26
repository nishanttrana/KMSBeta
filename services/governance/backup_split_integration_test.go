package main

import (
	"context"
	"strings"
	"testing"
)

// A split backup end to end on Postgres: five guardian shares, no share and
// no key stored, fewer than three shares or a lone share refused (and
// audited) without touching data, any three restore.
func TestSplitBackupKeyRestorePostgres(t *testing.T) {
	svc, pub := newIntegrationGovernance(t)
	ctx := context.Background()
	createNamedPolicy(t, svc, "t-split", "original")

	in := systemBackup()
	in.KeySplit = &BackupKeySplit{Threshold: 3, Guardians: []string{"CISO", "Legal", "CTO", "Ops", "Notary"}}
	job, shares, err := svc.CreateBackup(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 5 || shares[1].Guardian != "Legal" {
		t.Fatalf("want one share file per guardian: %+v", shares)
	}
	var row string
	if err := svc.store.(*SQLStore).db.SQL().QueryRow(`SELECT key_package_json::text FROM governance_backup_jobs WHERE id=$1`, job.ID).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(row, "share_b64") || strings.Contains(row, "backup_key_b64") || !strings.Contains(row, backupKeyModeSplit) {
		t.Fatalf("stored package must hold neither shares nor key: %s", row)
	}
	splitEv := pub.events["audit.governance.backup_key_split"]
	if len(splitEv) != 1 {
		t.Fatalf("key split not audited: %d", len(splitEv))
	}
	if data, _ := splitEv[0]["data"].(map[string]interface{}); data["threshold"] == nil || data["guardians"] == nil {
		t.Fatalf("split audit must name threshold and guardians: %+v", splitEv[0])
	}

	art, err := svc.GetBackupArtifactDownload(ctx, "root", job.ID)
	if err != nil {
		t.Fatal(err)
	}
	restore := func(keyFile *BackupKeyFile, set ...BackupKeyFile) (RestoreBackupResult, error) {
		r := RestoreBackupInput{TenantID: "root", ArtifactFileName: art["file_name"].(string), ArtifactContentBase: art["content_base64"].(string), KeyShares: set, CreatedBy: "it"}
		if keyFile != nil {
			r.KeyFileName, r.KeyContentBase = keyFile.FileName, keyFile.ContentBase64
		}
		return svc.RestoreBackup(ctx, r)
	}
	createNamedPolicy(t, svc, "t-split", "after-backup")

	if _, err := restore(nil, shares[0], shares[3]); err == nil {
		t.Fatal("two of five shares must not restore")
	}
	if _, err := restore(&shares[2]); err == nil {
		t.Fatal("one guardian's share must not restore on its own")
	}
	if names := policyNames(t, svc, "t-split"); !names["after-backup"] {
		t.Fatalf("refused restores must not modify data: %v", names)
	}
	refused := pub.events["audit.governance.backup_restore_refused"]
	if len(refused) != 2 {
		t.Fatalf("both refusals must be audited, got %d", len(refused))
	}
	if data, _ := refused[0]["data"].(map[string]interface{}); data["result"] != "refused" || !strings.Contains(data["reason"].(string), "needs 3") {
		t.Fatalf("refusal audit must carry the reason: %+v", refused[0])
	}

	if _, err := restore(nil, shares[4], shares[0], shares[2]); err != nil {
		t.Fatalf("three shares must restore: %v", err)
	}
	if names := policyNames(t, svc, "t-split"); !names["original"] || names["after-backup"] {
		t.Fatalf("restore must return the backup's contents: %v", names)
	}
	restored := pub.events["audit.governance.backup_restored"]
	if data, _ := restored[len(restored)-1]["data"].(map[string]interface{}); data["key_source"] != "guardian_shares" {
		t.Fatalf("restore audit must record the guardian shares: %+v", restored)
	}

	bad := systemBackup()
	bad.KeySplit = &BackupKeySplit{Threshold: 1, Guardians: []string{"a", "b"}}
	if _, _, err := svc.CreateBackup(ctx, bad); err == nil || len(pub.events["audit.governance.backup_create_refused"]) != 1 {
		t.Fatalf("a 1-of-2 split must be refused and audited: %v", err)
	}
}
