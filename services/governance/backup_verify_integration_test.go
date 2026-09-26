package main

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// Verify opens a backup with its key file or guardian shares and changes no
// data; a wrong key or too few shares is refused and audited.
func TestVerifyBackupPostgres(t *testing.T) {
	svc, pub := newIntegrationGovernance(t)
	ctx := context.Background()
	createNamedPolicy(t, svc, "t-verify", "before-backup")
	job, files := takeBackup(t, svc, systemBackup())
	createNamedPolicy(t, svc, "t-verify", "after-backup")

	in := RestoreBackupInput{TenantID: "root", ArtifactFileName: files.artifactName, ArtifactContentBase: files.artifactB64,
		KeyFileName: files.keyName, KeyContentBase: files.keyB64, CreatedBy: "auditor"}
	res, err := svc.VerifyBackup(ctx, in)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.Verified || res.DataModified || res.TableCount != job.TableCount || res.RowCountTotal != job.RowCountTotal || res.KeySource != "key_file" {
		t.Fatalf("verify must report the backup's real contents: %+v (job %d tables, %d rows)", res, job.TableCount, job.RowCountTotal)
	}
	if names := policyNames(t, svc, "t-verify"); !names["after-backup"] {
		t.Fatalf("verify must not change data: %v", names)
	}
	ok := pub.events["audit.governance.backup_verified"]
	if len(ok) != 1 || len(pub.events["audit.governance.backup_restored"]) != 0 {
		t.Fatalf("want one backup_verified and no backup_restored, got %d / %d", len(ok), len(pub.events["audit.governance.backup_restored"]))
	}
	if data, _ := ok[0]["data"].(map[string]interface{}); data["verified_by"] != "auditor" || data["row_count_total"] == nil {
		t.Fatalf("verified audit: %+v", ok[0])
	}

	wrong := in
	wrong.KeyContentBase = base64.StdEncoding.EncodeToString([]byte(`{"mode":"software","backup_key_b64":"` +
		base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")) + `"}`))
	if _, err := svc.VerifyBackup(ctx, wrong); err == nil {
		t.Fatal("a wrong key must fail verification")
	}

	split := systemBackup()
	split.KeySplit = &BackupKeySplit{Threshold: 3, Guardians: []string{"CISO", "Legal", "CTO", "Ops", "Notary"}}
	sjob, shares, err := svc.CreateBackup(ctx, split)
	if err != nil {
		t.Fatal(err)
	}
	art, err := svc.GetBackupArtifactDownload(ctx, "root", sjob.ID)
	if err != nil {
		t.Fatal(err)
	}
	withShares := func(set ...BackupKeyFile) RestoreBackupInput {
		return RestoreBackupInput{TenantID: "root", ArtifactFileName: art["file_name"].(string), ArtifactContentBase: art["content_base64"].(string), KeyShares: set, CreatedBy: "auditor"}
	}
	if _, err := svc.VerifyBackup(ctx, withShares(shares[0], shares[1])); err == nil {
		t.Fatal("two of five shares must fail verification")
	}
	sres, err := svc.VerifyBackup(ctx, withShares(shares[1], shares[3], shares[4]))
	if err != nil || sres.KeySource != "guardian_shares" || len(sres.ShareGuardians) != 3 {
		t.Fatalf("three shares must verify: %+v %v", sres, err)
	}

	refused := pub.events["audit.governance.backup_verify_refused"]
	if len(refused) != 2 {
		t.Fatalf("both failed verifications must be audited, got %d", len(refused))
	}
	for _, ev := range refused {
		if data, _ := ev["data"].(map[string]interface{}); data["result"] != "refused" || strings.TrimSpace(data["reason"].(string)) == "" {
			t.Fatalf("refusal audit must carry result and reason: %+v", ev)
		}
	}
	if names := policyNames(t, svc, "t-verify"); !names["after-backup"] {
		t.Fatalf("failed verifications must not change data: %v", names)
	}
}
