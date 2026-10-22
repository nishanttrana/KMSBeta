package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeAuthority answers as auth would for the schedule's administrator.
type fakeAuthority struct {
	active  bool
	missing []string
	err     error
	asked   []string
}

func (f *fakeAuthority) Authority(_ context.Context, tenantID, userID string, perms []string) (bool, []string, error) {
	f.asked = append(f.asked, tenantID+"/"+userID+"/"+strings.Join(perms, ","))
	return f.active, f.missing, f.err
}

func recipientPair(t *testing.T, bits int) (*rsa.PrivateKey, string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// unseal is what the administrator does with the private key (the restore
// dialog in the browser, or openssl): RSA-OAEP-SHA256 of wrapped_key_b64,
// put back as backup_key_b64.
func unseal(t *testing.T, priv *rsa.PrivateKey, file BackupKeyFile) BackupKeyFile {
	t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(file.ContentBase64)
	pkg := map[string]interface{}{}
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatal(err)
	}
	wrapped, _ := base64.StdEncoding.DecodeString(pkg["wrapped_key_b64"].(string))
	key, err := rsa.DecryptOAEP(sha256.New(), nil, priv, wrapped, []byte(pkg["oaep_label"].(string)))
	if err != nil {
		t.Fatalf("the private key must open the sealed key: %v", err)
	}
	pkg["backup_key_b64"] = base64.StdEncoding.EncodeToString(key)
	out, _ := json.Marshal(pkg)
	file.ContentBase64 = base64.StdEncoding.EncodeToString(out)
	return file
}

// A schedule end to end on Postgres: it takes real backups on the
// administrator's authority with the key sealed to their public key (never
// stored usable, never software), the private key's holder restores one,
// retention keeps the newest, and lost authority pauses it while an auth
// outage only postpones it, each audited.
func TestBackupSchedulePostgres(t *testing.T) {
	svc, pub := newIntegrationGovernance(t)
	ctx := context.Background()
	auth := &fakeAuthority{active: true}
	svc.authority = auth
	clock := time.Now().UTC().Truncate(time.Microsecond) // Postgres keeps microseconds
	svc.now = func() time.Time { return clock }
	store := svc.store.(*SQLStore)
	if _, err := store.db.SQL().ExecContext(ctx, `DELETE FROM governance_backup_schedules`); err != nil {
		t.Fatal(err)
	}
	// A tenant of this test's own: the shared CI database may hold an HSM
	// profile for root, left by another package's tests.
	noHSM := "t-nohsm-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	priv, pubPEM := recipientPair(t, 3072)
	_, weakPEM := recipientPair(t, 2048)
	enabled := true

	// Refused before anything is stored: no key protection, a software key,
	// HSM protection without an HSM, a weak or private key.
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: func() []byte { b, _ := x509.MarshalPKCS8PrivateKey(priv); return b }()}))
	for name, in := range map[string]BackupScheduleInput{
		"no protection":   {Name: "x", Scope: "system", IntervalHours: 24, RetainCount: 3},
		"software":        {Name: "x", Scope: "system", IntervalHours: 24, RetainCount: 3, KeyProtection: "software"},
		"hsm without HSM": {Name: "x", Scope: "tenant", TargetTenantID: noHSM, IntervalHours: 24, RetainCount: 3, KeyProtection: keyProtectionHSM},
		"weak key":        {Name: "x", Scope: "system", IntervalHours: 24, RetainCount: 3, KeyProtection: keyProtectionRecipient, RecipientPublicKey: weakPEM},
		"private key":     {Name: "x", Scope: "system", IntervalHours: 24, RetainCount: 3, KeyProtection: keyProtectionRecipient, RecipientPublicKey: privPEM},
		"zero retention":  {Name: "x", Scope: "system", IntervalHours: 24, RetainCount: 0, KeyProtection: keyProtectionRecipient, RecipientPublicKey: pubPEM},
	} {
		if _, err := svc.SaveBackupSchedule(ctx, "root", "", in, "admin-1"); !errors.Is(err, errInvalidBackupSchedule) {
			t.Fatalf("%s: want invalid schedule, got %v", name, err)
		}
	}
	if items, _ := svc.ListBackupSchedules(ctx, "root"); len(items) != 0 {
		t.Fatalf("refused schedules were stored: %+v", items)
	}

	sch, err := svc.SaveBackupSchedule(ctx, "root", "", BackupScheduleInput{Name: "nightly", Enabled: &enabled, Scope: "system",
		IntervalHours: 24, RetainCount: 2, KeyProtection: keyProtectionRecipient, RecipientPublicKey: pubPEM}, "admin-1")
	if err != nil {
		t.Fatal(err)
	}
	if sch.NextRunAt == nil || !sch.NextRunAt.Equal(clock.Add(24*time.Hour)) || sch.RecipientKeySHA256 == "" {
		t.Fatalf("saved schedule %+v", sch)
	}
	if n := svc.RunDueBackupSchedules(ctx); n != 0 {
		t.Fatalf("nothing is due yet, took %d", n)
	}

	createNamedPolicy(t, svc, "t-sched", "original")
	var taken []string
	for i := 0; i < 3; i++ {
		clock = clock.Add(25 * time.Hour)
		if n := svc.RunDueBackupSchedules(ctx); n != 1 {
			t.Fatalf("run %d: took %d backups", i, n)
		}
		got, _ := store.getBackupSchedule(ctx, "root", sch.ID)
		taken = append(taken, got.LastBackupID)
		if got.LastResult != "succeeded" || !got.NextRunAt.Equal(clock.Add(24*time.Hour)) {
			t.Fatalf("after run %d: %+v", i, got)
		}
	}
	if auth.asked[0] != "root/admin-1/auth.tenant.write" {
		t.Fatalf("every run asks auth for the administrator's authority: %v", auth.asked)
	}
	// Retention: the newest two of this schedule's three remain.
	ids, _ := store.scheduledBackupIDs(ctx, "root", sch.ID)
	if len(ids) != 2 || ids[0] != taken[2] || ids[1] != taken[1] {
		t.Fatalf("retention kept %v of %v", ids, taken)
	}
	if deleted := pub.events["audit.governance.backup_deleted"]; len(deleted) != 1 {
		t.Fatalf("the pruned backup must be audited as deleted: %d", len(deleted))
	}
	if ev := pub.events["audit.governance.scheduled_backup_taken"]; len(ev) != 3 {
		t.Fatalf("each scheduled backup is audited: %d", len(ev))
	}

	// The stored package can't open the backup; the sealed file, unsealed
	// by the private key's holder, restores it.
	var row string
	if err := store.db.SQL().QueryRow(`SELECT key_package_json::text FROM governance_backup_jobs WHERE id=$1`, taken[2]).Scan(&row); err != nil {
		t.Fatal(err)
	}
	stored := map[string]interface{}{}
	if err := json.Unmarshal([]byte(row), &stored); err != nil {
		t.Fatal(err)
	}
	if _, has := stored["backup_key_b64"]; has || stored["mode"] != backupKeyModeRecipient || stored["wrapped_key_b64"] == nil {
		t.Fatalf("stored package must hold only the sealed key: %s", row)
	}
	sealed, err := svc.GetBackupKeyDownload(ctx, "root", taken[2], "admin-1")
	if err != nil {
		t.Fatalf("a sealed key file can be downloaded again: %v", err)
	}
	art, err := svc.GetBackupArtifactDownload(ctx, "root", taken[2])
	if err != nil {
		t.Fatal(err)
	}
	restore := func(key BackupKeyFile) error {
		_, err := svc.RestoreBackup(ctx, RestoreBackupInput{TenantID: "root", ArtifactFileName: art["file_name"].(string), ArtifactContentBase: art["content_base64"].(string),
			KeyFileName: key.FileName, KeyContentBase: key.ContentBase64, CreatedBy: "admin-1"})
		return err
	}
	createNamedPolicy(t, svc, "t-sched", "after-backup")
	if err := restore(sealed); err == nil || !strings.Contains(err.Error(), "unseal") {
		t.Fatalf("a still-sealed key file must be refused with how to unseal it: %v", err)
	}
	otherKey := map[string]interface{}{}
	raw, _ := base64.StdEncoding.DecodeString(sealed.ContentBase64)
	_ = json.Unmarshal(raw, &otherKey)
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	otherKey["backup_key_b64"] = base64.StdEncoding.EncodeToString(k)
	forged, _ := json.Marshal(otherKey)
	if err := restore(BackupKeyFile{FileName: sealed.FileName, ContentBase64: base64.StdEncoding.EncodeToString(forged)}); err == nil {
		t.Fatal("a key that isn't this backup's must be refused")
	}
	if names := policyNames(t, svc, "t-sched"); !names["after-backup"] {
		t.Fatalf("refused restores must not modify data: %v", names)
	}
	if err := restore(unseal(t, priv, sealed)); err != nil {
		t.Fatalf("the unsealed key must restore: %v", err)
	}
	if names := policyNames(t, svc, "t-sched"); !names["original"] || names["after-backup"] {
		t.Fatalf("restore must return the backup's contents: %v", names)
	}

	// Auth can't be asked: postponed, not paused, no backup.
	auth.err = errors.New("auth unreachable")
	clock = clock.Add(25 * time.Hour)
	if n := svc.RunDueBackupSchedules(ctx); n != 0 {
		t.Fatalf("no backup without verified authority, took %d", n)
	}
	got, _ := store.getBackupSchedule(ctx, "root", sch.ID)
	if got.PausedReason != "" || !got.NextRunAt.Equal(clock.Add(backupScheduleRetry)) {
		t.Fatalf("an auth outage postpones: %+v", got)
	}
	// The administrator lost the permission: paused, audited, no backup.
	auth.err, auth.missing = nil, []string{backupSchedulePermission}
	clock = clock.Add(time.Hour)
	if n := svc.RunDueBackupSchedules(ctx); n != 0 {
		t.Fatalf("a revoked authority took %d backups", n)
	}
	got, _ = store.getBackupSchedule(ctx, "root", sch.ID)
	if got.PausedReason == "" || got.LastResult != "refused" {
		t.Fatalf("a revoked authority pauses: %+v", got)
	}
	refused := pub.events["audit.governance.scheduled_backup_refused"]
	if len(refused) != 2 {
		t.Fatalf("both refusals audited: %d", len(refused))
	}
	reasons := []string{}
	for _, ev := range refused {
		data, _ := ev["data"].(map[string]interface{})
		reasons = append(reasons, data["reason"].(string))
	}
	if strings.Join(reasons, ",") != "authority_unknown,authority_revoked" {
		t.Fatalf("refusal reasons %v", reasons)
	}
	clock = clock.Add(48 * time.Hour)
	if n := svc.RunDueBackupSchedules(ctx); n != 0 {
		t.Fatal("a paused schedule must not run")
	}
	// Saving it again, on a holder's authority, resumes it.
	auth.missing = nil
	if _, err := svc.SaveBackupSchedule(ctx, "root", sch.ID, BackupScheduleInput{Name: "nightly", Enabled: &enabled, Scope: "system",
		IntervalHours: 1, RetainCount: 2, KeyProtection: keyProtectionRecipient, RecipientPublicKey: pubPEM}, "admin-2"); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * time.Hour)
	if n := svc.RunDueBackupSchedules(ctx); n != 1 {
		t.Fatalf("a resumed schedule runs, took %d", n)
	}
	if last := auth.asked[len(auth.asked)-1]; last != "root/admin-2/auth.tenant.write" {
		t.Fatalf("a resumed schedule runs on the new administrator's authority: %s", last)
	}

	// A failed backup is audited and tried again within the hour.
	if _, err := store.db.SQL().ExecContext(ctx, `UPDATE governance_backup_schedules SET key_protection='hsm', recipient_public_key='', scope='tenant', target_tenant_id=$2 WHERE id=$1`, sch.ID, noHSM); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(2 * time.Hour)
	if n := svc.RunDueBackupSchedules(ctx); n != 0 {
		t.Fatal("an HSM schedule with no HSM must not fall back to a software key")
	}
	failed := pub.events["audit.governance.scheduled_backup_failed"]
	if len(failed) != 1 {
		t.Fatalf("a failed scheduled backup is audited: %d", len(failed))
	}
	if data, _ := failed[0]["data"].(map[string]interface{}); data["reason"] != "backup_refused" || data["result"] != "failure" {
		t.Fatalf("failure audit %+v", failed[0])
	}
	got, _ = store.getBackupSchedule(ctx, "root", sch.ID)
	if got.LastResult != "failed" || !got.NextRunAt.Equal(clock.Add(time.Hour)) {
		t.Fatalf("after a failure %+v", got)
	}
}
