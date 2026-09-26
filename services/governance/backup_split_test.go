package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateBackupKeySplitRejectsBadSplits(t *testing.T) {
	for name, split := range map[string]*BackupKeySplit{
		"one guardian":        {Threshold: 1, Guardians: []string{"a"}},
		"threshold 1":         {Threshold: 1, Guardians: []string{"a", "b", "c"}},
		"threshold above N":   {Threshold: 4, Guardians: []string{"a", "b", "c"}},
		"blank guardian":      {Threshold: 2, Guardians: []string{"a", " "}},
		"duplicate guardian":  {Threshold: 2, Guardians: []string{"Alice", "alice", "bob"}},
		"too many guardians":  {Threshold: 2, Guardians: strings.Split("a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q", ",")},
		"guardian name > 128": {Threshold: 2, Guardians: []string{"a", strings.Repeat("x", 129)}},
	} {
		if _, err := validateBackupKeySplit(split); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if g, err := validateBackupKeySplit(&BackupKeySplit{Threshold: 3, Guardians: []string{" CISO ", "Legal", "CTO", "Ops", "Notary"}}); err != nil || g[0] != "CISO" {
		t.Fatalf("3-of-5 split refused: %v %v", g, err)
	}
}

// splitFixture builds the share files createBackup would return.
func splitFixture(t *testing.T, key []byte, threshold int, guardians []string, backupID string) []BackupKeyFile {
	t.Helper()
	file := map[string]interface{}{"mode": "software", "backup_key_b64": base64.StdEncoding.EncodeToString(key), "backup_key_sha256": sha256Hex(string(key))}
	stored := map[string]interface{}{"mode": "software", "backup_key_sha256": sha256Hex(string(key))}
	shares, err := splitBackupKey(key, threshold, guardians, file, stored)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := file["backup_key_b64"]; ok {
		t.Fatal("share files must not carry the whole key")
	}
	if b, _ := json.Marshal(stored); bytes.Contains(b, []byte("share_b64")) || stored["mode"] != backupKeyModeSplit {
		t.Fatalf("stored package must hold no share: %s", b)
	}
	files, err := backupShareFiles(BackupJob{ID: backupID}, file, threshold, guardians, shares)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestSplitBackupKeyNeedsThresholdShares(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	guardians := []string{"CISO", "Legal", "CTO", "Ops", "Notary"}
	files := splitFixture(t, key, 3, guardians, "bkp_a")
	if len(files) != 5 || files[0].Guardian != "CISO" || !strings.HasSuffix(files[4].FileName, backupKeyExtension) {
		t.Fatalf("share files: %+v", files)
	}

	got, _, used, err := combineBackupKeyShares([]BackupKeyFile{files[4], files[0], files[2]})
	if err != nil || !bytes.Equal(got, key) || len(used) != 3 {
		t.Fatalf("3 of 5 shares must restore the key: %v", err)
	}
	if _, _, _, err := combineBackupKeyShares(files[:2]); err == nil || !strings.Contains(err.Error(), "needs 3") {
		t.Fatalf("2 of 5 shares must be refused, got %v", err)
	}

	tampered := append([]BackupKeyFile(nil), files[:3]...)
	raw, _ := base64.StdEncoding.DecodeString(tampered[1].ContentBase64)
	var pkg map[string]interface{}
	_ = json.Unmarshal(raw, &pkg)
	share, _ := base64.StdEncoding.DecodeString(pkg["share_b64"].(string))
	share[5] ^= 1
	pkg["share_b64"] = base64.StdEncoding.EncodeToString(share)
	raw, _ = json.Marshal(pkg)
	tampered[1].ContentBase64 = base64.StdEncoding.EncodeToString(raw)
	if _, _, _, err := combineBackupKeyShares(tampered); err == nil || err.Error() != errBackupShareMismatch {
		t.Fatalf("an altered share must be refused, got %v", err)
	}

	other := splitFixture(t, bytes.Repeat([]byte{9}, 32), 3, guardians, "bkp_b")
	if _, _, _, err := combineBackupKeyShares([]BackupKeyFile{files[0], files[1], other[2]}); err == nil {
		t.Fatal("shares from two backups must be refused")
	}
}
