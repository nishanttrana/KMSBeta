package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// A software-mode backup key can be split into M-of-N Shamir shares, one per
// named guardian, instead of one key file. No single share, and no set below
// the threshold, can open the backup (docs/SECURITY/BACKUP_KEYS.md).

const (
	backupKeyModeSplit     = "software_split"
	maxBackupGuardians     = 16
	maxBackupGuardianName  = 128
	errBackupShareMismatch = "the shares don't reconstruct this backup's key: a share is wrong, altered or from another backup"
)

// validateBackupKeySplit returns the trimmed guardian names.
func validateBackupKeySplit(split *BackupKeySplit) ([]string, error) {
	if split == nil {
		return nil, nil
	}
	guardians := make([]string, 0, len(split.Guardians))
	seen := map[string]bool{}
	for _, g := range split.Guardians {
		g = strings.TrimSpace(g)
		if g == "" || len(g) > maxBackupGuardianName {
			return nil, fmt.Errorf("key_split: guardian names must be 1-%d characters", maxBackupGuardianName)
		}
		if seen[strings.ToLower(g)] {
			return nil, fmt.Errorf("key_split: guardian %q is listed twice", g)
		}
		seen[strings.ToLower(g)] = true
		guardians = append(guardians, g)
	}
	if len(guardians) < 2 || len(guardians) > maxBackupGuardians {
		return nil, fmt.Errorf("key_split: name between 2 and %d guardians", maxBackupGuardians)
	}
	if split.Threshold < 2 || split.Threshold > len(guardians) {
		return nil, fmt.Errorf("key_split: threshold must be between 2 and the number of guardians (%d)", len(guardians))
	}
	return guardians, nil
}

// splitBackupKey splits the key and turns the software packages into split
// ones: the stored package records guardians and share fingerprints, the file
// package loses the whole key.
func splitBackupKey(backupKey []byte, threshold int, guardians []string, file, stored map[string]interface{}) ([][]byte, error) {
	shares, err := pkgcrypto.SplitSecret(backupKey, threshold, len(guardians))
	if err != nil {
		return nil, err
	}
	list := make([]map[string]interface{}, len(guardians))
	for i, g := range guardians {
		list[i] = map[string]interface{}{"guardian": g, "share_index": int(shares[i][0]), "share_sha256": sha256Hex(string(shares[i]))}
	}
	summary := map[string]interface{}{"threshold": threshold, "shares_total": len(guardians), "guardians": list}
	delete(file, "backup_key_b64")
	for _, pkg := range []map[string]interface{}{file, stored} {
		pkg["mode"] = backupKeyModeSplit
		pkg["key_split"] = summary
	}
	return shares, nil
}

// backupShareFiles renders one .key.json per guardian share.
func backupShareFiles(job BackupJob, file map[string]interface{}, threshold int, guardians []string, shares [][]byte) ([]BackupKeyFile, error) {
	out := make([]BackupKeyFile, len(shares))
	for i, share := range shares {
		pkg := make(map[string]interface{}, len(file)+3)
		for k, v := range file {
			pkg[k] = v
		}
		pkg["guardian"] = guardians[i]
		pkg["share_index"] = int(share[0])
		pkg["share_b64"] = base64.StdEncoding.EncodeToString(share)
		pkg["note"] = fmt.Sprintf("Key share %d of %d for guardian %s. Any %d shares of this backup restore it; this share alone cannot. Keep it apart from the other shares and the artifact.",
			share[0], len(shares), guardians[i], threshold)
		f, err := backupKeyFileFor(job, pkg)
		if err != nil {
			return nil, err
		}
		f.FileName = fmt.Sprintf("vecta-backup-%s.share-%d-%s%s", job.ID, share[0], fileSlug(guardians[i]), backupKeyExtension)
		f.Guardian = guardians[i]
		f.ShareIndex = int(share[0])
		out[i] = f
	}
	return out, nil
}

// combineBackupKeyShares rebuilds a split backup key from guardian share
// files and checks it against the backup's key fingerprint. It returns the
// first share's package (for the artifact fields) and the guardians used.
func combineBackupKeyShares(files []BackupKeyFile) ([]byte, map[string]interface{}, []string, error) {
	var first map[string]interface{}
	var threshold int
	shares := make([][]byte, 0, len(files))
	defer func() {
		for _, s := range shares {
			pkgcrypto.Zeroize(s)
		}
	}()
	guardians := make([]string, 0, len(files))
	for _, f := range files {
		if !hasApprovedBackupKeyName(strings.TrimSpace(f.FileName)) {
			return nil, nil, nil, fmt.Errorf("key share files must use %s extension", backupKeyExtension)
		}
		raw, err := decodeBase64Payload(f.ContentBase64)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("invalid key share file %s: %w", f.FileName, err)
		}
		var pkg map[string]interface{}
		if err := json.Unmarshal(raw, &pkg); err != nil {
			return nil, nil, nil, fmt.Errorf("key share file %s is not valid JSON", f.FileName)
		}
		if fmt.Sprint(pkg["mode"]) != backupKeyModeSplit {
			return nil, nil, nil, fmt.Errorf("%s is not a guardian key share", f.FileName)
		}
		split, _ := pkg["key_split"].(map[string]interface{})
		t, _ := split["threshold"].(float64)
		if first == nil {
			first, threshold = pkg, int(t)
		} else if fmt.Sprint(pkg["backup_id"]) != fmt.Sprint(first["backup_id"]) || fmt.Sprint(pkg["backup_key_sha256"]) != fmt.Sprint(first["backup_key_sha256"]) || int(t) != threshold {
			return nil, nil, nil, errors.New("key shares come from different backups")
		}
		share, err := base64.StdEncoding.DecodeString(strings.TrimSpace(fmt.Sprint(pkg["share_b64"])))
		if err != nil || len(share) != 33 {
			return nil, nil, nil, fmt.Errorf("key share file %s has no valid share", f.FileName)
		}
		shares = append(shares, share)
		guardians = append(guardians, fmt.Sprint(pkg["guardian"]))
	}
	if threshold < 2 {
		return nil, nil, nil, errors.New("key share files don't state the split threshold")
	}
	if len(shares) < threshold {
		return nil, nil, nil, fmt.Errorf("this backup needs %d guardian key shares; %d given", threshold, len(shares))
	}
	key, err := pkgcrypto.CombineShares(shares)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("key shares: %w", err)
	}
	if sha256Hex(string(key)) != fmt.Sprint(first["backup_key_sha256"]) {
		pkgcrypto.Zeroize(key)
		return nil, nil, nil, errors.New(errBackupShareMismatch)
	}
	return key, first, guardians, nil
}

func fileSlug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 32 {
		out = out[:32]
	}
	if out == "" {
		out = "guardian"
	}
	return out
}
