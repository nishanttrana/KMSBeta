package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pkgcrypto "vecta-kms/pkg/crypto"
)

// The write-ahead buffer holds audit events while Postgres or NATS is down
// (AUDIT_FAIL_CLOSED=false). Its records are HMAC'd so a record altered on
// disk is not ingested. The key is generated once and kept on the audit
// service's own volume next to the buffer, because the buffer must open
// during the outage it exists for, before keycore (pkg/mek) can be reached
// (docs/DECISIONS.md 2026-10-17). Until 13.20.0-beta the key was read from
// AUDIT_WAL_HMAC_KEY_B64, which no installer set, so it was random at every
// start and every record still buffered at a restart was dropped unread.

const (
	defaultAuditDataDir = "/app/data"
	walKeyFileName      = "audit-wal-hmac-key.b64"
	walKeyEnv           = "AUDIT_WAL_HMAC_KEY_B64"
)

func auditDataDir() string {
	if d := strings.TrimSpace(os.Getenv("AUDIT_DATA_DIR")); d != "" {
		return d
	}
	return defaultAuditDataDir
}

// loadOrCreateWALKey returns the buffer's HMAC key from path, creating it on
// first start. A key an operator set in AUDIT_WAL_HMAC_KEY_B64 is adopted
// into the file so records it signed still verify; otherwise a new random
// key is made. A file that exists but can't be read or decoded stops the
// service: replacing it would orphan every buffered record.
func loadOrCreateWALKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		key, decErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if decErr != nil || len(key) != 32 {
			return nil, fmt.Errorf("audit WAL HMAC key %s is malformed; restore it from backup (replacing it would orphan buffered events)", path)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("audit WAL HMAC key %s: %w", path, err)
	}
	key, err := adoptedOrNewWALKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// O_EXCL: two starts racing on one volume never write two keys.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		pkgcrypto.Zeroize(key)
		return loadOrCreateWALKey(path)
	}
	if err != nil {
		return nil, err
	}
	enc := base64.StdEncoding.EncodeToString(key)
	if _, err := f.WriteString(enc + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return key, f.Close()
}

func adoptedOrNewWALKey() ([]byte, error) {
	if raw := strings.TrimSpace(os.Getenv(walKeyEnv)); raw != "" {
		// The same reading LoadKey32 gave it (at least 16 bytes, padded to
		// 32), so records signed under it before the upgrade still verify.
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(key) < 16 {
			return nil, fmt.Errorf("%s is set but is not a base64 key of at least 16 bytes", walKeyEnv)
		}
		out := make([]byte, 32)
		copy(out, key)
		pkgcrypto.Zeroize(key)
		return out, nil
	}
	return pkgcrypto.RandomBytes(32)
}
