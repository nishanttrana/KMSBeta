# Governance backup keys

**Standing rule:** the platform never stores a key that opens a backup
unless that key is wrapped under a secret the database doesn't hold. The
key that wraps it is derived with HKDF-SHA256, never with a raw hash
(CLAUDE.md, "Crypto and transport standards").

A governance backup (`POST /governance/backups`) is a gzip JSON snapshot
sealed with AES-256-GCM under a fresh random 32-byte backup key. The
artifact (`.vbk`) is stored in `governance_backup_jobs` and can be
downloaded at any time. What happens to the backup key depends on the mode.

## Software mode (no HSM binding)

- The key file (`.key.json`, with `backup_key_b64`) is returned **once**, in
  the create response (`key_file`). The dashboard saves it immediately.
- The stored package holds the mode, the SHA-256 fingerprint of the key
  (`backup_key_sha256`) and `key_retained: false`. It never holds the key.
- `GET /governance/backups/{id}/key` answers `410 backup_key_not_retained`
  and emits `audit.governance.backup_key_download_refused`
  (`reason: key_not_retained`).
- Lose the key file and the backup can't be restored. That's the point: a
  copy of the database (dump, snapshot, replica) no longer opens its own
  backups.

## HSM-bound mode

Used when `bind_to_hsm` is true (the default) and the tenant has an enabled
HSM configuration (`auth_hsm_provider_configs`).

- Wrap key = `HKDF-SHA256(secret = BACKUP_HSM_WRAP_SECRET, salt = none,
  info = "vecta-kms/backup-key-wrap/v2|<binding fingerprint>|<request tenant>|<target tenant>")`.
  The binding fingerprint covers the provider, slot, partition, token label
  and library path.
- The backup key is sealed under it with AES-256-GCM (module-generated
  nonce; AAD binds the binding hash). The package records
  `key_derivation: "v2"`.
- The wrapped package is stored, so it can be downloaded again
  (`audit.governance.backup_key_downloaded`). The database alone can't open
  it: that needs `BACKUP_HSM_WRAP_SECRET` from governance's environment and
  the same HSM binding.
- `BACKUP_HSM_WRAP_SECRET` must be at least 32 characters
  (`openssl rand -hex 32`). A missing or short secret refuses the backup
  (`audit.governance.backup_create_refused`) and the restore
  (`backup_restore_refused`).
- Restore uses the binding of the tenant the backup was bound to (the target
  tenant for a tenant-scope backup).

Despite the name, the HSM isn't used to wrap the key. The binding metadata
only scopes the derivation. Real HSM wrapping is still open.

## What was wrong before (fixed 2026-09-26)

1. **Software-mode keys were stored in plaintext** in `key_package_json`, in
   the same row as the artifact. Anyone who could read the database, or any
   copy of it, could download and open every software-mode backup.
2. **HSM-bound wrap keys were a raw SHA-256** of
   `secret|fingerprint|tenants` (`key_derivation: "v1"`), not a KDF. Restore
   also tried three candidate inputs, including one without the tenants.

Migration `013_backup_keys_not_retained.sql` removes both from existing rows
(`backup_key_b64`, and the wrapped fields of every non-v2 `hsm_bound`
package) and marks them `key_retained: false`. Restore refuses v1 packages.
So a backup taken before the upgrade restores only with a software key file
saved earlier. The owner confirmed that no backups were taken on the old
version (2026-09-26).

## Contents under retired master keys

Rows of the tables in `pkg/mek.Catalog` found under a public development
key are re-wrapped by their owning service at capture and again at restore
([SERVICE_MASTER_KEYS.md](SERVICE_MASTER_KEYS.md#backups-kept-in-the-platform)).
If the service can't re-wrap them, the backup or restore is refused.

## Tests

- `TestSoftwareBackupKeyIsNotStored`, `TestHSMBoundBackupKeyUsesHKDF` (round
  trip; another binding, tenant or secret doesn't open it; the wrap key is
  the HKDF output and not the raw hash), `TestHSMBoundV1PackageIsRefused`,
  `TestBackupWrapSecretStrength`.
- Postgres (`VECTA_TEST_POSTGRES_DSN`, CI `integration-postgres`):
  `TestSoftwareBackupKeyNotRetainedPostgres` (the row doesn't hold the key;
  the download is refused and audited; the key file from creation restores),
  `TestMigrationScrubsStoredBackupKeysPostgres`, `TestBackupReprotectPostgres`,
  `TestBackupRestoreRoundTripPostgres`, `TestBackupRestoreRefusesTamperingPostgres`.
