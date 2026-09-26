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
HSM profile (HSM tab; for a system backup, the root tenant's).

- The hsm-connector ensures the tenant's key in its HSM,
  `vecta:<tenant>:tenant-key` (AES-256, sensitive, not extractable). The HSM
  then encrypts the backup key with it: `CKM_AES_GCM`, the IV from the HSM's
  own generator, and AAD = `vecta-kms/backup-key|<hsm tenant>|<request
  tenant>|<target tenant>` ([HSM_INTEGRATION.md](HSM_INTEGRATION.md)).
- The package records `key_wrap: "hsm_tenant_key"`, `hsm_tenant_id` and
  `hsm_key_label`. It is stored, so it can be downloaded again
  (`audit.governance.backup_key_downloaded`). The database alone can't open
  it: only that HSM can, through the connector, as the `kms-governance`
  identity.
- A restore sends the wrapped key to the HSM. A package pointed at another
  tenant's key, moved to another tenant pair, or tampered with doesn't
  open. With the HSM unreachable, the restore is refused
  (`backup_restore_refused`).
- If the HSM can't be reached, the backup is refused
  (`backup_create_refused`). It never silently becomes a software-mode
  backup.
- `BACKUP_HSM_WRAP_SECRET` is no longer used.

## What was wrong before (fixed 2026-09-26)

1. **Software-mode keys were stored in plaintext** in `key_package_json`, in
   the same row as the artifact. Anyone who could read the database, or any
   copy of it, could download and open every software-mode backup.
2. **HSM-bound wrap keys were a raw SHA-256** of
   `secret|fingerprint|tenants` (`key_derivation: "v1"`), not a KDF. Restore
   also tried three candidate inputs, including one without the tenants.
   The first fix used HKDF-SHA256 of the same environment secret
   (`key_derivation: "v2"`). The HSM still did nothing in either version:
   the "binding" only fed the derivation. Since then the HSM wraps the key
   itself, and both v1 and v2 are retired.

Migrations `013_backup_keys_not_retained.sql` and
`014_backup_keys_hsm_wrapped.sql` remove the stored keys from existing rows
(`backup_key_b64`, and the wrapped fields of every `hsm_bound` package the
HSM didn't wrap) and mark them `key_retained: false`. Restore refuses v1 and
v2 packages.
So a backup taken before the upgrade restores only with a software key file
saved earlier. The owner confirmed that no backups were taken on the old
version (2026-09-26).

## Contents under retired master keys

Rows of the tables in `pkg/mek.Catalog` found under a public development
key are re-wrapped by their owning service at capture and again at restore
([SERVICE_MASTER_KEYS.md](SERVICE_MASTER_KEYS.md#backups-kept-in-the-platform)).
If the service can't re-wrap them, the backup or restore is refused.

## Tests

- `TestSoftwareBackupKeyIsNotStored`.
- `TestHSMBoundBackupKeyWrappedByHSM`: a real PKCS#11 HSM (SoftHSM2). The
  key round-trips; another tenant's key, a rebound tenant pair or a tampered
  wrap doesn't open.
- `TestRetiredHSMBoundFormatsAreRefused` (v1 and v2).
- Postgres (`VECTA_TEST_POSTGRES_DSN`, CI `integration-postgres`):
  - `TestSoftwareBackupKeyNotRetainedPostgres`;
  - `TestHSMBoundBackupPostgres`: the backup is wrapped by the HSM, the key
    file is downloaded again and restores, and there is no restore without
    the HSM;
  - `TestMigrationScrubsStoredBackupKeysPostgres` (013 and 014);
  - `TestBackupReprotectPostgres`, `TestBackupRestoreRoundTripPostgres`,
    `TestBackupRestoreRefusesTamperingPostgres`.
