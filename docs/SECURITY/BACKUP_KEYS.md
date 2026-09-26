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

## Split key: M-of-N guardian shares (optional, software mode)

A single key file makes whoever holds it a single point of failure: lose it
and the backup is gone, keep it and that one person can restore every key.
`key_split: {"threshold": M, "guardians": [...]}` on create removes both.

- The backup key is split with Shamir secret sharing over GF(2^8)
  (`pkg/crypto.SplitSecret`) into one share per named guardian (2–16
  guardians, 2 ≤ M ≤ N). Polynomial coefficients come from the module DRBG;
  field arithmetic doesn't branch on share bytes.
- The create response returns `key_shares` (one `.key.json` per guardian,
  with `guardian`, `share_index`, `share_b64`) **instead of** a key file.
  No one receives the whole key, and the dashboard lists the shares once,
  with a download per guardian.
- The stored package holds `mode: "software_split"`, the key fingerprint,
  the threshold and, per guardian, the share index and share fingerprint.
  It never holds the key or a share.
- Restore takes `key_shares`. It needs at least M share files from the same
  backup, rebuilds the key (`pkg/crypto.CombineShares`) and refuses unless
  it matches `backup_key_sha256`. Fewer than M shares, an altered share,
  shares from different backups, or one share given as a key file are all
  refused and audited (`backup_restore_refused`) before any data changes.
- Audit: `audit.governance.backup_key_split` (threshold, guardians) at
  create; `backup_restored` records `key_source: guardian_shares` and the
  guardians whose shares were used.
- A split key is never HSM-bound: asking for both on a tenant with an
  enabled HSM is refused. An HSM-bound key never leaves the HSM, so it has
  nothing to split.
- FIPS: secret sharing is a split-knowledge procedure, not an encryption
  algorithm, and no FIPS standard covers it. It is available in every mode
  (see [FIPS.md](FIPS.md#whats-inside-the-validated-boundary-and-what-isnt)).

## Verifying a backup (recovery evidence)

`POST /governance/backups/verify` (System Administration > Backups > Verify
Backup) proves a backup can still be recovered, without touching data.
- It runs the same code as restore up to the point of applying
  (`openBackup`): key file, guardian shares or HSM unwrap, then AES-GCM
  under the backup's AAD, then the snapshot parse.
- It reports the real table and row counts, the capture time, the key
  source and the elapsed time.
- It doesn't check that the owning services can re-wrap rows under retired
  master keys. Restore checks that before it applies anything.
- Audit: `audit.governance.backup_verified`; a backup that doesn't open
  emits `audit.governance.backup_verify_refused` with the reason.
- This replaces the old keycore "DR drill", which reported fabricated
  results.

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
    `TestBackupRestoreRefusesTamperingPostgres`;
  - `TestVerifyBackupPostgres`: a key file and three guardian shares
    verify with real counts and no data change; a wrong key or two shares
    are refused and audited;
  - `TestSplitBackupKeyRestorePostgres`: five guardian shares, nothing
    stored, two shares or one share refused and audited with data
    untouched, any three restore.
- `TestVerifyBackupRouteAuthAndActor`: the verify route is root-admin only,
  and the audited caller comes from the token, not the body.
- `TestSplitBackupKeyNeedsThresholdShares`,
  `TestValidateBackupKeySplitRejectsBadSplits`; `pkg/crypto`:
  `TestGFArithmetic`, `TestShamirAnyThresholdSubsetRecovers`,
  `TestShamirBelowThresholdDoesNotRecover`, `TestShamirRejectsBadInput`
  (all FIPS modes).
