# Service master keys (pkg/mek)

**Standing rule:** a platform service that stores encrypted data gets its
master encryption key (MEK) from keycore through `pkg/mek`. No environment
variable, no fallback, and never a value derived from a string in the repo
(CLAUDE.md rules 3 and 6; `make conformance` rule `no-literal-key-material`).

Six services store envelope-encrypted data. Each value has its own data key
(DEK), and the service's MEK wraps it:

| Service | What it protects | Table |
|---|---|---|
| secrets | stored secret values (every version) | `secret_values` |
| certs | CA signing keys in the legacy format (the rest are under the sealed root key, CRWK) | `cert_cas` (`signer_kek_version` = `legacy*`) |
| cloud | cloud provider credentials | `cloud_accounts` |
| ekm | BitLocker recovery keys | `ekm_bitlocker_recovery_keys` |
| audit | webhook signing secrets and custom header values (Splunk HEC tokens, Datadog API keys), sealed together per webhook | `webhooks` (`creds_wrapped_dek` set) |
| compliance | playbook connection credentials (Slack/Teams webhook URLs, webhook URLs and headers, Jira and ServiceNow tokens), sealed together per connection (2.5.0-beta) | `compliance_playbook_connections` |

## What was wrong (found 2026-09-26)

Each service fell back to `SHA-256("vecta-<service>-dev-mek")` when its
`<SERVICE>_MEK_B64` was unset. cloud also fell back to the literal
`0123456789ABCDEF0123456789ABCDEF` for a short key. No installer, compose
file or script ever set these variables, so **every deployment** wrapped its
stored secrets, CA signing keys, cloud credentials and BitLocker recovery keys
under keys anyone with the source can compute. A copy of the database (a
pg_dump, a volume snapshot, a governance backup with its key package) was
enough to decrypt them.

## How the key works now

1. **System key.** At startup the service calls keycore
   `POST /system-keys/ensure` with its own service JWT. Keycore creates one
   AES-256 key per (service, purpose) in the internal service tenant,
   labelled `vecta.system`, and records it in `keycore_system_keys`. Only a
   verified service identity may call it, and only for itself.
2. **MEK.** The service derives its MEK with keycore
   `POST /keys/{id}/service-derive` (HKDF-SHA256, bound to the verified
   service identity, the key version and the purpose `<service>-mek`). No
   other caller can reproduce it.
3. **Pinned version.** `<service>_mek_state` records the keycore key, the
   version and a keyed fingerprint of the MEK (never the MEK itself).
4. **Check on every start.** If keycore derives a different MEK than the
   one recorded (a wrong keycore master key, or a member that joined a
   different primary), the service refuses to start
   (`audit.<service>.mek_check_refused`).
5. **Protected in keycore.** Keycore refuses at the storage layer anything
   that would make a system key unusable: destroy (immediate, scheduled,
   bulk or the purge sweep), disable or compromised status, deleting a
   version, and allowing export. It returns `409 system_key_protected` and
   emits `audit.key.system_key_change_refused`. Rotation and deactivation are
   allowed, since derivation keeps working.

Keycore must be reachable for these services to start; they retry for up to
10 minutes and then refuse. Keycore checks the policy service before creating
or deriving, like any other key operation.

**The audit service is the exception.** It is the platform's audit sink, so
it never refuses to start over its master key:
- it opens the key in the background and retries every minute while keycore
  is unreachable;
- until the key is open, writing webhook credentials returns
  `503 credentials_key_unavailable`, and a delivery that needs them fails with
  that reason (recorded and audited);
- webhooks without credentials, and the whole ingest pipeline, are
  unaffected;
- a key that doesn't match the stored data (`mek_check_refused`) stops the
  retries and keeps credentials unavailable (fail closed) rather than stopping
  the audit service;
- its `/mek/exposure` routes appear once the key is open.

The sealed payload names its tenant and webhook, so a blob copied onto
another row doesn't open there.

## Moving data off the old keys

On every start (primary only), and every 15 minutes after that,
`mek.Open` / `Keyring.Watch` scan the table and handle each row:

| The row's DEK opens under | Action | Event (per tenant) |
|---|---|---|
| the current MEK | nothing | none |
| a public dev key (or cloud's literal key) | re-wrap onto the MEK; record the item in the **exposure register** first | `dev_mek_rewrapped` (warning, item IDs) |
| `<SERVICE>_MEK_B64`, if an operator had set one | re-wrap | `mek_rewrapped` (`from: env_mek`) |
| the previously pinned keycore version (after a rotation) | re-wrap onto the new version | `mek_rewrapped` (`from: previous_version`) |
| none of these | leave it and report it (only when the count changes) | `mek_unreadable` |

- Each row is swapped only if it still holds the value that was read, so
  concurrent instances are safe. The value's ciphertext never changes.
- If a row that a legacy key opens can't be rewritten, the start is refused
  (`dev_mek_rewrap_refused` / `mek_rewrap_refused`) and the state isn't
  recorded. The next start retries. A service never serves with data left
  under a public key.
- The periodic rescan catches rows a restore brings back.
- **Cluster members never scan or write.** They check the fingerprint and
  derive the same MEK, because the join ships keycore's master key and the
  system key replicates. The primary re-wraps, and replication delivers the
  rows. Nothing needs to be copied between nodes.

## Rotating a service master key

Rotate the service's system key in keycore (Keys → filter `vecta.system`, or
`POST /keys/{id}/rotate`), then restart the service. On start it derives the
new version, re-wraps every row from the pinned version, and pins the new
one (`mek_rewrapped`, `from: previous_version`). Old versions stay derivable,
so a service that hasn't restarted yet keeps working on its pin. Rotation
re-wraps DEKs; it doesn't re-encrypt values.

## The exposure register: what re-wrapping can't fix

Re-wrapping protects the live database from now on. **It can't change copies
made before**: a pg_dump, a volume snapshot, or a backup artifact and key
file already downloaded. Those still decrypt with the public key. The only
real fix for such a copy is to make the values in it worthless, by replacing
the material. So each item found under a public key is recorded in
`<service>_mek_exposure` and stays open until one of these happens:

| Service | Closes automatically when |
|---|---|
| secrets | the value is rotated or updated (including Vault KV writes), or the secret is deleted |
| certs | the CA is deleted (issue a new CA, re-issue, then delete the old one) |
| cloud | the account is deleted (rotate at the provider, re-register, delete) |
| ekm | a `rotate` job escrows a new recovery key for the volume, or the client is deleted |
| audit | every credential the webhook had is replaced in one or more updates (a new or removed secret, and each header sent with a new value or dropped), or the webhook is deleted |
| compliance | every field of the connection is sent anew in one update, or the connection is deleted |

An administrator can also close an entry with a reason of at least 10
characters (`POST /mek/exposure/{item_type}/{item_id}/acknowledge`,
permission `<domain>.exposure.acknowledge`), for example for test data. Every
closure emits `mek_exposure_remediated` (warning when acknowledged).

The dashboard shows the register per tenant under **Administration → Tenant
→ Security → Key exposure register**, with the remedy for each kind of item.
`GET /mek/exposure?open=false` returns it (permission `<domain>.read`).

## Backups kept in the platform

Governance backups store the encrypted artifact in the database. A backup
of rows under the public keys would keep exposing them through the
platform's own backups. So, on the owning service's
`POST /mek/rewrap-legacy` (only the `kms-governance` identity may call it;
the service re-wraps only what a legacy key opens):

- **Captures are re-wrapped.** Before a backup is sealed, rows of the tables
  above that a public key opens are re-wrapped onto the service key. If the
  service can't re-wrap them, no backup is taken
  (`audit.governance.backup_create_refused`).
- **Restores are re-wrapped before any row is written.** Governance finds
  rows under a public key itself (those keys are public), so a clean backup
  never needs the services. For affected rows it calls the owning service,
  and the item (re)opens in the exposure register, because the old value is
  live again. If that service can't re-wrap, nothing is restored
  (`backup_restore_refused`).

Backups already stored are not re-sealed in place: governance no longer keeps
software-mode backup keys, and migration 013 removed the stored keys of
backups taken before the upgrade ([BACKUP_KEYS.md](BACKUP_KEYS.md)). An
earlier design re-sealed stored backups hourly. It was dropped with the
stored keys (no backups had been taken on the old version).

## Known limitations

- **Copies outside the platform** (downloaded backups, dumps, snapshots)
  can't be changed. They're why the exposure register exists; closing it
  means replacing the material.
- **CA signing keys** re-wrapped onto the sealed root key (certs'
  `RewrapLegacyCASigners`) are still the same private keys, so their entries
  stay open until the CA is replaced.
- **Keycore is a startup dependency** of secrets, certs, cloud and ekm. For
  audit it gates webhook credentials only; for compliance, playbook
  connections only (until the key opens, connection writes return 503 and
  notification steps fail with the reason).
- **Playbook credentials stored before 2.5.0-beta** were plaintext, inline
  in each playbook action. Compliance's primary moves each set into a
  sealed connection at startup (and every 15 minutes) and records it in the
  exposure register (`source: plaintext_storage`,
  `audit.compliance.playbook_connections_migrated`). Rotate those webhook
  URLs and tokens at the receiver. Since 2.6.0-beta the Playbooks →
  Connections view flags each one ROTATE, and the Administration exposure
  register lists them under "Playbook connections".
- **Webhook credentials stored before 1.25.0-beta** were plaintext. The
  audit service seals them at startup (and every 15 minutes, which catches
  restored rows) and records each webhook in the exposure register
  (`source: plaintext_storage`, audited as `audit.audit.mek_exposure_recorded`
  and `audit.audit.webhook_credentials_sealed`). Earlier database copies still
  hold them, so rotate them at the receiver.

## Tests

- **`pkg/mek`:** `TestMEKLifecycleSQLite`, `TestMEKLifecyclePostgres`
  (upgrade from a public and an env key, restart, restored row, remediation,
  keycore rotation, mismatch on a primary and a member, a member writes
  nothing), `TestRewrapFailureRefusesStart`,
  `TestKeycoreUnavailableRefusesStart`, `TestExposureAndRewrapRoutes` (with
  `routetest.RefusalsAudited`), and `TestCatalogIsValidAndMigrated`.
- **keycore:** `TestEnsureSystemKeyIsIdempotentAndServiceBound`,
  `TestSystemKeyIsProtectedFromDestruction`,
  `TestSystemKeyRouteIsServiceOnlyAndAudited`.
- **Per service:** `TestUpgradeMovesSecretsOffPublicKey` (and `…Postgres`),
  `TestUpgradeMovesCloudCredentialsOffPublicKey`,
  `TestUpgradeMovesRecoveryKeysOffPublicKey`,
  `TestUpgradeMovesCASignerOffPublicKey`.
- **governance:** `TestBackupReprotectPostgres` (capture and restore re-wrap).
- **audit:** `TestWebhookCredentialsAreSealedAtRest`,
  `TestWebhookCredentialsAreBoundToTheirWebhook`,
  `TestWebhookCredentialsFailClosedWithoutKey`,
  `TestPlaintextWebhooksAreSealedAndRegistered`,
  `TestCredsKeyringMismatchFailsClosed`, and `TestWebhookCredentialsPostgres`
  (migration, plaintext sealing, keycore rotation re-wrap).
- **Mode coverage:** everything runs in FIPS modes off / on / only. The
  Postgres tests run in CI `integration-postgres`.
