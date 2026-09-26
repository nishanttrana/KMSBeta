# Changelog

All notable changes to Vecta KMS are recorded here. Versions follow the
`MAJOR.MINOR.PATCH[-beta]` scheme; the canonical version lives in the
[`VERSION`](VERSION) file and is published as a git tag (`vX.Y.Z`).

## [1.8.0-beta] — 2026-09-26

### Internal mTLS, slice 1: every service link is TLS 1.3 mTLS from the internal Sub CA
- **Internal PKI.** At first start the certs service creates the
  `vecta-internal-services` Sub CA under `vecta-runtime-root`. Both appear in
  the CA hierarchy.
- **Enrolment.** Every service (all 31 Go services) generates its own key
  and enrols with a CSR at `https://certs:8035/v1/enroll`.
  - An HMAC proof of its platform identity authenticates the request.
  - It gets a 7-day certificate, renewed with a fresh key at two thirds of
    its lifetime without a restart.
  - The key never leaves the service. SANs come from the platform registry,
    never from the CSR.
- **Servers.** Every service listener (HTTP and gRPC) now requires a client
  certificate from the Sub CA. Plain HTTP, no certificate, or a certificate
  from any other CA is refused at the handshake.
- **Clients.** Each service routes calls to platform hosts over mTLS, and
  refuses plain `http://` to them. External calls keep public-CA trust.
  - All `*_URL` defaults are now `https://<service>:<port>`.
  - Several old `127.0.0.1` defaults pointed at the wrong port or at the
    container itself.
- **Envoy and the dashboard.**
  - Envoy reaches every service and the dashboard over mTLS with its own
    Sub CA client certificate.
  - Envoy's certificates, edge and internal, reload through file-based SDS
    when certs renews them.
  - `/svc/<service>/` and `/auth` now route straight to each service. The
    dashboard's nginx serves static files only, over TLS, accepting only
    Envoy.
- **Post-quantum key exchange, proven.** Every internal handshake negotiates
  `X25519MLKEM768` (hybrid ML-KEM) in FIPS modes `off`, `on` and `only`.
  `TestMutualTLSBetweenServices` asserts it, and Envoy's upstream stats show
  it on the running stack. Certificate signatures stay ECDSA: Go's TLS
  doesn't support ML-DSA certificates.
- **Payment's terminal port (9170) is TLS 1.3**, not plaintext TCP.
  - **Breaking:** terminals must now trust the Vecta internal root, which
    can be downloaded from the PKI tab.
  - Choosing a different external certificate comes in slice 4.
- **Governance approval callbacks** use mTLS, and dial only registered
  platform services. The target address comes from the request, so this also
  closes an SSRF.

### Removed
- **`POST /certs/internal/mtls/{service}`:** any authenticated caller could
  get a certificate and private key for any service name.
- **The "TLS 1.3 + Hybrid PQC (KMS internal)" TLS mode.** It minted ML-DSA
  "hybrid" certificates that no service used, then audited
  `internal_hybrid_tls_applied`. The System Administration TLS policy now
  shows the enforced policy instead of a selector.

### Enforcement
- **`make conformance` rule `tls-only`** fails on:
  - plain `ListenAndServe()` or `insecure.NewCredentials()`;
  - any `http://` to a platform host, in Go, compose, Envoy, nginx or the
    scripts.

### Fixes from the first deploy
- **New volumes needed `app` ownership.** `start-kms.sh` now prepares
  `internal-trust` (755) and `dashboard-tls` (750).
- **Envoy upstream TLS needed an explicit TLS 1.3 maximum.** Its upstream
  default maximum is 1.2, which with a 1.3 minimum leaves no version.
- **nginx needs the chain up to the root to verify a client.** It gets
  `internal-chain.crt`, and still requires the Sub CA as issuer.

## [1.7.0-beta] — 2026-09-26

### Removed: "mTLS Mesh" (it never issued a usable certificate)
- **Removed the mTLS Mesh tab, the certs service's `/mesh/*` endpoints and
  its Consul reconciler.**
- **Why:**
  - "Renew certificate" generated a self-signed certificate and key, then
    discarded both. It stored only metadata, so no service ever received a
    certificate.
  - The topology marked every service-to-service edge "mTLS verified" from
    a hardcoded list, while the services actually talk plain HTTP.
  - Trust anchors and registered services were records only. `tenant_id`
    came from the request body, and nothing was audited.
- Certs migration 012 drops the four `mesh_*` tables.

### Standing rule: every connection is TLS, every internal one is mTLS
- **CLAUDE.md rule 10** ([docs/SECURITY/INTERNAL_TLS.md](docs/SECURITY/INTERNAL_TLS.md)):
  - no plain HTTP anywhere;
  - internal mTLS with certificates from an internal-services Sub CA under
    `vecta-runtime-root`, both created at deployment and shown in the CA
    hierarchy;
  - external certificates from the internal CA or an external CA (PKI tab);
  - per-service one-click rotation and mechanism choice, including PQC
    hybrid key exchange.
- **Honest status: not yet compliant.**
  - Service-to-service calls are plain HTTP inside the Docker network.
  - Postgres runs with `sslmode=disable`; NATS, Valkey and Consul are
    plaintext.
  - Delivery is planned in four slices (see the doc).

## [1.6.0-beta] — 2026-09-26

### Backups: Verify Backup (real recovery evidence)
- **New "Verify Backup" button** in System Administration > Backups, next to
  Restore Backup, and `POST /governance/backups/verify`.
  - It opens a backup with its key file or guardian shares exactly as a
    restore would, and reports real table and row counts, the capture time,
    the key source and how long it took.
  - It changes no data.
  - Audited: `audit.governance.backup_verified` and
    `audit.governance.backup_verify_refused`.
- **Restore and verify now take the acting user from the verified token.**
  `created_by` in the request body was trusted before.

### Process: real capability only, and never expose a secret
- **New standing rules** (CLAUDE.md 8 and 9):
  - Every feature must be 100% real capability, never mimicked or faked
    ([docs/SECURITY/REAL_CAPABILITY.md](docs/SECURITY/REAL_CAPABILITY.md)).
  - Passwords, tokens, keys and other secrets are never exposed in commands,
    logs, output, chat, commits or URLs
    ([docs/SECURITY/SECRET_HANDLING.md](docs/SECURITY/SECRET_HANDLING.md)).
- **`make conformance` has a new `real-capability` rule.** It fails on
  `simulate*` / `synthetic*` / `fabricate*` / `fake*` / `mock*` functions
  outside tests, and on `Math.random` byte generation in the dashboard.
- **Fix: the Tokenize nonce no longer falls back to `Math.random`** or a
  timestamp. It uses the browser CSPRNG only, and fails if that is missing.
- **Fix: compiled service binaries were committed by mistake.**
  `services/governance/governance` (35 MB) came in with 1.4.0-beta and
  `services/certs/certs` with 1.5.0-beta. Both are now untracked, and
  `.gitignore` covers every `services/<name>/<name>` build output.

### Removed: DR drill (it fabricated results)
- **Removed the "DR Drill" tab and keycore's `/dr-drill/*` endpoints.**
- **Why:** triggering a drill ran nothing. Every step was marked "passed",
  with 10/10 keys restored, RPO 0 and a made-up RTO, and nothing executed
  the schedules.
  - The routes also took `tenant_id` from the request body and emitted no
    audit events.
- Keycore migration 023 drops `dr_drill_schedules` and `dr_drill_runs`,
  which also purges the fabricated runs.
- The Command Center's single-node advice now points at Verify Backup.

## [1.5.0-beta] — 2026-09-26

### Removed: CT log monitor (it fabricated findings)
- **Removed the "CT Log Monitor" tab and the certs service's
  `/ct-monitor/*` endpoints.**
- **Why:** it never read a Certificate Transparency log. Adding a watched
  domain started `simulateCTFetch`, which invented 2–3 certificates for the
  domain, including one from a made-up issuer "UnknownCA-ShadowNet" in a log
  called `argon2024`. It then raised **high-severity "certificate issued by
  unknown CA" alerts** from them, shown like real findings.
  - The routes also took `tenant_id` from the request body and emitted no
    audit events.
- **Certs migration 011 drops `ct_watched_domains`, `ct_log_entries` and
  `ct_alerts`**, which also purges every synthetic entry and alert already
  stored.
- **Unchanged:** the internal certificate Merkle log (`/certs/merkle/*`,
  "Certificate Transparency" on the Certificates overview). It is real and
  stays.
- Certificate discovery and scanning may come later as a new feature
  (docs/DECISIONS.md).

## [1.4.0-beta] — 2026-09-26

### Backups: split the key among guardians (M-of-N)
- **Optional guardian split when creating a backup.** In System
  Administration > Backups, tick "Split the key among guardians", name 2–16
  guardians and set how many shares restore it (for example 3 of 5).
  - Each guardian gets one share file, listed once with its own download.
    No one holds the whole key.
  - Any M shares restore the backup. Fewer can't, and losing up to N−M
    shares doesn't lose it.
  - The platform stores neither the key nor the shares: only fingerprints.
  - API: `key_split` on `POST /governance/backups`; `key_shares` on
    `POST /governance/backups/restore`.
  - Audited: `audit.governance.backup_key_split`, plus `key_source` on
    `backup_restored`. Every refused split restore is audited too.
- **Shamir secret sharing moved into `pkg/crypto`** (`SplitSecret`,
  `CombineShares`), with branch-free GF(2^8) arithmetic. The old keycore
  copy branched on share bytes during recovery.

### Removed: general key escrow workflow
- **Removed the "Key Recovery & Escrow" tab and keycore's `/escrow/*` and
  `/enterprise/escrow/*` endpoints** (guardians, policies, escrowed keys,
  recovery requests, Shamir split/verify, escrow tiers).
- **Why:** it kept records only. Escrowing a key stored its name, not its
  material, and an approved recovery released nothing.
  - Guardian votes took `guardian_id` from the request body, so any caller
    could approve as any guardian.
  - `tenant_id` also came from the body.
  - None of the actions was audited.
- Keycore migration 022 drops the four escrow tables and the `escrow_tier` /
  `escrow_shamir` control records.
- The `keycore.escrow_tier` preview entry is gone.
- BitLocker recovery-key escrow (EKM) is a separate feature and stays.

## [1.3.0-beta] — 2026-09-26

### Versioning
- **Build info in the dashboard.** An ⓘ button next to the header clock shows
  the running version, git commit (`-dirty` if built from uncommitted code)
  and build time, so you can tell at a glance which build is deployed.
  - `deploy-local.sh` and `install.sh` pass `VECTA_COMMIT` and
    `VECTA_BUILD_TIME` as dashboard build args; `VECTA_VERSION` comes from
    `VERSION`.
- **Every KMS change bumps the minor version.** `scripts/check-docs.sh` fails a
  change to code or deployment unless `VERSION` has a higher MINOR (or MAJOR)
  than the base branch and `CHANGELOG.md` has a section for it.

### Development moves entirely to KMSBeta
- Nothing is developed in the KMSExtension repo any more. Features cut from
  the core are removed and stay recoverable from git history.
- The Edge & IoT preview now says "there is no edge runtime" instead of
  pointing at KMSExtension.

### HSM: activity log, create alerts, provenance, partition view, HSM CAs
- **HSM activity in the HSM tab.** Every HSM operation and refusal was
  already audited (`audit.hsm.*` from the connector, `audit.key.hsm_*` from
  keycore). The HSM tab now lists them, and the Audit Log's service filter
  has "hsm". `GET /svc/audit/events` takes `action_prefix` (repeatable,
  matched literally).
- **Alerts when creating keys and CAs.** If the tenant has HSM keys on, the
  create-key form says so, and **Create in HSM** starts checked for
  algorithms the HSM supports (unsupported ones hide the box). The create-CA
  form offers **Key storage: in the tenant's HSM** for ECDSA CAs. Importing
  into the HSM stays refused.
- **One HSM per tenant.** A tenant's HSM profile names one PKCS#11 slot; use
  the vendor's HA or cluster behind that slot for redundancy. Each HSM key
  now records the device that generated it (`hsm_serial`, `hsm_token`,
  `hsm_model`, `hsm_manufacturer` labels and in `audit.key.create`). If the
  profile later points at a device without the key, operations answer
  `409 hsm_key_not_found` naming the recorded serial, not a generic error.
  Rotating onto a different device emits `audit.key.hsm_device_changed`.
- **Verify in HSM** (key details, `GET /svc/keycore/keys/{id}/hsm`) reads
  the key back from the HSM: its label, and the HSM's own flags that it was
  generated on the token (`CKA_LOCAL`), is sensitive and was never
  extractable. Tests assert those attributes for AES, RSA and ECDSA keys.
- **Show HSM partition** (Keys and Certificates tabs,
  `GET /svc/keycore/hsm/objects`) lists what is in the tenant's partition,
  including keys and certificates that were there before the KMS. Other
  tenants' KMS objects are hidden. Read-only for now: existing objects can't
  yet be adopted as KMS keys.
- **CA keys in the HSM are real now.** The certs "HSM-backed" key backend
  stored a software key like the default one. `key_backend: "hsm"` now
  generates the CA key in the tenant's HSM through keycore (ECDSA
  P-256/P-384), and certificates, CRLs and OCSP responses are signed there.
  Keycore sign takes `prehashed: true` for HSM keys. CAs created as
  "HSM-backed" before were stored as `keycore` and keep working as the
  software keys they always were; the CA list now labels them "Software key,
  keycore co-signed".
- **Tests:** the audit `action_prefix` filter is also proven on Postgres
  (`TestQueryEventsByActionPrefixPostgres`, now in CI `integration-postgres`).
- **No fake CRLs.** When CRL signing failed, certs published a JSON note
  wrapped in `X509 CRL` PEM headers. It now fails and emits
  `audit.cert.crl_generation_failed`.

### HSM integration: real PKCS#11, per-tenant key and HSM-resident keys
- **New `hsm-connector` service.** It loads the customer's own PKCS#11
  library: Securosys Primus, Thales Luna, Entrust nShield, Utimaco, AWS
  CloudHSM, or any PKCS#11 v2.40+ HSM. It is the only process that holds
  the HSM PIN. Before this, the HSM tab only stored a profile and nothing
  ever used the HSM. The compose entry pointed at an image that was never
  built.
- **HSM tab → KMS integration (per tenant):**
  - **Test connection** shows what the connector really logged in to
    (manufacturer, model, token, firmware).
  - **Tenant key in HSM:** the tenant gets its own AES-256 key inside the
    HSM, and every new key's material is encrypted by it. Existing keys keep
    the KMS master key.
  - **HSM keys:** the create-key form offers **Create in HSM**. The key is
    generated in the HSM (AES-GCM, RSA-PSS, ECDSA P-256/P-384), never leaves
    it, and its encrypt, decrypt, sign and verify run there. Export, wrap
    and derive are refused (`409 hsm_operation_unsupported`). Rotation
    creates a new HSM key, and destroy removes the objects from the HSM.
- **Tenant isolation:** every HSM object is labelled `vecta:<tenant>:...`,
  and the connector refuses other tenants' labels, even on a shared
  partition. Only keycore and governance may use HSM keys. Libraries load
  only from the provider workspace, and PIN variables must be named `*PIN*`.
- **HSM-bound governance backups are now wrapped by the HSM**, under the
  tenant key. `BACKUP_HSM_WRAP_SECRET` is gone (it was never passed to
  governance in compose, so HSM-bound backups failed there). Migration 014
  retires the secret-derived v2 packages.
- **Removed "Vecta KMS HSM":** the menu entry is now "Securosys Primus HSM".
  The unused `software-vault` "software HSM" service is removed, along with
  `SOFTWARE_VAULT_PASSPHRASE` (recoverable from git history before commit
  `091109c`).
  `hsm_mode: software` now means no HSM. `hardware` starts `hsm-connector`
  and `hsm-integration` (the library upload, which no deployment profile
  used to start).
- **Removed a dead "HSM-backed" checkbox** from the create-key form (it was
  hard-wired to unchecked).
- **Docs:** `docs/GETTING_STARTED.md` §4.6 listed environment variables and a
  `vecta-kms hsm verify` command that don't exist, and it's rewritten. The
  cloud examples no longer describe a "Vecta HSM".
- **Tests** run against SoftHSM2, a real PKCS#11 library installed in CI.
  Vendor hardware hasn't been tested from this repository; see
  docs/SECURITY/HSM_INTEGRATION.md, "Not yet validated".
- **New audit events:** `audit.hsm.*`, `audit.key.hsm_settings_updated`,
  `hsm_refused`, `hsm_objects_destroyed`, `hsm_destroy_failed`.

### Security: governance system administration without a token
- **Governance ran without verifying tokens.** It read its verification key
  only from `GOVERNANCE_*` / `KEYCORE_*` variables or a key file, never from
  the shared `JWT_PUBLIC_KEY_B64` that compose sets. When the key was
  missing, it logged "jwt parser disabled" and admitted every
  system-administration request that sent `tenant_id=root`. In a standard
  compose deployment, anyone who could reach governance could list, download
  or restore backups, change the FIPS mode, and change settings, network and
  FDE state.
- **Fixed:** governance reads the shared key and **refuses to start** without
  one (`refusing to start: no JWT verification key`). System administration
  needs a verified root administrator.
- **Service callers:** keycore and policy (reading `GET /governance/system/state`)
  and posture (writing `PUT /governance/system/posture-controls`) had called
  without a token. They now use their own service identities
  (`kms-keycore`, `kms-policy`, `kms-posture`). Governance admits each only on
  that route. keycore and policy now read the platform state as
  `tenant_id=root`: governance only serves root, so per-tenant reads had
  always been refused with 403.
- **New audit events:** `audit.governance.system_admin_refused` for every
  refusal (`reason`: `authentication_required`, `tenant_required`,
  `tenant_mismatch`, `not_root_tenant`, `token_tenant_not_root`,
  `insufficient_privileges`), and `audit.governance.authentication_refused`
  (`invalid_token`). Governance events now carry `result: refused` at the top
  level too, not only in `data`.
- **Operators:** make sure governance gets `JWT_PUBLIC_KEY_B64` (compose
  already requires it) and `INTERNAL_SERVICE_BOOTSTRAP_SECRET` for keycore,
  policy and posture. `POSTURE_GOVERNANCE_BEARER_TOKEN` still overrides
  posture's identity.

### Security: governance backup keys
- **Software-mode backup keys were stored in plaintext** next to the
  encrypted artifact, so anyone who could read the database (or a dump of
  it) could open every such backup. **Fixed:** the key file is returned once,
  in the `POST /governance/backups` response (`key_file`), and the dashboard
  saves it the moment the backup is created. The platform keeps only its
  fingerprint. `GET /governance/backups/{id}/key` answers
  `410 backup_key_not_retained` for these backups.
- **HSM-bound backups wrapped their key under a raw SHA-256** of the wrap
  secret and binding. **Fixed:** the wrap key is HKDF-SHA256
  (`key_derivation: "v2"`), and `BACKUP_HSM_WRAP_SECRET` must be at least 32
  characters. v1 key packages are refused on restore.
- **Breaking:** migration 013 removes the stored keys of existing backups
  (plaintext software keys and v1 wrapped keys). Those backups restore only
  with a software key file saved before the upgrade. No backups had been
  taken on the old version. The hourly job that re-sealed stored backups
  (unreleased) is removed; contents are re-wrapped at capture instead.
- New audit events: `audit.governance.backup_create_refused`,
  `backup_key_downloaded`, `backup_key_download_refused`
  (`reason: key_not_retained`). The backup's creator is now taken from the
  verified token. Tenant-scope HSM-bound restores use the target tenant's
  binding, as the backup did.
- Details: [docs/SECURITY/BACKUP_KEYS.md](docs/SECURITY/BACKUP_KEYS.md).

### Security: keycore trusted identity headers for key access
- **A caller could grant itself access to keys.** When the token lacked a
  field, or there was no token, keycore filled the caller's user, role,
  permissions and groups from `X-Actor-*` / `X-KMS-Subject` headers. A token
  with no permissions plus `X-Actor-Permissions: *` or `X-Actor-Role: admin`
  was treated as an admin for encrypt, decrypt, sign, export and other key
  operations. `X-Actor-Groups` matched group grants, a header user ID alone
  counted as authenticated, and `X-KMS-Interface` moved a request under
  another interface's subject policies.
- **Fixed:** key access is decided from the verified token only. Group
  membership comes from the store, keyed by the verified user. Every HTTP
  caller is evaluated as the `rest` interface. The headers are kept only as
  unverified audit context.
- **New audit events:**
  - `audit.key.access_refused` for every key-access denial (`result:
    refused`, with `reason`, the verified actor and any headers it sent);
  - `audit.key.actor_headers_ignored` whenever a request carries identity
    headers.

  Key-operation endpoints now answer a denial with `403 access_denied`
  instead of `400 <op>_failed`.
- **Operators:** check for `audit.key.actor_headers_ignored`. No platform
  service sends these headers, so any hit is a stale integration or an
  attempt to spoof.
- **No anonymous key use (breaking for token-less integrations).** A request
  with no token could use any key that had no grants, unless the tenant had
  enabled deny-by-default. Every key operation now needs a verified token:
  otherwise `403 access_denied`, audited as `audit.key.access_refused` with
  `reason: authentication_required`. The creator, admins and service
  identities are unaffected.
  - Keycore now refuses to start without the key that verifies tokens
    (`JWT_PUBLIC_KEY_B64`, which compose already requires); before, it
    started without it and couldn't identify anyone.
  - Two platform callers relied on anonymous access and now use service
    identities:
    - compliance playbooks (rotate, status and destroy key actions, and the
      certs, policy, audit and auth actions) call as `kms-compliance`. The
      token is sent only to those service hosts, never to webhooks or
      external URLs.
    - reconciler's key-lifecycle calls carry the new `kms-reconciler`
      identity and, for the first time, the key's `tenant_id`. Keycore
      rejected those calls before for the missing tenant, so scheduled
      rotation and deactivation now actually run.

### Security: stored secrets, CA keys, cloud credentials and BitLocker keys were under public keys
- **Every deployment was affected.** secrets, certs, cloud and ekm wrapped
  their stored data under keys derived from strings in the source code
  (`SHA-256("vecta-<service>-dev-mek")`; cloud could also use
  `0123456789ABCDEF…`), because their `<SERVICE>_MEK_B64` was never set. A
  copy of the database or a backup was enough to decrypt stored secret
  values, legacy-format CA signing keys, cloud provider credentials and
  BitLocker recovery keys.
- **Master keys now come from keycore; there is nothing to configure.** Each
  service derives its key from a keycore system key bound to its own
  identity. Plain `docker compose up` works. Cluster members derive the same
  key with nothing to copy. Keycore refuses to destroy, disable, delete a
  version of, or export a system key (`409 system_key_protected`); rotate it
  and restart the service to re-key. These four services now need keycore
  (and policy) up to start; they retry for 10 minutes.
- **Automatic migration:** on the primary, every row under a public or old
  key is re-wrapped before the service serves, and again every 15 minutes, so
  restored rows are caught. A row that can't be rewritten blocks the start.
  Values and ciphertext are unchanged.
- **Backups:** a new backup's contents are re-wrapped through the owning
  service at capture, and a restore's before any row is written. A clean
  backup never needs the services; an affected one is refused, with nothing
  written, if its service can't re-wrap. (Backup keys: see the next section.)
- **Exposure register (action needed):** re-wrapping can't change copies
  made before the upgrade (database dumps, snapshots, downloaded backup
  files). Every item that was under a public key is listed under
  **Administration → Tenant → Security → Key exposure register**
  (`GET /svc/<service>/mek/exposure`), with how to fix it. An entry closes
  itself when the material is replaced:
  - a secret is rotated or deleted;
  - a CA is replaced;
  - a cloud account is re-registered;
  - a BitLocker volume is rotated.

  An administrator can also acknowledge an entry with a reason. **Rotate the
  listed material if anyone may have had an older copy.**
- New audit events: `audit.<svc>.dev_mek_rewrapped`, `mek_rewrapped`,
  `*_rewrap_refused`, `mek_unreadable`, `mek_check_refused`,
  `mek_exposure_remediated`, and `audit.key.system_key_*`.
- **Dashboard:** a 403 no longer signs the user out; only 401 does (a
  missing permission, such as `secrets.read`, is not an expired session).
- The new conformance rule `no-literal-key-material` fails any key derived
  from, or set to, a string literal.

### Platform kernel: audit, tenancy and permissions for every route
- **New `pkg/route` kernel.** A route is registered with its audit action and
  required permission. The kernel then authenticates the caller, enforces
  one tenant, checks the permission, and emits a specific
  `audit.<service>.<action>` event for every request, including failures and
  refusals (`result: refused`, with `reason`). A route without an action or
  permission stops the service at startup. See
  [docs/PLATFORM_CONTRACT.md](docs/PLATFORM_CONTRACT.md).
- **`make conformance` fails on new raw `http.ServeMux` routes.** 31 legacy
  handler files are on a shrink-only burn-down list
  (`scripts/route-kernel-burndown.txt`); the plan is in
  [docs/ARCHITECTURE_MIGRATION.md](docs/ARCHITECTURE_MIGRATION.md).
- **Secrets service migrated (reference service).**
  - **Security fix:** `POST /secrets`, `/secrets/generate/*` and the Vault
    KV write took `tenant_id` from the request body without checking it
    against the token, so a caller could create secrets in another tenant.
    This is now refused (`403 tenant_mismatch`) and audited.
  - **Breaking: permissions are now required.** `secrets.read` (metadata,
    versions, stats, audit trail), `secrets.value.read` (value and Vault KV
    reads), `secrets.write` (create, update, rotate, generate, Vault writes)
    and `secrets.delete`. `admin` / `tenant-admin` (`*`) and activated API
    clients (`kms.read` / `kms.write`) are unaffected. Other roles need these
    permissions granted.
  - **Tenant resolution:** when no tenant is named, the token's tenant is
    used. Vault clients without a namespace no longer fall into a tenant
    called `default`. Conflicting tenants in query, header and body are
    refused (`403 tenant_conflict`).
  - `created_by` / `updated_by` record the verified caller, not the value in
    the request body.
  - **Audit events:** each request emits exactly one event, carrying actor,
    target, correlation ID and outcome, including failures and refusals.
    New actions: `audit_log_read`, `stats_read`, `vault_kv_read`,
    `vault_kv_written`, `vault_kv_deleted`, `vault_metadata_read`,
    `vault_token_lookup`, `vault_health_read` and `vault_seal_status_read`.
    Key generation now emits one `generated` event instead of `created`
    plus `generated`.

### Clustering (slice 3a of 5): write forwarding
- **Any node takes any request.** On a member:
  - crypto operations, reads, logins and audit run locally;
  - key, policy and configuration changes are forwarded to the primary and
    answered as if made there (`X-Vecta-Forwarded-To`);
  - if the primary is unreachable or its certificate doesn't match the pin,
    the write fails with `502 primary_unreachable` and nothing changes.

  Every service gets this through `pkg/config`.
- **Forwarding security:**
  - the member verifies the caller;
  - the primary authenticates the member by a credential issued at join
    (hash stored, revoked when the node is removed);
  - the primary's auth mints a 5-minute token (`POST /auth/cluster/mint`,
    cluster-manager only);
  - every forward and refusal is audited on both sides (five new events).
- **Members no longer write replicated data.** Such writes would have diverged
  the member or stopped replication:
  - keycore operation counts go to the node-local `key_op_counters` (limits
    still enforced);
  - scheduled jobs run on the primary only (compliance, reporting, posture,
    SBOM, certs sweeps and mesh discovery, approval expiry, the dataprotect
    receipt reconciler);
  - dataprotect working-key state isn't recorded on members;
  - `fle_metadata` is node-local.
- **Cluster tab** shows when the node is a member and which primary it
  forwards to (`forwards_to` in replication status).

### Fixes
- **Key import rejected about 2% of valid keys.** Keycore trimmed
  "whitespace" from binary DER. A key whose encoding started or ended with
  byte 0x09–0x0d or 0x20 lost that byte and failed with "unsupported DER" or
  "PEM payload does not contain a supported key block". DER is now parsed
  untrimmed (`TestImportDERWithWhitespaceBoundaryBytes`).


## [1.2.0-beta] — 2026-09-25

### Clustering (slice 2 of 5): secure join
- **Join a second KMS from the UI.** Platform → Cluster → Add Instance issues a
  one-time join bundle on the primary; pasting it on the new node joins it.
  - The master key moves keycore-to-keycore under ML-KEM-768 and never exists
    in plaintext outside keycore.
  - The member gets a replication role limited to its components.
  - Replication credentials are sealed to the member.
  - The primary's TLS certificate is pinned from the bundle.
  - Every step is audited.
- **Node-local identities never replicate:** the node's own admin/CLI accounts
  and internal service identities (auth migration 011: `node_local` plus
  publication row filters).
- **Security fix: cluster-manager had no authentication.** It now requires a
  root administrator or an internal service identity on every admin route.
  The node-to-node routes authenticate themselves.
- **Postgres worker limits:** raised so a member can replicate every
  component. The defaults left all but one component stuck in the initial
  copy.
- **Removed the old "Add Instance" dialog**, which recorded a node without
  joining it and reported "added to cluster".

### Clustering (slice 1 of 5)
- **Removed a false claim.** The Cluster overview and dashboard said nodes
  synchronized component state, but no node ever applied another node's data.
  Status now comes only from the database (`GET /cluster/replication/status`,
  and the Cluster tab shows per-component sync state and lag).
- **Replication engine:** Postgres logical replication with one publication
  per component; members subscribe only to their assigned components
  (`pkg/clusterrepl`). Proven between two real Postgres servers: assigned
  components copy and stream; node-local tables and unassigned components
  don't (`scripts/test-cluster-replication.sh`).
- **Every table classified:** replicated per component, node-local (50, each
  with a reason) or shared-append (`pkg/clustercatalog`), enforced by test.
- Postgres runs with `wal_level=logical`.
- Joining a node, write forwarding, failover and the Helm chart follow in
  slices 2–5 (`docs/CLUSTERING.md`).

### Security
- **Audit coverage for this refresh.** New events:
  - service-key revocation and retirement in auth;
  - per-service FIPS mode application and rollout completion (restart-safe);
  - reserved-prefix derive attempts (critical);
  - SHA-1 OCSP refusals in strict mode;
  - dataprotect key-derivation refusals.

  The full catalogue, including what can't be audited (startup refusals), is
  in `docs/SECURITY/AUDIT_EVENTS_2026-09.md`. `docs/API_REFERENCE.md` now
  documents `service-derive`, the `/kdf/keys` migration API, the
  `X-Vecta-KDF-Version` header and the governance `fips-mode` API. Governance
  migration 011.
- **Audit coverage completed for this work.**
  - **Governance:** refused backup restores are now audited
    (`audit.governance.backup_restore_refused`, with the reason).
  - **Backup scheduler:** emits `audit.backup.policy_created`, `_updated` and
    `_deleted`, plus `run_refused_preview` and `restore_refused_preview`.
  - **keycore:** enterprise control events carry `feature_status`.
  - **Docs:** the audit subject reference in `docs/API_REFERENCE.md` is
    corrected to the subjects the code actually emits.
- **Fixed: signing verification always failed.** `VerifyArtifact`
  re-marshalled the envelope from JSONB, whose key order differs from the
  signed bytes, so no artifact ever verified. The exact signed bytes are now
  stored (`envelope_b64`), and older records are rebuilt in their original
  field order. Verify also takes the artifact (`payload` or `digest_sha256`) and
  reports `signature_valid`, `digest_checked` and `digest_match`, where before
  it only re-checked the stored record.
- **Fixed: one KMIP request could crash the KMIP service.** A role-denied
  operation (for example `kmip-client` Revoke) made a middleware return a nil
  response, which kmip-go dereferenced. Denials now return a failed batch item,
  and a recovery middleware turns any operation panic into a KMIP error.
- **Fixed: KMIP ignored object lifecycle state.** Revoked (deactivated) keys
  still encrypted and destroyed keys were still returned by Get. Protecting
  operations now require Active, processing operations allow Active,
  Deactivated or Compromised, and Get refuses destroyed objects (KMIP 1.4).
- **Preview features are labelled everywhere** (`pkg/features`,
  `docs/PREVIEW_FEATURES.md`).
  - **Which:** federation, binding policies, sharing grants, metadata profiles,
    escrow tiers, edge, advanced-encryption modes, audit-chain anchors and the
    backup scheduler store configuration without enforcing it.
  - **How they are labelled:** responses carry `X-Vecta-Feature-Status:
    preview`, records carry `feature_status`, and the dashboard shows Preview
    (Docs page, Backup tab banner).
  - **Enforcement:** conformance keeps the Go and dashboard lists identical.
- **Removed fabricated data.**
  - **Backup scheduler:** it simulated backups (random key counts, a fake
    checksum, a no-op restore). Run and Restore now return `409
    feature_preview`, and past runs and restore points are relabelled
    `simulated`.
  - **Audit-chain anchors:** they no longer claim a Merkle root or "anchored"
    status (keycore migration 018).
  - **Command Center:** the backup check uses governance's real encrypted
    backups.
  - **`RECOMMENDED_FEATURES.md`:** no longer claims "5/5 production-ready", or
    QKD/QRNG/MPC (which moved to KMSExtension).
- **New tests:**
  - **Postgres integration** (CI job `integration-postgres`): governance backup
    create/restore round trip and tamper refusal (ciphertext, key, scope/AAD,
    file type); signing sign/verify, tampering and policy gates; backup
    scheduler preview behaviour.
  - **KMIP over real TLS:** certificate authentication, tenant isolation, key
    lifecycle, role denial.
  - **FIPS mode is now changed in the KMS UI**, not at deployment.
  - **Where:** System Administration → Runtime Crypto → Platform FIPS 140-3
    mode (root admins).
  - **Before confirming:** the dialog lists the features that stop and start
    working in the target mode and the services that will restart, then asks
    for a typed confirmation and a reason. The change is audited as
    `audit.governance.fips_mode_changed`, with severity critical for a
    downgrade.
  - **Applying it:** services restart themselves gracefully in tiers (edge
    first, core services, then governance) and come back in the new mode by
    re-executing with the matching `GODEBUG`.
  - **Progress:** the dialog shows each service's actual mode until all match
    (about 1–2 minutes).
  - **Deployment variable:** `VECTA_FIPS_MODE` now only seeds the initial
    mode, and the installer no longer asks.
  - New API: `GET/PUT /governance/system/fips-mode` and
    `GET /governance/system/fips-mode/impact`. Governance migration 010.
- **Fixed predictable data protection keys.** dataprotect derived tokenization,
  FPE, masking, field, envelope and searchable-encryption working keys from
  the key's public KCV, because keycore never returns key material to it.
  - **keycore:** new `POST /keys/{id}/service-derive` (service identities only;
    HKDF over key material, bound to service, tenant, key, pinned version and
    purpose; audited as `audit.key.service_derive`). Generic `/derive` can't
    reproduce these subkeys.
  - **dataprotect:** derives every working key through service-derive (v2).
    Keys created after this release are v2 from birth. Existing keys stay
    readable in state `legacy`, with every legacy use audited, until an
    operator migrates them: `/kdf/keys/{key_id}/start-migration` → re-protect
    (`X-Vecta-KDF-Version` dual-read, `reprotect-vault` for stored tokens) →
    `/complete`.
  - **After migration:** identifier-derived keys are refused in every FIPS
    mode, and strict mode refuses them outright.
  - **Stored tokens:** vault tokens record their derivation version (migration
    011); token strings don't change.
  - **Dashboard:** a new Working-Key Derivation panel under Data Protection.
  - See `docs/SECURITY/DATAPROTECT_KEY_DERIVATION.md`.
- `pkg/crypto.HKDFSHA256` now uses the FIPS-module `crypto/hkdf` (identical
  output, covered by a compatibility test).
- **FIPS 140-3 on the certified Go Cryptographic Module; mode is the
  customer's choice.**
  - **Build:** every binary builds with `GOFIPS140=v1.0.0` (CMVP-certified
    snapshot).
  - **Runtime choice:** `VECTA_FIPS_MODE` = `on` (default) | `only` (strict) |
    `off`, set in the installer or `.env` and passed to Go as
    `GODEBUG=fips140`. Services refuse to start if the runtime doesn't match
    or the module isn't certified.
  - **Honest reporting:** governance and the dashboard report the real mode
    and claim "validated" only for the certified module in FIPS mode. The
    dashboard no longer shows made-up library versions.
  - **Crypto changes:** AES-GCM now uses module-generated IVs everywhere
    (`pkg/crypto`, keycore, keycache, archival, certs, software-vault), with
    stored formats unchanged and legacy data still decrypting.
  - **Strict mode:** it refuses X25519, ChaCha20, SHA-1, DES/TDES,
    caller-supplied GCM IVs, OpenPGP v4 and non-module ML-DSA/SLH-DSA with
    clear errors instead of panics.
  - **Testing:** CI runs the suite in all three modes.
  - See `docs/SECURITY/FIPS.md`.
- Fixed: the certs OCSP responder answered every request with a SHA-1 CertID
  regardless of the request's hash (RFC 6960). It now echoes the request's
  hash algorithm.
- Conformance allowlist burn-down: 7 → 4 files. keycore archival and
  self-test, and software-vault, now use `pkg/crypto`.
- **Closed a service-impersonation loophole.** `INTERNAL_SERVICE_BOOTSTRAP_SECRET`
  defaulted to a public placeholder (and `install.sh` never generated it), so
  anyone could derive every internal service's API key. Compose now requires
  the secret. `servicetoken.ValidateBootstrapSecret` rejects the placeholder and
  secrets shorter than 32 characters. Auth refuses to start on a weak value and
  revokes service keys derived from the placeholder on startup. `install.sh` and
  `run-local.sh` generate the secret.
- Rotating `INTERNAL_SERVICE_BOOTSTRAP_SECRET` now works: on start, auth
  retires every service API key derived from a previous secret, and
  `scripts/rotate-secrets.sh` rotates it.
- Placeholder secrets are rejected. `.env.example` values such as
  `your-workload-identity-secret` had been accepted as real secrets (and
  `deploy-local.sh` copied them into new `.env` files). `.env.example` now
  ships every secret empty. Every service refuses to start with a `your-...` /
  `change-me` secret (`pkg/config`). `deploy-local.sh` refuses placeholders and
  generates every missing secret, including the auth JWT signing key.
  `POSTGRES_PASSWORD` is now required by compose.
- No built-in database credentials. `pkg/config` no longer falls back to
  `postgres://postgres:postgres@localhost…`, and `pkg/db` requires
  `POSTGRES_DSN`. Services refuse a DSN whose password is empty, equals the
  username, is a vendor default or is a placeholder. `run-local.sh` builds the
  DSN from `.env`. Conformance bans `user:pass@` URL literals in Go and compose.
- Bootstrap admin default password is now `changeit` (forced change on first
  login, unchanged). The CLI user no longer falls back to the hardcoded
  `VectaCLI@2026`; unset means a random password.
- `make conformance` rule 3 (secure defaults) fails the build on any secret
  with a hardcoded fallback in compose or Go. See
  `docs/SECURITY/SECURE_DEFAULTS.md`.

### Process
- Documentation now ships with every change. `CLAUDE.md` holds the standing
  engineering rules and a table of where each kind of change is documented.
  `docs/DECISIONS.md` records design decisions and rejected alternatives. The
  CI job `docs-with-change` (`scripts/check-docs.sh`) fails a pull request
  that changes code without a CHANGELOG, learning, decisions, security or
  CLAUDE.md update. `make conformance` now also runs in CI.

### Fixed
- `install.sh` failed to parse on macOS's bash 3.2 (`syntax error near
  unexpected token ';;'`). The cause was PowerShell quote-escaping
  (`${var//\'/''}`) inside `$(...)`. It's replaced with a `ps_quote` helper,
  and conformance now runs `bash -n` over every shell script.
- **Fixed a cross-tenant authorization flaw in the (unreleased) service-to-service
  JWT work.** Service principals were recognised by role `client-service`
  alone, but *every* external client-credentials token carries that role, so
  any registered client could have bypassed tenant binding and per-key grants.
  A caller is now a service principal only if its verified JWT has role
  `client-service` **and** the reserved `service.internal` permission **and** a
  `kms-*` client id **and** the internal service tenant. The reserved
  permission is stripped from API-key creation, tenant-role writes, user login
  tokens and client-token requests from non-service clients; only the auth
  bootstrap can grant it. keycore decides service-principal status from JWT
  claims only (never from `X-Actor-*` headers). Covered by
  `pkg/tenantcheck/service_principal_test.go` and verified end-to-end.
- Service JWTs are now attached on internal keycore calls from autokey, certs,
  cloud, compliance, dataprotect, discovery, ekm, hyok, kmip, payment, pqc, sbom
  and signing (`servicetoken.SetDefault`), still non-enforcing (phase 3 of 4).
- Go vulnerabilities: **29 → 0** reachable (`govulncheck`). Toolchain
  1.26.0 → 1.27.1 fixes 25 stdlib advisories (crypto/x509, crypto/tls,
  net/http, html/template, net/url, encoding/asn1, encoding/xml, os);
  `golang.org/x/text` 0.39; gRPC pinned to the upstream fix for GO-2026-6443 /
  GO-2026-6348 / GO-2026-6061; unmaintained `golang.org/x/crypto/openpgp`
  replaced by `github.com/ProtonMail/go-crypto` in the secrets service.
- Dashboard: `npm audit` reports 0 vulnerabilities (previously 8 advisories, including high-severity ones in postcss, nanoid, browserslist and brace-expansion).
- Internal service ports (every `8xxx`/`18xxx`, NATS, Valkey, Consul, etcd) are
  now published on `127.0.0.1` only (`KMS_INTERNAL_BIND`); only Envoy
  (80/443/5696) listens on all interfaces. Previously Valkey, NATS and every
  service's HTTP/gRPC port were reachable from the LAN.

### Added
- **Security Command Center** home page and **Recommendations** page: live
  posture score, KPIs and ~30 rules over keys, certificates, access control,
  rotation, backups, cluster, posture and PQC state, each mapped to NIST SP
  800-57 / 800-131A / IR 8547, PCI DSS 4.0, DORA, CNSA 2.0 and CA/B Forum.
  Unassessable sources are shown as "not assessed" — never guessed. See
  [docs/RECOMMENDATIONS.md](docs/RECOMMENDATIONS.md).
- `deploy-local.sh`: one-command, re-runnable local deployment (adds new
  required secrets without touching existing ones, native-arch builds, JWT key
  sync, waits for health, prints the URL).

### Changed
- New design system: **Graphite** (dark) and **Paper** (light) themes — neutral
  surfaces, a single accent, colour reserved for status, larger type (11–14 px
  instead of 9–10 px), no gradients/neon glow. All modules inherit it through
  the existing tokens.
- Navigation: task-oriented groups in sentence case, sidebar module filter,
  breadcrumb in the top bar, search-first ⌘K button; duplicate user/logout pill
  removed from the top bar.
- Go 1.27.1; all Go modules updated (`go get -u ./...`); dashboard deps
  updated (React 19.3, Vite 8.3, Vitest 5, TanStack Query 5.103, Recharts 3.10,
  lucide 1.48, ESLint 10.11, Playwright 1.63).
- Images: golang 1.27.1, alpine 3.24, node 24.21 LTS, nginx 1.30.5, trivy
  0.74.0, postgres 17.11, pgbouncer 1.25.2, NATS 2.14.7, Valkey 9.0.6, Consul
  1.22.7, etcd 3.6.15, Envoy 1.39.1.
- Dockerfiles build for the host architecture (`TARGETARCH`) instead of forcing
  `amd64` — native arm64 on Apple Silicon instead of emulation — and use
  BuildKit cache mounts, so rebuilds reuse module and compile caches.
  `.dockerignore` now excludes `.gomodcache` (multi-GB) and stray binaries.
- CI: Node 24, actions/checkout v5, setup-node v5, setup-go v6.

### Fixed
- Key Management table showed `-` for Algorithm, Size/Curve and KCV on first
  load (the shell's key catalog dropped those fields).
- Three tabs (Key Analytics, Key Scheduling, Threat Protection) called `fetch`
  directly, failing lint; now use the tracked client.
- A 32 MB `workload` build artifact was committed to the repo; removed and
  ignored.

## [1.1.0-beta] — 2026-06-09

### Added
- Enterprise key-audit tier and enterprise controls + DSPM feed (keycore).
- Post-quantum readiness DSPM finding (`quantum_vulnerable_algorithm`): maps
  in-use classical asymmetric algorithms (RSA/ECC/DH) to a NIST PQC migration
  recommendation.
- Repeatable secret rotation tooling: [`scripts/rotate-secrets.sh`](scripts/rotate-secrets.sh)
  and [`docs/SECURITY/SECRET_ROTATION.md`](docs/SECURITY/SECRET_ROTATION.md).
- Version tracking: `VERSION` file, versioned image tags
  (`vecta/<svc>:${VECTA_VERSION}`), `BUILD_VERSION` stamped into services, and
  this changelog.
- Installer (`install.sh`) now provisions every secret the compose file
  requires — `POSTGRES_PASSWORD`, `NATS_AUTH_TOKEN`,
  `WORKLOAD_IDENTITY_SHARED_SECRET`, `SOFTWARE_VAULT_PASSPHRASE`,
  `INTERNAL_API_TOKEN`, `AUTH_BOOTSTRAP_CLI_PASSWORD` — plus a generated JWT
  signing keypair (public key in `.env`, private key seeded into the auth
  volume) and `VECTA_VERSION`. Image presence checks are version-aware.
- FeatureForge wired through the full deployment surface: `feature_forge` is
  now in the installer `FEATURE_KEYS` registry (data-driven features block, so
  it flows into `recommended`/`all`/`custom` profiles automatically); its
  tenant-scoped `ff_*` tables are surfaced in governance backup coverage under
  the `feature_intent_classification_and_promotion_governance` capability; and
  it is a first-class HA replication component (in `cluster-profile-full`).
- Custom HA cluster profile: `install.sh` can build a `cluster-profile-custom`
  by selecting individual services to replicate; the selection is passed via
  `CLUSTER_BOOTSTRAP_COMPONENTS` and seeded by cluster-manager. Core services
  (auth, keycore, policy, governance) are always replicated.
- `deployment.schema.json` updated to accept `metadata.install_mode` and the
  `spec.cluster_bootstrap` block (mode, replication_profile_id,
  replication_components, join_endpoint, join_token) that the installer emits.

### Changed
- Refreshed dashboard UI: centered minimal login (static brand glyph, reduced
  motion) and a premium dark-theme polish.
- Dependencies pinned to verified latest-stable registry versions (Go + npm).
- Dashboard ESLint debt cleared; `npm run lint` passes at `--max-warnings=0`.
- REST API catalog regenerated (945 routes) to match current services.

### Fixed
- Consolidated the worktree into a single package; replaced fabricated
  dependency versions that did not resolve on the public registries and left
  the tree un-buildable.
- Stopped tracking `.env` (it had leaked dev secrets); secrets rotated.
- Excluded `.git` (~900MB) and local state from the Docker build context via
  `.dockerignore`; it was being shipped to the daemon on every root-context
  service build and dominated (and stalled) image builds.

### Security
- Removed fabricated "security scan" reports that cited non-existent versions
  as safe; replaced with honest stubs pointing to real tooling
  (`govulncheck` / `npm audit` / `osv-scanner`).
- All tenant-scoped HTTP services require JWT; reconciler endpoints gated behind
  a shared internal token.

## [1.0.0-beta] — prior
- Initial beta: 30+ Go microservices, React dashboard, KMIP, PQC primitives,
  FIPS 140-3 target. See git history before `v1.1.0-beta`.
