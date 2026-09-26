# Changelog

All notable changes to Vecta KMS are recorded here. Versions follow the
`MAJOR.MINOR.PATCH[-beta]` scheme; the canonical version lives in the
[`VERSION`](VERSION) file and is published as a git tag (`vX.Y.Z`).

## [1.2.0-beta] — 2026-09-25

### Security: secrets were stored under a public key
- **Every deployment's secrets service wrapped stored secrets under a key
  derived from a string in the source code.** It fell back to
  `SHA-256("vecta-secrets-dev-mek")` when `SECRETS_MEK_B64` was unset, and no
  installer or compose file ever set it. Anyone with the repo and a copy of
  the database or a backup could decrypt every stored secret.
- **`SECRETS_MEK_B64` is now required** (base64 of 32 random bytes). The
  service refuses to start if it's missing, isn't exactly 32 bytes, is
  patterned, or is the old public key. Compose requires it, and `install.sh`,
  `deploy-local.sh` and `run-local.sh` generate it. **Upgrading with plain
  `docker compose up`** now stops with `SECRETS_MEK_B64 is required`: run
  `./deploy-local.sh`, or add `SECRETS_MEK_B64=$(openssl rand -base64 32)` to
  `.env`.
- **Automatic migration on the first start with a real key:** every value
  under the public key has its data key re-wrapped under `SECRETS_MEK_B64`.
  Values stay readable and their ciphertext is unchanged. Each tenant gets
  `audit.secrets.dev_mek_rewrapped`, listing the affected secrets. A value
  that can't be rewritten blocks the start (`dev_mek_rewrap_refused`) and is
  retried on the next start. **Action for operators:** database copies and
  backups made before this upgrade can still be decrypted with the public
  key. Treat the listed secrets as exposed to anyone who had such a copy, and
  rotate them at their source.
- **MEK rotation is now supported:** `rotate-secrets.sh` moves the old key to
  `SECRETS_MEK_PREVIOUS_B64`, and the service re-wraps on start
  (`audit.secrets.mek_rewrapped`). A wrong key stops the start
  (`mek_check_refused`) instead of failing every read. **Cluster members must
  use the primary's `SECRETS_MEK_B64`**, since the join doesn't transfer it.
- **New conformance rule `no-literal-key-material`:** no key derived from, or
  set to, a string literal in `services/`. It found the same defect in certs,
  cloud and ekm (dev MEK fallbacks, and in cloud a hardcoded
  `0123456789ABCDEF…` key). Those are listed in the shrink-only
  `scripts/literal-key-burndown.txt` and are **not fixed yet**.

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
