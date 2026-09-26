# Decisions

The approaches this product is built on, and why. Newest first. Add an entry
whenever you choose between real alternatives, so the choice isn't argued again
or quietly undone. Each entry covers the decision, why it was made, what was
rejected, and how it's enforced.

---

## 2026-09-26 — Every KMS change bumps the minor version
**Decision:** any change to code or deployment raises MINOR in `VERSION` (MAJOR
for breaking changes) and adds a matching `## [x.y.z]` CHANGELOG section. The
dashboard shows the version, commit and build time behind the ⓘ button by the
clock.
**Why:** a deployment tagged with an unchanged version can't be told apart from
the previous one. The owner took a current build for a stale one.
**Rejected:** patch bumps (the owner asked for minor); bumping per commit
(granularity is the change being merged, compared with the base branch);
version derived from git only (the `VERSION` file stays the source of truth
for image tags and `BUILD_VERSION`).
**Enforced by:** `scripts/check-docs.sh` (`version-bump`), which fails if
VERSION's MAJOR.MINOR didn't increase over the merge base or the CHANGELOG has
no section for it. Test-only changes are exempt, as for the docs gate.

## 2026-09-26 — One HSM per tenant; partition objects listed, not adopted; HSM CAs are ECDSA
**Decision:**
- A tenant has one HSM profile (one PKCS#11 slot). Redundancy comes from the
  vendor's HA/cluster behind that slot (Securosys, Luna HA groups, nShield
  Security World), not from the KMS choosing among HSMs.
- Each HSM key records the device (serial, token, model) that generated it.
  A key whose object is missing on the configured device is refused with
  `hsm_key_not_found` naming that serial; rotation onto another device is
  audited (`audit.key.hsm_device_changed`).
- Objects already in the partition are listed read-only in Keys and
  Certificates. Adopting them as KMS keys is not built yet.
- HSM CA keys are ECDSA P-256/P-384 only.

**Why:** choosing an HSM per key needs placement rules, per-key routing and
a story for keys that exist on only one device; vendor HA already
replicates keys across devices under one slot. Recording the device makes a
misconfigured profile obvious instead of a generic PKCS#11 error. Adoption
needs decisions about labels, usage flags and extractable keys (an
extractable key isn't HSM-protected in the sense the KMS promises), so it
is listed, not guessed. The HSM signs RSA only with PSS, and OCSP responses
(x/crypto/ocsp) can't carry RSA-PSS.

**Rejected:** several HSM profiles per tenant with a per-key picker
(placement and failover complexity for what vendor HA already does);
silently adopting every partition key (would put keys the KMS didn't create
and can't vouch for under its audit claims); RSA PKCS#1 v1.5 signing in the
HSM for CAs (the connector implements RSA signing with PSS only; adding v1.5 is a separate, reviewable change).

**Enforced by:** `TestHSMKeyProvenance`, `TestPartitionListing`,
`TestGeneratedKeysHaveHSMAttributes`, `TestHSMCAKeysSignInTheHSM` (RSA
refused).

## 2026-09-26 — Customer HSMs through their own PKCS#11 library, in a separate connector
**Decision:** HSMs are integrated through the vendor's PKCS#11 library (owner's
choice over a vendor REST API). The library loads in a dedicated
`hsm-connector` service (cgo, Debian), which keycore and governance call with
their service identities. Per tenant, two switches: a tenant key in the HSM
that protects new key versions (owner: "new keys only"), and HSM-resident
keys created per key. There is no Vecta or software HSM (owner), and
`software-vault` was removed. HSM-bound backups are wrapped by
the tenant key in the HSM.

**Why:**
- One integration serves every vendor that ships a PKCS#11 library, and the
  owner requires real integrations, no fakes.
- Vendor libraries are glibc builds and can't load into keycore's static
  Alpine binary. A separate process also keeps a crashing vendor library and
  the HSM PIN away from keycore.
- A per-tenant key gives each tenant its own root of trust in the HSM
  without moving every operation into the HSM. HSM-resident keys cover the
  keys that must never leave it.

**Rejected:**
- cgo in keycore: glibc libraries, a larger FIPS build surface, and a
  vendor crash would take down the KMS.
- Securosys REST (TSB) API: it covers one vendor, and the owner chose
  PKCS#11.
- Re-wrapping existing keys under the tenant key on enable: the owner chose
  new keys only. Turning it off doesn't touch existing keys either.
- Refusing HSM operations in FIPS `only` mode as "third-party crypto": they
  run in the HSM's own module with approved mechanisms. The KMS doesn't
  claim that module's validation; the customer checks it.
- A software HSM for demos: nothing may pose as an HSM. Tests use SoftHSM2,
  a real PKCS#11 library, only in tests.

**Enforced by:** `pkg/hsmconnector` tests on SoftHSM2 (isolation, callers,
confinement, `routetest.RefusalsAudited`), the keycore and governance HSM
tests through the real connector, `TestHSMStoragePostgres`, and
`TestHSMBoundBackupPostgres` (docs/SECURITY/HSM_INTEGRATION.md).

---

## 2026-09-26 — Governance fails closed; services are admitted per route
**Decision:** governance refuses to start without a token-verification key
(read through `pkg/jwtauth`, so the shared `JWT_PUBLIC_KEY_*` works). System
administration needs a verified root administrator. A platform service is
admitted only on a route named for its identity in
`systemAdminServiceCallers`, and every refusal is audited.

**Why:** a missing key disabled authentication, and in compose the key was
always missing. Service callers need exactly one read (state) and one write
(posture controls), so a per-route identity list grants that and nothing
more. Backups, restore and the FIPS mode stay administrator-only.

**Rejected:**
- Admitting any service principal on system-admin routes: that would let
  any compromised internal service restore backups or change the FIPS mode.
- Migrating governance to the `pkg/route` kernel in the same change: that's
  the right end state (phase 2), but the auth hole needed closing now. The
  refusal reasons match the kernel's so the migration keeps them.
- Keeping `POSTURE_GOVERNANCE_BEARER_TOKEN` as the only posture credential:
  nothing ever set it.

**Enforced by:** `TestMissingJWTKeyRefusesStart`,
`TestSystemAdminRoutesRequireVerifiedToken`, `TestSystemAdminRefusalReasons`,
`TestSystemAdminServiceCallersAreRouteBound`, and
`TestGovernanceCallsCarryServiceIdentity` in keycore, policy and posture.

---

## 2026-09-26 — Governance never stores a key that opens its backups
**Decision:** a software-mode backup key is returned once, in the create
response, and never stored. The platform keeps only its fingerprint. An
HSM-bound key is stored wrapped under
`HKDF-SHA256(BACKUP_HSM_WRAP_SECRET, binding, tenants)`, with the secret at
least 32 characters. Migration 013 removes existing stored keys, and v1
(raw SHA-256) packages are refused. Master-key re-wrapping of backup
contents moves from an hourly job over stored backups to capture time.

**Why:** a key in the same row as the artifact makes the encryption
decorative for anyone with the database. The owner accepted that backups
from the old version won't restore (none were taken).

**Rejected:**
- Wrapping software keys under a governance master key from `pkg/mek`: a
  database copy plus a running keycore would still open them. A backup has
  to survive the loss of the platform, so the operator must hold its key.
- Keeping v1 unwrap as a fallback: it keeps the raw-hash derivation
  reachable, and there were no v1 backups to keep.
- Keeping the stored-backup re-seal job: without stored keys it has
  nothing to open. Re-wrapping at capture covers every new backup.
- Deleting old backup rows: scrubbing the key keeps the artifact usable
  with a key file saved earlier.

**Enforced by:** `TestSoftwareBackupKeyIsNotStored`,
`TestSoftwareBackupKeyNotRetainedPostgres`,
`TestMigrationScrubsStoredBackupKeysPostgres`, `TestHSMBoundBackupKeyUsesHKDF`,
`TestHSMBoundV1PackageIsRefused`, `TestBackupWrapSecretStrength`
([SECURITY/BACKUP_KEYS.md](SECURITY/BACKUP_KEYS.md)).

---

## 2026-09-26 — No anonymous key use in keycore
**Decision:** every key operation needs a verified identity. The
"backward-compatible" branch that let a caller with no token use any key
without grants (when deny-by-default was off) is removed. Keycore refuses to
start without its token-verification key. Platform callers that relied on
anonymous access get service identities: compliance playbooks call as
`kms-compliance` (token confined to platform service hosts), and reconciler
calls as the new `kms-reconciler`.

**Why:** an unauthenticated request is not a tenant's caller. Deny-by-default
being off should mean "creator and admins may use ungranted keys", not
"anyone who can reach the port may". Rule 4 already forbids unverified
identity, and anonymity is the extreme case.

**Rejected:**
- Keeping anonymous access behind a flag: its only users were the two
  internal callers above, and they're fixed.
- Accepting the shared internal API token as an identity: every internal
  caller holds it, so it can't say who acted.
- Requiring a token at the handler for every route: the internalauth routes
  (reconciler's due-for-lifecycle and archive) and health checks don't carry
  a JWT, and key access is where identity matters.

**Enforced by:** `TestAnonymousKeyUseIsRefused`,
`TestPlaybookSendsServiceTokenOnlyToPlatformServices`,
`TestLifecycleCallsCarryServiceIdentityAndTenant`.

## 2026-09-26 — Service master keys come from keycore; exposure is tracked until material is replaced
**Decision:**
- secrets, certs, cloud and ekm get their master key from keycore through
  `pkg/mek`: a protected system key per service (`POST /system-keys/ensure`),
  service-derive bound to the service identity, and the version pinned in
  `<svc>_mek_state`. There is no environment variable and no fallback.
- Rows under any key an earlier release used are re-wrapped at startup and
  by a periodic rescan.
- Items that were under a public key go into an exposure register until the
  material is replaced.
- Governance re-protects its stored backups, and re-wraps restores before
  writing.

**Why:**
- All four services fell back to public keys, and nothing ever configured
  the real ones. A required env var (tried first, in the same unreleased
  branch) would still:
  - break a plain `docker compose up` on upgrade;
  - need copying to every cluster member by hand;
  - make every installer, backup runbook and rotation step carry a
    data-destroying secret.
- Keycore already holds key material under its master key, which the cluster
  join ships. Deriving from it satisfies rule 6 and makes members work with
  nothing to copy.
- **Protection at keycore's storage layer:** destroying a system key would
  crypto-shred a service's whole store, and every destroy path (API, bulk,
  scheduled sweep) funnels through a few store methods.
- **Exposure register:** re-wrapping can't touch copies made before (dumps,
  snapshots, downloaded backups). The only real remedy is to replace the
  material. A register that closes itself when the material is rotated or
  deleted turns "treat these as exposed" into tracked work.
- **Backups:** governance keeps backup artifacts, and for software-mode
  backups their keys, in the database. So the live database kept exposing
  the old values until its backups were re-protected too.

**Rejected:**
- Required `<SERVICE>_MEK_B64` (for the reasons above).
- Generating a key file per node: backup/DR and cluster members would need
  it copied, and losing it loses the data.
- Re-encrypting values with new DEKs instead of re-wrapping: a pre-upgrade
  copy already holds the old ciphertext and a public-key-wrapped DEK, so it
  adds nothing.
- Rotating exposed material automatically: CA keys, cloud credentials and
  BitLocker recovery keys are in use outside the platform, and replacing them
  blind would break their users.
- Deleting pre-upgrade backups: destructive, and a downloaded copy survives
  anyway.

**Enforced by:**
- `no-literal-key-material` (the only public keys are marked lines in
  `pkg/mek/catalog.go`).
- `TestCatalogIsValidAndMigrated`, `TestMEKLifecycle*`,
  `TestSystemKeyIsProtectedFromDestruction`, the per-service
  `TestUpgradeMoves*` tests and `TestBackupReprotectPostgres`.
- docs/SECURITY/SERVICE_MASTER_KEYS.md.

## 2026-09-26 — Feature kernel (pkg/route): rules are declared per route, applied in one place
**Decision:** every HTTP route is registered through `pkg/route` with a
`route.Spec` (audit action, permission, resource, tenancy). The kernel
authenticates, resolves and enforces one tenant, checks the permission, and
emits exactly one `audit.<service>.<action>` event per request, including
failures and refusals (with `reason`). Services move onto it one at a time
([ARCHITECTURE_MIGRATION.md](ARCHITECTURE_MIGRATION.md)); `services/secrets`
is the reference.

**Why:**
- Cross-cutting rules lived in about 960 hand-written handlers, with 22
  private `mustTenant` copies. Each new feature had to be reminded of audit,
  tenancy and permissions, and some missed them: `POST /secrets` accepted a
  body `tenant_id` without checking it (a cross-tenant write).
- A rule in the kernel reaches every migrated route. A rule in a handler
  reaches one.
- Specific events for refusals were owner policy (2026-09-25), but nothing
  guaranteed them.

**Rejected:**
- Rewriting the product from scratch: it would lose the FIPS, clustering and
  audit-chain work and the security fixes, and ship months of unreviewable
  change at once.
- Relying on the generic `auditmw` `http_request` record: it has no action
  semantics, target or refusal reason, so governance and DAM can't run on it.
- Per-service middleware: the same duplication at a different layer.
- Emitting from the service layer: it can't see refusals that happen before
  the service is called, and it duplicates events when one service method
  calls another (generate → create).
- Letting `kms.read` / `kms.write` match any domain by verb: once auth
  migrates, API clients would gain `auth.*.write`. The coarse grants apply
  only to domains listed in `route.CoarseDomains` (today, `secrets`).
- Resolving the tenant only from query/header (as `mustTenant` did): body
  tenants are how the dashboard sends writes, so the body must be checked,
  not ignored.

**Enforced by:**
- Registration panics without an action or permission.
- `make conformance` rule `route-kernel`: a raw `http.ServeMux` in a service
  file fails unless the file is on `scripts/route-kernel-burndown.txt`, which
  only shrinks.
- `routetest.RefusalsAudited` proves each route refuses and audits the three
  refusal cases.
- `pkg/route` tests: cross-tenant body, conflicting sources, service
  principals, and failure/refusal events.

## 2026-09-26 — Cluster write forwarding: member verifies, primary re-mints
**Decision:** on a member, every service's HTTP wrapper forwards lifecycle
writes to the primary's cluster-manager.
- The member verifies the caller's token and sends the claims, authenticated
  by a per-member credential issued at join.
- The primary has its own auth mint a 5-minute token (`fwd_node` set) and
  proxies to the service.
- Writes are forwarded by default; `pkg/clusterroute.Local` lists the
  exceptions.

**Why:**
- Verification keys differ per node, so the user's token can't be replayed on
  the primary.
- Re-minting keeps every service's own authorization and audit untouched.
- Default-forward means a new endpoint can't diverge a member.

**Rejected:**
- Sharing one JWT key cluster-wide: a member compromise would forge tokens
  for every node.
- Proxying the raw user token.
- An allowlist of forwarded writes: a new write would silently diverge.
- Letting members write and reconcile later (split-brain on key state).

**Enforced by:** `TestClusterForwarding`, `TestLocalRoutesExist`,
`TestSecureJoinEndToEnd`, and the rule in CLUSTERING.md that background jobs
check `RunsPrimaryJobs`.

## 2026-09-25 — Documentation ships with the change
**Decision:** every change updates CHANGELOG.md, learning.md, this file and/or
`docs/SECURITY/` in the same commit. Standing instructions live in `CLAUDE.md`.
**Why:** the owner shouldn't have to repeat instructions, and FIPS reviewers
need a written trail of why each security control exists.
**Rejected:** documenting at release time (context is lost by then).
**Enforced by:** `scripts/check-docs.sh` in CI on pull requests, plus the
"Documentation is part of done" table in `CLAUDE.md`.

## 2026-09-25 — Cluster join: master key moves keycore-to-keycore under ML-KEM; join pinned by bundle
**Decision:**
- **Master key:** the member's keycore creates a one-time ML-KEM-768 key,
  and the primary's keycore seals its master key to it, bound to the join
  context. Only the cluster-manager service identity may drive this. The
  member stores the key on its own volume and restarts on it.
- **Replication access:** it gets a dedicated role with SELECT only on the
  member's component tables, plus `BYPASSRLS`. Its credentials are sealed to
  the member's cluster-manager.
- **Trusting the primary:** the member pins the primary's TLS certificate from
  the join bundle and authenticates with a one-time token.
- **cluster-manager:** now requires a root admin or a service identity on
  every admin route.

**Why:**
- A member can't use replicated key material without the master key, and the
  plaintext key must never exist outside a keycore process.
- Pinning plus a one-time token needs no pre-shared CA, like
  `kubeadm join`.

**Rejected:**
- **Moving the master key through cluster-manager in plaintext:** it widens
  exposure.
- **The existing `CLUSTER_SYNC_SHARED_SECRET` as the join credential:** a
  long-lived shared secret on every node.
- **A superuser replication connection:** far more than the member needs.

**Enforced by:** `TestClusterMEKTransfer*` (keycore),
`TestSecureJoinEndToEnd` (two real Postgres servers, real TLS, wrong-pin
refusal) and `TestClusterRoutesRequireRootAdmin`.

## 2026-09-25 — Clustering: one lifecycle writer, per-component Postgres logical replication
**Decision (customer's choice):**
- The primary is the only lifecycle writer; members forward lifecycle writes
  and run crypto operations locally.
- Failover is manual, plus a majority vote at 3+ nodes, with fencing.
- Replication is Postgres 17 logical replication with one publication per
  component; members subscribe only to their assigned components.
- Every table is classified replicated / node-local / shared-append in
  `pkg/clustercatalog`, and a test enforces it.

**Why:**
- The existing framework recorded sync events that nothing ever applied.
  Writing apply logic for about 250 tables in 30 services would be large and
  fragile.
- Logical replication gives a transactional initial copy and streaming for
  free, and each service already owns its tables, so the per-component split
  is natural.

**Rejected:**
- **Active-active multi-writer:** concurrent rotate/destroy on two nodes can
  diverge key state, and unique-name collisions stall replication.
- **Physical streaming replication / Patroni for the whole database:** it
  can't replicate selectively per feature, and it would clone node-local data.
- **Per-entity event apply handlers:** see Why.

**Enforced by:** `TestEveryTableIsClassified`, the two-node integration test,
and status that comes only from the database.
## 2026-09-25 — Record-only features are labelled "preview" from one catalogue, not deleted
**Decision:**
- Features that store configuration without enforcing it are listed in
  `pkg/features.Preview`.
- Every response of such a feature is labelled, and the dashboard mirrors the
  list (checked by conformance).
- Operations they cannot perform refuse with `409 feature_preview`.
- Fabricated data they had produced is relabelled, not deleted: simulated
  backup runs, fake Merkle roots.
- The simulated backup scheduler stays a preview; real backup is governance.

**Why:** the owner's options were "finish or mark preview". Marking is honest
today and keeps the APIs stable for the teams that will finish them. Finishing
federation or edge is product work, not a fix.

**Rejected:**
- **Deleting the features:** they break API clients and lose work.
- **A "preview" note in the docs only:** API consumers never see it.
- **Keeping the backup simulation:** it produced evidence of backups that never
  happened.
- **Rewiring the scheduler to governance backups now:** it needs
  service-to-service backup authorisation and restore of HSM-bound key
  packages. That's tracked as the way to finish it.

**Enforced by:** conformance `preview-catalogue`, keycore and backup tests.

## 2026-09-25 — Security-critical paths get integration tests against real dependencies
**Decision:** backup/restore, signing and the KMIP wire protocol are tested
against real Postgres and a real TLS KMIP client. The Postgres tests run in CI
job `integration-postgres` (disposable database, serial run).
**Why:** each of these paths hid a defect that only real dependencies expose:
JSONB key order, information_schema, TRUNCATE CASCADE, and TLS client-cert
authentication.
**Rejected:** SQLite-only tests for these paths (they would have passed with
the signing bug in place).

## 2026-09-25 — FIPS mode is changed in the UI and applied by staggered self-restart
**Decision:**
- The platform FIPS mode is a governance setting, changed by a root admin in
  System Administration. The deployment variable only seeds it.
- Every service applies a change itself: it polls the setting, waits its
  restart tier, sends itself SIGTERM (graceful shutdown), and is restarted by
  its supervisor.
- At startup the service re-executes itself with the matching `GODEBUG`
  before any cryptography runs.
- Before confirming, the UI shows the features that stop and start and the
  services that restart. The change is audited, with severity critical for a
  downgrade.

**Why:** the customer asked for the choice to live in the product, not in the
deployment. Go fixes the FIPS mode at process start, so a restart is
unavoidable; making each service apply the change itself needs no Docker
socket or orchestrator access.

**Rejected:**
- **Governance restarting containers through the Docker socket:** that hands
  root on the host to a web-facing service.
- **Restarting only the "affected" services:** the mode covers every Go
  process's cryptography, so a partial restart leaves a mixed posture.
- **Restarting everything at once:** a full outage. Tiers keep the platform
  up.
- **Switching modes without a restart:** Go doesn't support it.

**Enforced by:** `pkg/config.RequireFIPSRuntime` (by construction), the
conformance `fips-module` rule (common env and a restart policy on every Go
service), governance tests, and a real-container end-to-end check
(docs/SECURITY/FIPS.md).

## 2026-09-25 — dataprotect working keys come from keycore (service-derive), with a per-key migration
**Decision:**
- keycore gets `POST /keys/{id}/service-derive`: HKDF over the key's secret
  material, bound to the verified calling service, tenant, key, pinned
  version and purpose.
- dataprotect derives every working key through it (v2).
- Identifier-derived keys (v1) survive only per key, in state
  `legacy`/`migrating`, until an operator completes that key's migration.
- New keys are v2 from birth. Strict FIPS mode refuses v1 everywhere.

**Why:** the working key was HMAC over the public KCV, so it was predictable.

**Rejected:**
- **Running tokenize/FPE inside keycore:** a large move of format-preserving
  code into the crypto boundary, with a keycore round trip per value.
  Service-derive keeps the algorithms in dataprotect while the secret stays
  in keycore.
- **Exporting raw key material to dataprotect:** it would spread the root
  secret. A purpose-bound HKDF subkey can't be turned back into the key.
- **Switching every key to v2 at upgrade:** FPE and vaultless outputs carry no
  version marker and aren't authenticated, so old ciphertexts would decrypt to
  wrong values with no error.
- **A version marker inside outputs:** impossible for format-preserving
  tokens and FPE.
- **Trial decryption with v2, falling back to v1:** it gives wrong plaintext
  without any error for unauthenticated formats.

**Enforced by:** the state machine in `services/dataprotect/kdf.go`, the
generic-derive reserved-prefix check, tests in all three FIPS modes, and
`audit.dataprotect.kdf_legacy_used` on every legacy use.

## 2026-09-25 — FIPS 140-3: certified Go module always, runtime mode is the customer's choice
**Decision:** every binary links the CMVP-certified Go Cryptographic Module
(`GOFIPS140=v1.0.0`). The customer chooses `VECTA_FIPS_MODE` = `on` (default),
`only` or `off`, passed to Go as `GODEBUG=fips140`. Services refuse to start
when the runtime doesn't match. Every mode is tested in CI.
**Why:** `pkg/fips` was an in-app allowlist with no validated module behind
it, and the "FIPS mode" variable never reached the containers. A lab asks
which validated module does the cryptography; the answer must be true in the
build and visible at runtime.
**Rejected:**
- BoringCrypto (cgo, a different module, and the Go team now points to the
  native module).
- Hard-wiring strict mode (it would break customers' legacy payment TDES and
  X25519 integrations; the customer decides).
- A per-tenant runtime toggle (Go fixes the mode at process start; per-tenant
  rules stay in the governance FIPS Policy).
- Wrapping everything in `fips140.WithoutEnforcement` to make strict mode pass
  (that would be strict in name only). `WithoutEnforcement` is used only for
  known-answer self-tests with published vectors.
**Enforced by:** conformance `fips-module`, `config.RequireFIPSRuntime`, the
CI `fips-modes` matrix, and `TestBuiltWithCertifiedModule`.

## 2026-09-25 — Placeholder secrets are rejected in the shared config loader
**Decision:** `pkg/config` rejects placeholder secret values (`your-...`,
`change-me`, `replace-me`) at startup, from `Load` and `NewHTTPServer`, rather
than each service validating its own variables.
**Why:** plain `docker compose up` bypasses the deploy scripts, and a
per-service check would be forgotten in the next new service. Putting it in
the shared loader gives every `pkg/platform` service the check by
construction.
**Rejected:** a check only in `deploy-local.sh` (bypassed by plain compose);
auto-replacing placeholders on a live stack (a baked-in Postgres password
would break the database).
**Exception:** customer-side `ekm-agent` reads a config file, not the
environment.
**Extended (same day):** connection-string env vars (`*_DSN`,
`*DATABASE_URL`) are parsed, and a default, username-equal, empty or
placeholder password is rejected. A missing `POSTGRES_DSN` is an error rather
than a built-in localhost default.

## 2026-09-25 — Secrets: fail fast or generate, never a public fallback
**Decision:** no secret may default to a value in the repo. Weak values stop
the service at startup, and credentials derived from a removed default are
revoked on startup.
**Why:** a `-change-me` fallback for `INTERNAL_SERVICE_BOOTSTRAP_SECRET` let
anyone derive every internal service's API key on installer-based deployments.
**Rejected:** a startup warning (ignored in practice); "tokenless" degraded mode
for a weak secret (degraded identity is no identity).
**Exception:** admin `changeit`, seeded with a forced password change.
**Enforced by:** `make conformance` rule 3, which also runs in CI. See
[SECURITY/SECURE_DEFAULTS.md](SECURITY/SECURE_DEFAULTS.md).

## 2026-09-25 — Service principals are keyed on unforgeable claims
**Decision:** a caller may bypass tenancy only with role `client-service` AND
the reserved `service.internal` permission AND a `kms-*` client id AND the
internal tenant. The reserved permission is stripped at every API write path.
**Why:** the role alone is carried by every client-credentials token, so keying
on it would have been a cross-tenant bypass.
**Rejected:** role-only checks; trusting `X-Actor-*` headers.
**Enforced by:** `tenantcheck.IsServicePrincipal` and
`pkg/tenantcheck/service_principal_test.go`.

## 2026-06-18 — Service-to-service auth: per-service JWTs from one bootstrap secret
**Decision:** each service derives its API key as
`HMAC(bootstrap secret, service name)` and exchanges it at auth for a
short-lived JWT. The rollout is phased (attach, then enforce).
**Why:** one secret to distribute instead of 20, while every service still gets
a distinct, auditable identity.
**Rejected:** a shared static bearer token for everything (no per-service
attribution); per-service secrets in `.env` (secret sprawl).
**Rotation:** auth bootstrap retires every service key that doesn't match
the current secret, so rotation locks out the old value on the next auth start
(added 2026-09-25). Service JWTs already minted live out their TTL (≤ 1 h).

## 2026-09-26 — Cut features are removed; all work happens in KMSBeta
**Decision:** a feature cut from the core is deleted from KMSBeta and
recovered from its git history if it's ever wanted again. Nothing is
committed to `KMSExtension` any more (owner: "all the work have to be done on
KMS beta only", "stop touching KMSExtension"). Supersedes the 2026-06-12
entry below.
**Why:** one repository to develop, review and certify. A second repo of
parked code that nobody builds only looks like a product. Git history
already keeps every removed line.
**Rejected:** keeping KMSExtension as a read-only archive of cut code.
**Enforced by:** CLAUDE.md ("All work happens in KMSBeta").

## 2026-06-12 — Cut features move to KMSExtension, not the bin (superseded 2026-09-26)
**Decision:** features removed from the core move to the sibling
`KMSExtension` repo and integrate over REST (`pkg/kmsclient`), holding no key
material.
**Why:** it keeps the core's certification boundary small without losing work.

## 2026-06-11 — One crypto library, one audit pipeline
**Decision:** all primitives come from `pkg/crypto` (FIPS-gated). All audit
events go through `pkg/audit` onto the single `AUDIT` stream.
**Why:** about 34 services had duplicated crypto helpers and private audit
streams, which is impossible to certify or reason about.
**Enforced by:** `make conformance` rules 1–2, with a burn-down allowlist that
only shrinks.
