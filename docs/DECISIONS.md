# Decisions

The approaches this product is built on, and why. Newest first. Add an entry
whenever you choose between real alternatives, so the choice isn't argued again
or quietly undone. Each entry covers the decision, why it was made, what was
rejected, and how it's enforced.

---

## 2026-10-01 — Secrets: stale rules are raised and removed by a person; caps apply at once (7.32.0-beta)

**Decision.** A rule whose subject has gone is stamped and raised by an
hourly check (audit event, Playbooks trigger), never removed or disabled by
the system. Deleting any rule that is the last allow rule over its path is
refused unless the request confirms the reopening. A cap change prunes every
secret in the request that makes it.

**Why.** Under "allow restricts", removing a rule can only widen access, so
it must be a person's decision made with the consequence in front of them.
"Gone" is also not permanent for roles. A cap that waits for the next write
never reaches the secrets nobody writes.

**Rejected.** Auto-removing stale rules: silently reopens a path, or lifts a
deny on a role between holders. Auto-disabling them (keeping the path
restricted): that is what a stale rule already does. A background prune
after a cap change: the caller could not be told what was removed, and a
member must not write. A time-limited grace period before pruning: a second
state to explain for no safety gain, since the dashboard asks first.

**Enforced by.** `TestReopenGuard`, `TestStaleSubjects` (member mode, once
per rule, unreachable owner, never removes), `TestCapAppliesNow`, all also
on Postgres; the browser test of the delete dialog.

---

## 2026-10-01 — Secrets: version caps by path; a rule's subject is verified with its owner (7.31.0-beta)

**Decision.** A version cap can be set on a path (a secret or a folder), in
the same path form as access rules; the most specific applies, the tenant's
last. An access rule is stored only after the service that owns its subject
confirms it exists (auth, keycore, workload identity), and refused if that
service cannot be asked. Stored rules are re-checked when listed and
flagged, not removed.

**Why.** One path syntax for rules and caps means one thing to learn and one
matcher to test. A free-text subject turned a typo into a silent lockout of
a folder. Refusing on an unreachable owner keeps "every stored rule was
verified" true. Auto-removing a rule when its subject disappears would
silently reopen a path whose only allow rule it was.

**Rejected.** A `max_versions` column on each secret plus a separate folder
table: two mechanisms. Letting secrets read auth's tables: services own
their data. Reusing `GET /auth/users` and `/auth/clients` with a service
token: they scope to the caller's tenant, which for a service is the
internal one. Storing unverifiable rules as "pending".

**Enforced by.** `TestCapFor`, `TestPathCaps`, `TestSubjects`,
`TestPlatformDirectory` (secrets, also on Postgres); `TestSubjectsCheck`,
`TestSubjectsRoutesRefusalsAudited` (auth).

---

## 2026-10-01 — Secrets: root mount, keycore groups, fail closed on unknown membership (7.30.0-beta)

**Decision.** (1) The Vault mount is the first segment of a secret's name,
except `secret`, the root mount, whose paths are names as they are. Existing
secrets written under other mounts are renamed by migration. (2) Group
subjects in access rules are keycore's access groups, resolved by a call to
keycore under the secrets service's identity and cached for 30 seconds.
(3) When membership cannot be read, a request a group rule bears on is
refused with 503. (4) Default-deny, the version cap and the retention period
are per-tenant settings changed with `secrets.access.manage`.

**Why.** (1) A root mount keeps every dashboard-created secret reachable by
Vault clients at `/v1/secret/...` and every Vault-written secret at the URL
it was written to, while making two mounts two namespaces. (2) One group
store: a second one in secrets would drift from the one operators already
manage for keys. (3) "Could not check" treated as "not a member" would skip
a deny rule during an outage. (4) Each of these widens or destroys, so they
sit behind the same permission as the rules.

**Rejected.** Mount always the first segment, no root: dashboard secrets
with plain names would lose their Vault address. Falling back to the bare
path when `<mount>/<path>` is missing: that is the bug, by another route.
Carrying groups in the token: membership would be as stale as the token.
Purging deleted secrets with no audit event because no request caused it:
every destroy is audited, so the sweep emits its own.

**Enforced by.** `TestMounts`, `TestMigration005Postgres`, `TestGroupRules`,
`TestDefaultDeny`, `TestVersionCap`, `TestRetention` (member mode
included), all also run on real Postgres in `TestAccessAndVersionsPostgres`;
`TestListUserAccessGroups` in keycore.

---

## 2026-10-01 — Secret access rules restrict, on top of the route permission (7.29.0-beta)

**Decision.** Access to a secret needs the route permission **and**, where
an allow rule covers the secret's path for that capability, being named by
such a rule; a deny rule naming the caller wins
(docs/SECURITY/SECRET_ACCESS.md). Paths with no allow rule stay governed by
the permission alone. Subjects are fields of the verified token (user, role,
client, workload). Delete is recoverable; destroying and managing rules are
separate permissions that `kms.write` does not grant.

**Why.** `secrets.value.read` was tenant-wide: one grant read everything.
Restricting rules can be adopted one folder at a time with no migration and
no lockout, and they cannot widen access, so a mistaken rule fails closed
for that path only. Destroy is irreversible and rule changes decide who
reads what, so neither should ride on a coarse write grant.

**Rejected.** Rules that grant (Vault-style policies replacing the
permission): two sources of grants to reason about, and every existing
tenant would need policies written before anything worked. Default-deny for
unlisted paths: right as an opt-in tenant setting later, wrong as a default
that empties every existing vault on upgrade. Reusing keycore's key access
groups as subjects: a cross-service call on every secret read; left open.
Keeping delete permanent and adding a separate "archive": two verbs for
operators to confuse, and Vault KV clients already expect delete to be
recoverable.

**Enforced by.** `TestAccessRulesAreEnforcedOnEveryRoute` (each route, as a
caller no rule names), `TestDecide`, `TestAccessRuleValidation`,
`TestListPagesCountVisibleSecrets`, `TestSoftDeleteRestoreDestroy`,
`TestVersionReadRollbackDestroyAndConditionalWrite`; `routetest.RefusalsAudited`
covers the new routes' permissions.

---

## 2026-10-01 — Secret Vault charts count the full list; a value is read only on request (7.27.0-beta)

**Decision.** The vault page pages every secret of the tenant and computes
its tiles, charts and drill-downs from those rows with shared bucket
functions and one "now" (`tabs/vault/meta.ts`). Opening a secret reads its
metadata, versions and change history; the value is read only on Reveal or
Download. The version list carries no digest of the value. The page lists
only the Vault routes the router registers.

**Why.** The earlier page drew its type bar from `/secrets/stats` and its
cards from the first 500 secrets, so the two could disagree, and stats
answered 0 on any failure. Reading the value on open made every click a
`value_read` warning in the audit log, which buries the reads that matter.
An unsalted SHA-256 of a password is a guessing oracle for anyone who can
list versions.

**Rejected.** Server aggregates with a paged drill-down, as Discovery does:
right once vaults hold tens of thousands of secrets, but it needs filter
parameters on `GET /secrets` (expiry and change windows) that do not exist
yet; the list is metadata only and pages at 500. Activity charts on this
page: audit charts live in Audit Log → Activity (one home per view), so the
page links there. Keeping the OpenBao panel as a "preview": the endpoints
are not stored configuration, they are absent.

**Enforced by.** `web/dashboard/tests/vault.spec.ts` (bar count equals list
length, no `/value` call before Reveal, "unavailable" on failure, removed
strings absent); `TestStatsFailureIsNotZero`, `TestVersionsCarryNoValueHash`,
`TestVaultKVWriteReportsRealVersion`, `TestVaultTokenLookupSelfReportsTokenOnly`,
`TestDeleteRecordsTheCaller` in `services/secrets`.

---

## 2026-10-01 — The component size gate is a ratchet (7.25.0-beta)

**Decision.** `check:component-size` keeps the 500-line limit for every new
component. The 29 files already over it are listed in
`web/dashboard/scripts/component-size-burndown.json` with a ceiling at their
current size. A listed file may not grow; a file not listed must be within
the limit; an entry must be removed once its file is within the limit or
gone. `--tighten` lowers ceilings to current sizes and never raises one.

**Why.** The gate had an empty allowlist and 30 files over the limit (one of
2,778 lines), so it failed on every commit and told nobody anything. It sat
behind an already-red lint step, so it had not even been seen.

**Rejected.** Raising the limit to fit the largest file: no limit at all.
Removing the gate: new 2,000-line tabs would keep arriving. Splitting 29
files in one change: a large refactor of working screens with no test
coverage to protect it. The ratchet stops the growth now and lets each file
be split when it is next worked on.

**Enforced by** `tests/unit/componentSizeGate.test.ts` (growth, a new
oversized file and a stale entry each fail) and the CI dashboard job.

## 2026-10-01 — Overview → Analytics merged into Overview → Operations (7.24.0-beta)

- **Decision:** key and operations trends live in Overview → Operations, as
  the tabs Key inventory and Operation metrics beside Status (the
  operations dashboard). Overview has no Analytics entry. This amends the
  2026-09-30 and 2026-09-28 "one home" entries below only in where that home
  is.
- **Why:** owner, 2026-10-01. After audit and alert charts moved out
  (7.15.0-beta), Analytics held two views about the same thing the
  Operations dashboard shows, under a second menu entry.
- **Rejected:** stacking all three on one scrolling page. The dashboard
  polls every 30 seconds and the metrics have their own window picker; tabs
  keep each view's controls beside its data.
- **Enforced by:** `tests/smoke-tabs.spec.ts` ("analytics, alerts and audit
  each have a single home"): no Analytics entry in the menu, and Operations
  has the three tabs. `RETIRED_TABS` sends old links to Operations.

## 2026-10-01 — runtime-certs is real tmpfs; an external edge certificate is kept on the certs key volume (7.21.0-beta)

- **Decision:** `runtime-certs` is tmpfs on every install, created only by
  Compose. What certs can issue again (the `runtime` and `ca` edge and KMIP
  certificates, Envoy's client certificate) exists only there. What it
  can't issue again is kept on the node's certs key volume
  (`/var/lib/vecta/certs/edge`) and copied into tmpfs at start: an external
  certificate with its key and serial marker, and the key of a pending CSR.
  The kept copy is node-local and stored as the files were before (mode
  0600, owned by certs, not wrapped). This amends the 6.13.0-beta entry
  below only in where the node keeps the key.
- **Why:** the compose file, `RUNTIME_CONTROL_FLOW.md` and the certs API
  said these keys are materialized into tmpfs, and they were on disk (owner,
  2026-10-01, chose to make the statement true). An external key can't be
  regenerated without the customer's CA signing again, so it must survive a
  restart.
- **Rejected:**
  - *Keep the volume on disk and correct the statements.* No behaviour
    change, but every runtime key stays at rest for no reason.
  - *Wrap the external key under the CRWK.* Rejected in 6.13.0-beta for the
    rewrap on CRWK rotation it needs. In software root-key mode the CRWK
    passphrase is on the same volume, so wrapping adds little there.
- **Consequences:** a full restart issues the runtime certificates again,
  so their serials change. From 7.22.0-beta certs revokes each one it
  replaces (it records the last issued certificate per listener beside the
  kept copy); before that the old ones stayed active until they expired.
  Leaving the `external` source discards the kept certificate and key; an
  expired kept certificate is discarded at the next start.
- **Enforced by:** `scripts/test-volume-repair.sh` (the mount is tmpfs, using
  the real compose declaration; an upgrade keeps external material and loses
  no persistent volume), conformance `compose-volumes`,
  `TestEdgeExternalCertificateSurvivesRestart` (restored and audited; a
  mismatched, expired or discarded copy is not),
  `TestEdgeCertificateReplacedIsRevoked`,
  `TestExternalEdgeCertificateSurvivesRestartOnRealEnvoy` (real Envoy on a
  real tmpfs volume: removed, restored, served again).

---

## 2026-10-01 — Discovery: git repositories through the hosting API; schedules on checked authority (7.20.0-beta)

- **Decision (how a repository is read):** discovery asks the hosting
  service's API for a tar.gz of one ref over HTTPS and scans the stream in
  memory with the code scan's parser. It writes nothing to disk and runs no
  git program.
- **Why:** the only cryptography is this service's own TLS, so the feature
  is the same in every FIPS mode, and every request goes through the scan's
  dial guard after DNS resolution, redirects included.
- **Rejected:** running the `git` program. Its TLS is the image's OpenSSL,
  outside the certified module, and it resolves and connects by itself, so
  the dial guard could not check the address it reaches. `go-git`: a large
  dependency that brings its own SHA-1 and transport code. Speaking the git
  smart protocol directly: a pack has no file paths without hashing every
  object with SHA-1, which the module refuses in strict mode.
- **Cost:** each hosting service has its own archive URL, so the provider
  is detected for github.com, gitlab.com, bitbucket.org, codeberg.org and
  gitea.com and stated for any other host. Bitbucket Server and Azure
  DevOps are not covered. Only the ref's latest commit is read.
- **Decision (credentials):** a private repository's token is a sealed
  compliance connection of type `git` (docs/SECURITY/CONNECTIONS.md).
  Compliance opens it for the `kms-discovery` identity only, for that type
  only. Discovery checks that the connection's host is the repository's
  host before every use and removes the token on a redirect to any other
  host. A URL with a user name or token in it is refused and not copied to
  the audit event.
- **Decision (schedules):** one schedule per tenant, saved by a signed-in
  user who holds `discovery.write`. Before every run discovery asks auth
  whether that user is still active and still holds it
  (docs/PLATFORM_CONTRACT.md). Lost authority pauses the schedule; an
  unanswered check postpones the run 15 minutes without pausing. Schedules
  run on the primary only.
- **Rejected:** running a schedule as the service with no named authority
  (it would lend discovery's reach, including sealed tokens, to anyone who
  once could save one). Letting an API client save one: there is no user
  for auth to re-check.
- **Enforced by:** `TestGitScanReadsEachHostingAPI`,
  `TestGitTokenStaysOnItsHost`, `TestGitScanReportsRefusals`,
  `TestGitArchiveLimits`, `TestNormalizeRepository`,
  `TestRepositoryRoutesAudited`, `TestRepositoryTestReadsTheArchive`,
  `TestScheduleRoutesAudited`, `TestScheduleRunsOnCheckedAuthority`,
  `TestScheduleSkippedOnClusterMember`, `TestScheduleDisabledAndBusy`,
  `TestGitConnectionIsDiscoverysAlone`,
  `TestAuthorityCheckForDiscoveryOnly`,
  `TestTargetsAndAssetRemovalPostgres`, and the opt-in
  `TestLivePublicRepositories`.

---

## 2026-10-01 — Discovery: background scans, SSH and ranges, uploads, server-counted charts (7.18.0-beta)

- **Decision (scans):** a scan runs in the background on the node that
  accepted `POST /discovery/scan` (the primary: cluster members forward
  writes), one per tenant, with a 10-minute deadline. Sources run
  concurrently and the scan row is updated as each finishes. A scan still
  "running" past its deadline reads as `interrupted`; nothing rewrites it.
- **Decision (SSH):** the probe reads the server's identification and
  `SSH_MSG_KEXINIT`, which are sent in the clear, and then, per host key
  type, starts one ECDH exchange (curve25519, or NIST P-256/P-384 for a
  server in FIPS mode) to read the host key from the reply, as `ssh-keyscan`
  does. Discovery computes no shared secret and verifies nothing: the
  client value is random bytes (X25519) or a discarded `pkg/crypto` P-256 or
  P-384 key. The endpoint asset's algorithm is the strongest key exchange
  the server offers; the weak ones it also offers are listed beside it.
- **Decision (ranges):** a range is at most 256 addresses and a tenant's
  targets at most 4096. An address in a range that does not answer has no
  service and is counted, not reported as an error. Reserved addresses are
  refused when the range is added; platform addresses inside one are
  refused at dial time, as for single hosts.
- **Decision (uploads):** an uploaded file is parsed in memory and
  discarded. Only what was found is stored, with a fingerprint for secrets.
  The file name, size and finding count go in the audit event, never the
  content. An upload is recorded as a scan of source `upload`.
- **Decision (reviews):** a review lives in the asset's metadata. `status`
  is what the scan observed.
- **Decision (charts):** the service counts the whole inventory in one
  pass and lists with the same predicate, with no cap. The dashboard's
  charts show the summary's numbers, and a click pages
  `GET /discovery/assets` with the filter that number was counted with.
- **Why:** the page offered only TLS targets and gave no way to set up the
  other sources. A tenant cannot mount a repository into the service, so
  the code source needs an in-product alternative, which uploads provide.
  SSH keys and algorithms are a large part of an estate's cryptography and
  were not inventoried.
- **Rejected:** importing `golang.org/x/crypto/ssh` into the service for
  the probe. It would complete a handshake with non-module cryptography
  for no gain: the facts needed are in the first cleartext packets.
  Naming an unread RSA host key by a guessed size: it stays "not assessed".
  Storing uploaded files for later rescans: they contain private keys.
  Counting in the browser over a loaded list: a list with a cap is a
  sample. A per-scan history chart: assets carry the ID of the last scan
  that saw them, so an older scan's bar could not list what it counted.
- **Enforced by:** `TestScanRunsInBackgroundOneAtATime`,
  `TestAbandonedScanReadsInterrupted`, `TestSSHProbeReadsHostKeys` (a real
  SSH server), `TestNetworkScanSSHTargetAndRange`,
  `TestTargetRangesAndProtocol`,
  `TestUploadInventoriesWithoutStoringSecrets`, `TestReviewSurvivesRescan`,
  `TestSummaryCountsEqualFilteredLists`, `TestInventoryIsNeverASample`,
  `TestTargetsAndAssetRemovalPostgres`, and the dashboard spec
  `tests/discovery.spec.ts`.

---

## 2026-09-30 — Remove user-minted API keys; REST client keys are the only API keys (7.16.0-beta)

- **Decision:** `POST /auth/api-keys` is removed, and keys it left behind are
  deleted at startup. The only API keys are an approved REST client's key
  (issued at activation, replaced by rotation, deleted by revocation) and
  the platform's service keys (derived from the bootstrap secret).
- **Why:** the endpoint stored any permissions its caller named, even ones
  the caller didn't hold, on a key bound to no client. `/auth/client-token`
  refuses unbound keys, so the keys did nothing today. A later change that
  accepted them would have been a privilege escalation.
- **Rejected:** keeping it and capping permissions at the caller's. That
  would add a second, weaker credential path next to REST clients, which
  already have approval, governance, sender-constrained binding, rotation
  and revocation.
- **Enforced by:** the route is gone
  (`TestUnboundAPIKeysRemovedAndRetired`). Client key admin runs on the
  route kernel (`TestClientAdminRefusalsAudited`), and rotation is proven
  by using the key (`TestRotatedClientKeyWorksAndOldKeyStops`).

---

## 2026-09-30 — Integration how-tos live in Documentation, not a product tab (7.14.0-beta)

- **Decision:** the DevSecOps / IaC tab is removed. How to drive the KMS
  from CI/CD is documented in `docs/CI_CD_AUTOMATION.md` and mirrored in
  Documentation → Guides. A dashboard tab must operate on live data. Static
  how-to content goes in Documentation (one home per view).
- **Why:** the tab was static and described integrations that don't exist
  (Terraform provider, SDKs, Helm chart, sidecar). Rule 8 forbids UI that
  presents a capability that isn't built.
- **Rejected:** keeping the tab with a "preview" badge, because there's
  nothing to preview: no backend and no stored configuration. We also
  rejected building a Terraform provider or SDKs to make the claims true,
  which is a separate product decision for the owner.
- **Enforced by:** the product map (`docs/generated/`) lists each tab's API
  calls, and a new tab with 0 calls is reviewed against this entry. The
  guide names only routes and fields verified in source.

---

## 2026-09-30 — Discovery: weak and quantum-vulnerable are separate classes; tenants add TLS targets (7.11.0-beta)

- **Decision:** `cryptocatalog.Assess` reports `weak` and
  `quantum_vulnerable` separately instead of one `vulnerable`, and discovery
  derives the class on read. Tenants add network scan targets (host and port)
  through the API and dashboard, in addition to `DISCOVERY_TLS_ENDPOINTS`.
- **Why:** the merged class marked ECDSA-P256 as vulnerable, which reads as
  "broken now". Both facts are in the catalogue already, and the customer
  decides when to migrate quantum-vulnerable algorithms (CLAUDE.md, crypto
  standards). The environment variable was the only way to name a target, so
  a tenant couldn't scan its own endpoints.
- **Rejected:** a startup job rewriting stored classes. It writes a
  replicated table and would need primary-only gating against a cluster
  reader that may still be pending at boot, whereas deriving on read writes
  nothing. Also rejected: blocking private (RFC 1918) ranges. Scanning the
  customer's internal endpoints is the point of the feature.
- **SSRF boundary:** only `discovery.write` holders add targets. Loopback,
  link-local (cloud metadata), multicast and unspecified addresses are
  refused when a target is added and at dial time after DNS resolution. The
  probe sends only a TLS ClientHello and records the server's handshake.
  **Closed in 7.13.0-beta** (owner: "do not show internal services"): every
  address a platform host resolves to, and discovery's own, is refused at
  dial time for operator and tenant endpoints alike. Internal mTLS
  certificates are skipped by the certs source and hidden if already
  stored; the PKI tab is their one home. Still not blocked: the Docker
  host's gateway address, where a port the operator published is reachable.
  That is the KMS's published, external surface.
- **Enforced by:** `TestRefuseReservedAddr`, `TestTenantTargetDialGuard`,
  `TestNormalizeTarget`, `TestStoredVulnerableIsReclassifiedOnRead`,
  `TestAssessmentDoesNotRepeatTheOldMislabels`.

---

## 2026-09-30 — Keep Workload Identity, Confidential Compute and Discovery; restore their pages (7.9.0-beta)

- **Decision** (owner, choosing among keep, remove or fix): keep all three and
  restore their dashboard pages. Discovery was the weak one: no verified
  caller, a hand-weighted posture score, and PII scanning. It was fixed
  rather than removed: moved onto the route kernel with `discovery.read` /
  `discovery.write`, scores dropped, PII scanning removed.
- **Why:** Workload Identity is how agents and AI workloads get their own
  identity (docs/AI_WORKLOADS.md), and Confidential Compute is the only path
  for attested key release. Both are on the route kernel and real end to
  end. pqc and sbom read discovery's inventory.
- **Rejected:** removing discovery. That would have meant rewriting pqc and
  sbom first. Also rejected: a user-set classification. The classification
  is a catalogue fact about the algorithm (CLAUDE.md, customer decides
  migration), so a review records only a status and notes.
- **Enforced:** `TestDiscoveryRoutesRefusalsAudited`,
  `TestDiscoveryWritesNeedPermissionAndOwnTenant`,
  `TestDiscoveryRelabelRefusedAndAudited`; discovery left
  `scripts/route-kernel-burndown.txt`.

---

## 2026-09-30 — No content inspection in the KMS; AI gateway to KMS Extension (7.5.0-beta)

- **Decision:** the KMS serves AI workloads only through keys, secrets,
  identity, tokenization and signing. It doesn't proxy LLM traffic or
  inspect, score or filter prompts and responses.
- **Why:** a KMS in the data path of every LLM call holds every prompt,
  widens the FIPS boundary to six outbound providers, and turns a KMS outage
  into an AI outage. Content classifiers are a different product category,
  and a regex version can't honestly be called protection (rule 8).
- **Rejected:** keeping the gateway and fixing its defects. That fixes the
  credentials and audit but leaves a weak classifier in a product whose
  reviewers expect everything it claims to hold up.
- **Enforced by:** the CLAUDE.md standing rule; the service and tab are
  deleted; the sources live in KMS Extension `seeds/services/ai-gateway`.

## 2026-09-30 — Algorithm change by rotation under the same key ID (7.3.0-beta)

**Decision.** A key's algorithm changes by rotation: the new version carries
the target algorithm, older versions keep theirs for decrypt and verify, and
the key ID stays. PQC migrations prefer this and create a successor key only
when keycore refuses the change.

**Why.** NIST CSWP 39 asks that an algorithm change not require changing the
applications that use it. A successor key has a new ID, so every caller had to
be found and changed, which is exactly the agility gap CARAF measures as Y.

**Rejected.** (1) Successor keys only: pushes the change onto every caller.
(2) Changing the algorithm of existing material: impossible, the material
belongs to its algorithm. (3) Letting an old version encrypt or sign: would
keep producing data under the algorithm being retired; old versions only
process (SP 800-57). (4) Moving an HSM-resident key in place: the HSM object
defines the algorithm; a new HSM key is created instead.

**Limits.** The target must serve every operation the key serves (an
encryption key can't become ML-DSA; an RSA encryption key to ML-KEM gets a
successor). Rewrap moves ciphertext only when the caller sends it; keycore
does not hold the customer's data.
## 2026-09-30 — Dataprotect: platform token everywhere, wrapper token only on wrapper runtime routes (7.2.0-beta)

**Decision.** Dataprotect verifies a platform JWT on every route in one
gate (`NewAuthenticatedHandler`), in front of the handlers. Without a
platform token, only the wrapper runtime routes (lease, receipt, renew,
resolve for a named wrapper) are admitted, and only with an
`X-Wrapper-Token`, which the service verifies against the wrapper's
registration. Registration needs an operator token.

**Why.** Nothing verified tokens before (see learning.md). A single gate
can't be skipped by a new handler; checking inside each handler is what
failed.

**Rejected.** Dropping `SkipJWT` for the platform middleware: it can't admit
the wrapper routes, and its 401 isn't audited as a specific event. Moving
all about 50 routes onto `pkg/route` in this fix: that is the right end
state (dataprotect is on the burn-down list), but closing the hole shouldn't
wait for it. Tokenless registration: `register/complete` takes
`governance_approved` from the body, so it has to come from an operator.

**Enforced by:** `TestUnauthenticatedRequestsAreRefusedAndAudited`,
`TestWrapperRuntimeRoutesReachTheWrapperCheck`,
`TestVerifiedTokenReachesTheService`, `TestAuthenticatedHandlerNeedsAParser`.

---

## 2026-09-30 — Payment sources go to KMS Extension as a seed (7.1.0-beta)

**Decision.** The owner asked to move the payments tab and codebase "to kms
extension github". The removal from KMSBeta shipped in 7.0.0-beta; the
sources are a seed in `KMSExtension/seeds/` (`fa2ae8c`), which amends the
2026-09-26 rule that nothing more goes to KMSExtension. Development still
happens only in KMSBeta (CLAUDE.md).

**Why a seed, not a live extension service.** KMS Extension's contract is
that extension services hold no key material and do no cryptography; payment
does both. The seed's README lists that and the broken key-by-ID path as
conditions for promotion.

---

## 2026-09-30 — Remove the payment service

- **Decision:** the owner chose to remove payment from the core product.
- **What stays:** `pkg/payment`, because keycore's TR-31 key import uses its
  parser. Service identities of removed services are revoked at every auth
  start, so their credentials can't outlive them (secure-defaults rule 3).

## 2026-09-30 — Composite signatures by dual signing; no HSM HBS until a testable library exists (6.26.0-beta)

**Decision.** Composite keys `ML-DSA-65+ECDSA-P256` and `ML-DSA-87+ECDSA-P384`
sign with both algorithms; verification requires both. Stateful hash-based
signatures stay unoffered, including through the HSM path.

**Why.** Requiring both signatures keeps a signature sound if either
algorithm falls, with no new cryptography. For HBS, SP 800-208 rules out
software keys, and our HSM rule requires tests against a real PKCS#11
library; SoftHSM2 implements no HSS/XMSS mechanism, so an HSM path would be
untested code presented as a feature.

**Rejected.** Adopting a draft composite encoding (not settled; the owner
asked not to cite drafts); "either signature verifies" (only as strong as the
weaker algorithm); an untested CKM_HSS passthrough in hsm-connector.

**Enforced by.** `TestCompositeSignatureKey`,
`TestStrictModeRefusesCompositeSignatureKey`,
`TestCreateKeyRefusesAlgorithmsItCannotGenerate` (XMSS/LMS/HSS refused).

---

## 2026-09-30 — Cryptoperiods per tenant; X25519MLKEM768 only hybrid; no software HBS (6.25.0-beta)

**Decision.** Tenants set their own cryptoperiod per key category (1–3650
days), used by the lifecycle scan. Keycore offers one hybrid key,
`X25519MLKEM768` (the TLS hybrid construction: secrets and ciphertexts
concatenated, ML-KEM first). Stateful hash-based signatures are not offered
by keycore.

**Why.** The customer decides policy (CLAUDE.md), and the built-in periods
were fixed. X25519MLKEM768 is the established hybrid with no invented
combiner. SP 800-208 requires XMSS/LMS generation and signing in hardware.

**Rejected.** A custom hybrid KDF combiner (a new construction to justify);
composite signatures (no settled construction); software LMS/XMSS; capping
tenant periods at the SP 800-57 value (the customer's choice).

**Enforced by.** `TestTenantCryptoperiodDrivesRotation`,
`TestHybridKEMKeyRoundTrip`, `TestStrictModeRefusesHybridKEMKey`,
`TestCreateKeyRefusesAlgorithmsItCannotGenerate`.

---

## 2026-09-29 — Public key read: the per-key read decision, delegated as usage `read` (6.18.0-beta)

**Decision.** Keycore serves an asymmetric key's current public key at
`GET /keys/{id}/public-key` (PEM SubjectPublicKeyInfo), decided like every
other per-key read: the key must be visible to the caller
(KEY_ACCESS_MODEL.md section 8). ekm reads it for the user it serves with
the new delegated usage `read`, so the user's view decides, and asks keycore
on every request instead of serving its cache. A delegated `read` is refused
on any key operation (`delegation_usage_mismatch`).
**Why.** A public key is not secret; whoever may see a key's metadata may
read its public half, the same as its KCV. A stricter check (an explicit
`read` grant) would hide the public key from a user who holds `wrap` or
`verify` on the key and needs it to use it. Keycore's delegation replaces the
decision's operation with the delegated usage, so without the mismatch
refusal a `read` grant forwarded by a service would have authorized a key
operation.
**Rejected.** Adding the public key to `GET /keys/{id}` (every metadata read
of a software key pair would decrypt its private key); a separate
`public-key-read` grant operation (a new usage with nothing it protects
beyond visibility); serving post-quantum raw public keys under an SPKI or
`opaque` label (they are refused, `spki_unavailable`); ekm serving its cached
copy (stale after rotation, and a second decision in front of keycore's).
**Enforced by.** `TestPublicKeyReadOfAHiddenKeyIsRefused`,
`TestDelegatedPublicKeyReadUsesTheUsersView`,
`TestDelegatedReadCannotPerformAKeyOperation`,
`TestTDEPublicKeyFollowsRotation`, `TestTDEPublicKeyReadCarriesTheUsersToken`.

## 2026-09-29 — EKM agents never hold the TDE key; no export route (6.15.0-beta)

**Decision.** The EKM agent sends every DEK wrap and unwrap to the KMS. The
dead local-cache path (`GET /ekm/tde/keys/{id}`, `POST .../export`) is removed,
not built.

**Why.** Exporting the TDE master key would put it in the memory of every
database host, a customer-side process outside the module boundary. Every
use there would then escape keycore's per-use decision and audit. The routes
never existed, so removing the path loses no working capability. Wrapping a
DEK is one small round-trip per database key load, not per I/O, so the
latency case for a cache is weak.

**Rejected.** Building the export routes, which do not exist, behind
keycore's export policy. It would work, but it widens key egress for a
performance gain nobody measured.

**Enforced by** `TestAgentCallsOnlyRegisteredEKMRoutes` and
`TestAgentHasNoKeyExportPath` (services/ekm-agent).

---

## 2026-09-29 — No port 80; KMIP certificate chosen like the edge's; KMIP fails closed (6.14.0-beta)

**Decision.**
- The plain-HTTP redirect on port 80 is removed rather than kept as a
  convenience.
- The KMIP server certificate gets the same three sources as the HTTPS
  edge, chosen separately.
- KMIP refuses to start without its certificate files.

**Why.**
- CLAUDE.md rule 10: nothing speaks plain HTTP. A redirect still receives
  the request (path, query and any credential a client puts in it) in
  clear text before redirecting. Clients that need it can use HSTS-aware
  bookmarks or a load balancer the customer owns.
- The 6.13.0-beta reason for keeping KMIP on `vecta-runtime-root` ("clients
  trust the KMS's CA") was a default, not a constraint: a customer can
  equally want a KMIP certificate from their own CA. Server and client
  trust stay separate: the choice changes only the server certificate;
  client certificates still come from the KMIP client CA and are always
  verified.
- A listener that swaps in a weaker config on error is worse than one that
  doesn't start: the failure is invisible.

**Rejected.** One certificate choice for both listeners (KMIP clients and
browsers often trust different CAs); keeping the redirect but restricting
it to loopback (it still answers in clear text).

**Enforced by.** `tls-only` conformance (port 80 and redirects),
`TestKMIPTLSFailsClosed`, `TestKMIPServerCertificateReloadsAndClientsAreVerified`,
`TestKMIPCertificateSource`.

---

## 2026-09-29 — Edge certificate: three sources, external via per-node CSR; inventory reads the measurement (6.13.0-beta)

**Decision.**
- The HTTPS edge certificate comes from `vecta-runtime-root`, a software
  CA from the PKI tab, or an external CA. The choice is replicated; every
  node applies it.
- An external certificate is issued for a key the node generates. The CSR
  and install routes are node-local, and the key never leaves the node.
- The pqc inventory reads certs' measurement of the external listeners and
  classifies them from `pkg/cryptocatalog`.
- X25519 is measured in FIPS mode by a hand-built ClientHello.

**Why.**
- Uploading an external private key would mean storing and replicating it
  under the certs wrapping key, rewrapping it on CRWK rotation, and
  trusting an operator's copy. A CSR keeps the key where it is used.
- HSM CAs are refused: they sign only for a user they act for, and edge
  renewal runs unattended. An HSM CA can still sign the CSR as an external
  CA.
- The internal-services Sub CA is refused so an external-facing
  certificate never chains to the internal trust anchor.
- The probe pins the installed certificate instead of verifying a chain:
  an external root may be in no pool certs has, and pinning proves more
  (that exact certificate is served).
- The hand-built hello performs no cryptography: it sends a random share
  and reads the ServerHello's selected group, which is all the measurement
  needs. Go's TLS stack is still used for every group it can offer.

**Rejected.** A per-listener certificate for KMIP (KMIP clients pin the
KMS's CA); a key upload; marking X25519 "not measured" in FIPS mode.

**Enforced by.** `TestEdgeExternalCertificateFlow`,
`TestEdgeCertificateFromPKICA`, `TestEdgeProfileAppliedByRealEnvoy`,
`TestProbeMeasuresX25519InFIPSMode`, `TestInventoryReportsMeasuredListeners`.

---

## 2026-09-29 — Workload signing keys: seal in the store, refuse backups that would copy plaintext (6.11.0-beta)

**Decision.** The tenant's root CA and JWT-SVID signer private keys are
sealed together as one envelope per tenant row, under a `pkg/mek` master key
for `kms-workload-identity`, in the SQL store (`GetSettings` /
`UpsertSettings`). The plaintext columns stay, always written empty, so the
primary can seal what earlier releases left in them (and what a restore
brings back), record each tenant in the exposure register, and clear them.

**Why.** CLAUDE.md rule 6 and SERVICE_MASTER_KEYS.md. One envelope per row
(not per key) matches audit and compliance and keeps the conditional update
atomic. The payload names the tenant so an envelope moved between rows
doesn't open. Sealing in the store means every path (lazy first read,
settings update, trust-domain change, rotation) is covered without handler
changes.

**Rejected.**
- *Reinterpreting the existing columns as ciphertext:* a silent switch;
  a row would be ambiguous between plaintext and sealed.
- *Keys in keycore (non-exportable signing keys):* the X.509 CA signing
  path and JWT signer would call keycore on every issuance; a larger change
  with its own availability trade-off. Still possible later.
- *Governance stripping plaintext columns from a backup:* the restored
  tenant would have a CA certificate without its key. Governance refuses
  the capture instead and names the service to start. A deployment that
  disabled workload with unsealed rows must start it once.
- *Refusing a restore of an older backup with plaintext rows:* restoring an
  old backup is legitimate; the rows are sealed by the next periodic pass
  (at most 15 minutes) and recorded as exposed.

**Enforced by** `TestSigningKeysSealedAtRest{SQLite,Postgres}`,
`TestBackupRefusesPlaintextSigningKeys{,Postgres}`,
`TestCatalogIsValidAndMigrated`.
## 2026-09-29 — Key access: deployed means the compose profile, unknown fails closed (6.10.0-beta)

**Decision.** ekm, cloud and hyok decide whether key access justifications
are deployed from `VECTA_DEPLOYED_PROFILES`, which `docker-compose.yml` sets
from `COMPOSE_PROFILES`. Not in a known list: allow, with reason
`key_access_not_deployed`. In the list, or the list empty/unset: evaluate,
and refuse with `424 key_access_unavailable` (audited) on any failure.
`pkg/keyaccess.Gate` is the one implementation; its zero value refuses.

**Why.** `COMPOSE_PROFILES` is already the single output of
`parse-deployment.sh` / `.ps1`, exported by `start-kms` and written to `.env`
by `install.sh`, so every install path carries it without new installer
logic (and nothing new has to run under bash 3.2).

**Rejected.** Passing `KEY_ACCESS_URL` only when the profile is enabled:
compose can't make an environment entry conditional on a profile, so each
installer would compute it, in bash and PowerShell. A dedicated
`KEY_ACCESS_DEPLOYED` flag: the same duplication. Keeping
`HYOK_POLICY_FAIL_CLOSED` as the key access switch: a configuration that
makes an outage an allow is not a customer choice we offer. 6.20.0-beta
removed `HYOK_POLICY_FAIL_CLOSED` altogether: the policy engine check fails
closed with no setting.

**Enforced by** `TestGateFromEnvDeployment`, `TestGateNeverAllowsOnFailure`,
and per service `Test{EKM,Cloud}KeyAccessUnavailableRefuses`,
`TestHYOKKeyAccessFailsClosed` and the `...NotDeployedAllows` tests.

---

## 2026-09-29 — Workload token exchange: the SVID is the credential; keyaccess evaluate only for its three callers (6.9.0-beta)

**Decision.** The workload, keyaccess and confidential routes moved onto the
`pkg/route` kernel. One route is `Public` to the JWT layer:
`POST /workload-identity/token/exchange`. It authenticates with the
workload's SVID, not a bearer token:

- **JWT-SVID:** signature against the tenant's own JWT signer (or a federated
  JWKS, only while `federation_enabled`), expiry, and an audience in the
  tenant's `allowed_audiences`, including when the request names one.
- **X.509-SVID:** the chain must verify to the tenant CA (or a federated
  bundle) with `clientAuth`, *and* the request carries a proof of
  possession: a signature by the SVID's private key over the tenant, the leaf
  certificate's SHA-256 and a `signed_at` within two minutes, accepted once.
- The verified SPIFFE ID must own the registration a `registration_id`
  names. The minted token's client is the registration, not a body
  `client_id`.
- `tenant_id` in the request only selects whose trust anchors verify the
  SVID. A request that also carries a bearer token must name its tenant.
- The kernel audits it as `audit.workload.token_exchanged`, with the
  verified SPIFFE ID as actor (`route.Call.Authenticated`) and every refusal
  under its reason. `pkg/jwtauth.MustWrapRouter` lets only a tokenless
  request that the router matches to a `Public` route skip the JWT layer.

`POST /key-access/evaluate` needs `keyaccess.evaluate`, and the handler
admits only the `kms-ekm`, `kms-cloud` and `kms-hyok-proxy` service
principals (`tenantcheck.IsServicePrincipal` plus client ID), each for its
own service name. `pkg/keyaccess` now sends the caller's service JWT.

**Why.**
- A workload that has only an SVID must be able to get a KMS token; a
  bearer-token requirement would need a static credential, the thing the
  exchange exists to replace.
- Presenting an X.509 chain proves nothing: the certificate is public (every
  TLS peer sees it). Identity from the TLS peer certificate is ruled out too:
  behind Envoy the peer is always Envoy (CLAUDE.md rule 4). So possession is
  proved by a signature in the body.
- Before this change a caller could name another registration's
  `registration_id` with its own SVID and receive that registration's
  permissions, name any `audience` to bypass the tenant's audience policy,
  and have federated bundles honoured with federation switched off.
- An evaluation creates a decision record, and possibly a governance
  approval, in the name of the service that asked. Only the service that
  will act on it may ask, so "any authenticated caller" and even tenant
  administrators are refused.

**Rejected.**
- *mTLS client-certificate authentication for X.509-SVIDs:* the service
  never sees the workload's certificate behind Envoy, and trusting a
  forwarded header is identity from an unverified source.
- *A server-issued nonce (challenge round trip) instead of a timestamped
  signature:* it adds a stateful endpoint and replicated nonce storage for
  little gain over a two-minute window plus a replay cache. Exchanges are
  writes, so cluster members forward them to the primary, which holds the
  cache (in memory; a restart inside the window forgets it, listed as open).
- *Keeping `client_id` in the exchange:* a body-chosen label on a minted
  token lets one workload appear as another in downstream audit.

**CoarseDomains.** None of `workload`, `keyaccess` or `confidential` joins
`route.CoarseDomains`. Workload identity and key-access policy are
administration of who may use keys, and confidential governs key release;
`kms.read` / `kms.write` grants must not reach them.

**Enforced by.** `TestExchangeWithJWTSVID`, `TestExchangeRefusals`,
`TestExchangeWithX509SVIDNeedsProofOfPossession`,
`TestFederatedSVIDNeedsFederationEnabled`,
`TestEvaluateRestrictedToEvaluatorIdentities`,
`TestMustWrapRouterAdmitsOnlyPublicRoutesWithoutToken`,
`TestPublicRouteRecordsVerifiedActor`, `routetest.RefusalsAudited` per
service, and the `route-kernel` conformance rule (the three handlers left
the burn-down list).
## 2026-09-29 — External edge key exchange: one node-wide profile, hot restart, measured by handshake (6.8.0-beta)

**Decision.** The HTTPS edge (Envoy) and the KMIP listener share one
key-exchange profile, set by a root administrator in Service mTLS, stored
in the replicated certs policy table as `vecta-edge`. Envoy applies it by a
hot restart from an entry script; KMIP per handshake. Certs measures both by
handshake. The keycore interface records (ports, bind addresses, TLS
certificate source) were removed rather than made real.

**Why.**
- A listener is per node and serves every tenant, so the choice is
  platform administration (root tenant), not a tenant row.
- Envoy can't change `ecdh_curves` at runtime and SDS can't carry TLS
  parameters. Rendering the config and hot-restarting keeps connections up;
  moving the listener to file-based LDS would have split `envoy.yaml`,
  which the route checks and product map parse.
- Envoy can't read JSON, so certs also writes a plain group list; the entry
  script validates every name and fails closed at start.
- Measurement uses the real listener: one TLS 1.3 handshake per group, the
  way a client would see it. Nothing is marked applied from the stored
  value.
- The interface records couldn't be made real without the KMS managing
  compose port mappings and Envoy listeners, which belong to the
  deployment. Choosing the edge certificate's CA stays the planned slice 4
  of INTERNAL_TLS.md.

**Rejected.** A per-listener profile (two listeners, one security decision,
and KMIP clients are often older than browsers: the refusal is shown
instead); keeping the interface editor as a preview (the honest answer to
every field was "not applied").

**Enforced by.** `TestEdgeProfileAppliedByRealEnvoy`,
`TestEdgeTLSAppliedOnlyWhenMeasured`,
`TestEdgeProfileAppliedPerHandshakeAndMeasured`,
`TestInterfacePortRoutesRemoved`, `TestInterfacePortTablesDroppedPostgres`.

---

## 2026-09-29 — Interface PQC mode: remove it; svctls kx_profile is the listener control (6.4.0-beta)

**Decision.** Keycore's per-interface `pqc_mode` was removed (option a)
rather than enforced (b) or listed as a preview (c).

**Why.**
- Nothing honoured it. No `tls.Config`, Envoy context or KMIP listener read
  it, and its only reader (the pqc inventory) had already stopped.
- The real need is covered where the KMS owns the listener: svctls gives
  every internal identity a `kx_profile` (`pqc-required` / `pqc-preferred` /
  `classical`) that sets the server's `CurvePreferences`, is chosen per
  service in Certificates / PKI → Service mTLS, and is tested by real handshakes
  (`TestMutualTLSBetweenServices` asserts the negotiated ML-KEM group;
  `TestPQCRequiredServerRefusesClassicalOnlyPeers`,
  `TestClassicalServerRefusesHybridOnlyPeers`).
- Enforcing it (b) was the wrong shape: `key_interface_ports` rows are
  per tenant, but a listener is per node and shared by every tenant. Two
  tenants could set `pqc_only` and `classical` on the same port. A real
  edge control is node-wide and owned by root administration.
- A preview (c) keeps a selector whose honest answer is always "not
  applied", for a need that is already met or needs a different design.

**Rejected.** Mapping `pqc_mode` onto svctls `kx_profile` (two settings for
one listener, and the tenant-scoped one would override a platform one).

**Open.** The Envoy edge listener sets no `ecdh_curves`, so its key exchange
is Envoy's default. If customers need to require hybrid at the edge, build
a node-wide edge profile that writes the Envoy config and prove it with a
handshake test.

**Enforced by.** `TestInterfacePortPQCModeRemoved` (the kernel's strict
decode rejects the field), `TestInterfacePQCModeDroppedPostgres`.

---

## 2026-09-29 — PQC policy: remove it; migration rules are the only PQC switch (6.3.0-beta)

**Decision.** Every field of the pqc service's tenant policy was removed
rather than enforced or listed as a preview, and the readiness scores were
replaced by the counts they were computed from.

**Why, per field.**
- `require_pqc_for_new_keys`: a keycore migration rule
  (`quantum_vulnerable -> decrypt_only`) already refuses new protection with
  quantum-vulnerable keys, with a date and an audited refusal. A second
  switch would be a second decision point (KEY_ACCESS_MODEL: one keycore
  decision).
- `profile_id`, `default_kem`, `default_signature`, `hqc_backup_enabled`:
  no consumer beyond recommendation text. Making them real would mean pqc
  choosing algorithms for keycore, which the customer's rules already do
  through `target_algorithm`.
- `interface_default_mode`, `certificate_default_mode`: nothing sets a
  listener's key exchange from them, and the product issues no PQC
  certificates (1.19.0-beta). The inventory can only honestly report what it
  measures, so interfaces are "not assessed".
- `flag_*`: they only suppressed findings. A findings list that can be
  switched off is not an inventory.
- Scores: 55/30/15 and 85/15 (hybrid as 0.7) had no source.
  "N of M classical" is measured and needs no weighting.

**Rejected.**
- *A preview entry with 409 on `PUT`.* A preview is for a capability we
  intend to build. Every field here duplicates the migration rules or has no
  target, so a preview would advertise a feature that shouldn't exist.
- *Enforce `require_pqc_for_new_keys` by having keycore call pqc.* That adds
  a cross-service dependency on the key-operation path to do what a
  migration rule does locally.
- *Keep the score but document the weights.* A documented guess is still a
  guess (rule 7).

**Enforced by.** `TestPQCPolicyRemovedAndNoInventedScores`,
`TestPolicyAndScoreDroppedPostgres`, and the inventory count assertions in
`TestPQCServiceReadinessPlanExecuteRollback`.

## 2026-09-29 — Swap drill runs in memory; no maturity tiers (6.1.0-beta)

**Decision.** The algorithm-swap drill generates throwaway keys in keycore's
memory and runs them through the key engine functions (`signWithKeyAlgorithm`,
`encryptWithKeyAlgorithm`, `mlkemEncapsulate` and their checks). It does not
create canary keys in the tenant's inventory. It passes the same FIPS check
and the same migration-policy decision (`policyRefusal`) a real key would.

**Why.** The drill must measure the code path customer keys use, on the
customer's hardware, without side effects. Canary keys would appear in
inventory, posture and CBOM counts, need destroy approvals, and could be
left behind by a failed run. The HTTP and storage layers add the same cost
to both algorithms, so leaving them out keeps the comparison about the
algorithms.

**Rejected.** Standard benchmark tables: numbers from other hardware, which
is what the drill replaces. A maturity-tier view (tiers 1–4): its scale comes
from a standards document, and the owner's rule is that the product quotes
none and the customer decides. The facts a tier would summarise are shown
where they are measured instead: rule coverage (posture), CARAF completeness
and decisions (risk assessment), and drill history.

**Enforced by.** `TestDrillMeasuresRealRoundTrips`,
`TestAgilityDrillRouteValidatedAndAudited`,
`TestAgilityDrillStrictRefusesNonModuleAlgorithm`.

---

## 2026-09-29 — Delegated key use: forward the user's own token (6.0.0-beta)

**Decision.** A service that performs a user's request forwards the user's
verified bearer token and the usage to keycore, which verifies the token
itself and decides as the user. Built in `pkg/delegation`; the model is
KEY_ACCESS_MODEL.md section 5.

**Why.** Keycore trusted service identities tenant-wide, so the user behind
dataprotect, payment and certs was invisible and their grants never applied.
The token is the only identity the service didn't make up: keycore checks
its signature, expiry and tenant with its own key.

**Rejected.**
- *The service names the user (a body field or header, as the playbook
  delegation in auth does).* That trusts the service to tell the truth about
  who asked; a compromised or buggy service could name anyone. Auth's
  delegated operations are narrower (one identity, re-checked against auth).
- *Swapping the request's claims for the user's.* The route permission (for
  example `key.usage.meter`) belongs to the service; users don't hold it.
  Keycore keeps the service's claims for the route and uses the user as the
  access actor.
- *Accepting the base operation for user grants (`encrypt` covers
  `fpe-encrypt`).* The owner asked for CipherTrust-level granularity, which
  keeps FPE, translate and CA signing as separate rights. Workload tokens are
  the exception, because their permission vocabulary has no such names.
- *Delegating `service-derive`.* It's a service-only route; dataprotect's
  metering call just before it carries the decision.
- *Delegating a new HSM CA's self-signature.* The key was made moments
  before by certs; the user was authorized to create the CA.

**Enforced by.** `TestDelegatedUseDecidesWithUserGrant`,
`TestDelegatedExportIsDecidedByTheTranslateGrant`, `TestDelegationRefusals`,
`TestDelegatedTenantMustOwnTheKey` (keycore), `TestAttachForwardsOnlyAUser`,
`TestMiddlewareKeepsOnlyAVerifiedToken` (pkg/delegation),
`TestDataprotectNamesItsUsage`, `TestTranslatePINNamesItsUsages`,
`TestHSMSignerCarriesRequestContextAndUsage`, and on real SoftHSM2
`TestHSMCAKeysSignInTheHSM` (usage of every HSM signature).

---

## 2026-09-29 — Automation/ALKM/PQC: remove what isn't real rather than document it (5.3.0-beta)

**Decision.** Where `docs/AUTOMATION_ALKM_PQC.md` described a capability
the code didn't deliver, the dead or fake code was removed and the guide
rewritten, rather than the rows being re-worded as "not wired". The
exceptions are real capabilities with a wrong label or gate: the sustained-risk
detector keeps running under an honest name
(`audit.security.sustained_risk_detected`) and becomes a playbook trigger,
because the playbook layer is where a response (disable the key) belongs.

**Why.** CLAUDE.md rule 8 prefers removal to a pretend feature. Dead code
with its own tests keeps getting cited as evidence (see learning.md). Three
pieces were harmful rather than inert: the KMIP auto-decommission refused
active clients after 90 days, `/tenants/onboard` audited provisioning that
never happened, and "auto-quarantine" named an enforcement that didn't occur.

**Rejected.**
- *Building the missing pieces now* (composite keys, HBS state tracking,
  dependency registry, KMIP last-seen tracking). Each is real work with its
  own design: composite keys need a key-format and KMIP story, and last-seen
  tracking would write a replicated table from every cluster node on every
  connect (docs/CLUSTERING.md). They can come back as features with tests.
- *Keeping automatic destroy in the lifecycle reconciler* and making it send
  the pre-destroy acknowledgements. That would let a timer irreversibly
  destroy keys under a service identity, which the playbook rule reserves for
  a governance approval.
- *Keeping Y2Q* next to the crypto-agility CARAF risk ratings: two
  prioritisation scores would disagree. The unused Y2Q code goes, and the
  CARAF slices add the one that is used.

**Enforced by.** The tests listed in the 5.3.0-beta CHANGELOG entry, the
route index (`scripts/check-doc-routes.py`), and
`TestTriggerSubjectsAreEmitted` for the new trigger.

---

## 2026-09-29 — Key visibility: see only the keys you can use (5.0.0-beta)

**Decision.** The owner chose option A: a key is listed and readable only by
its creator, holders of an active grant on it (directly or through a group,
including a new view-only `read` grant), workloads bound to it, tenant
admins, service identities, and holders of `key.inventory.read`, a
permission for auditors who need the full inventory. Tenant-wide inventory
and analytics views need `key.inventory.read`.

**Why.** Access already worked this way: a user without a grant couldn't use
a key, so listing it only leaked names that often reveal systems, customers
or data sets. Deny-by-default is the repo's secure-default rule, and it
matches how CipherTrust scopes keys to groups.

**How.** The filter is a condition in the list query (creator or one of the
granted key IDs), not a filter over a fetched page, so restricted callers
get full pages and cursors reach every visible key. A hidden key answers
exactly like a missing one, and the tenant is checked before any lookup, so
the response never confirms that a key exists. Refusals are audited
(`reason: not_visible`).

**Rejected.**
- *Option B, tenant-wide by default with per-key restriction.* It keeps the
  leak for every key nobody remembered to restrict.
- *403 for a hidden key.* It confirms the key exists; a 404 identical to a
  missing key's doesn't.
- *Filtering the page after the query.* It returns short or empty pages to
  restricted users and breaks cursor paging.
- *Making `Service.GetKey` itself visibility-aware.* Background jobs
  (rotation, reconciler, lifecycle) call it with no user; the check belongs
  on the read routes.

**Enforced by.** `TestKeyListShowsOnlyVisibleKeys`,
`TestScopedKeyListPagesFully`, `TestHiddenKeyReadsLookMissingAndAreAudited`,
`TestReadGrantIsViewOnly`, `TestHiddenKeyCheckNeverCrossesTenants`,
`TestInventoryViewsNeedInventoryPermission`,
`TestFingerprintCheckRespectsVisibility`, and on real Postgres
`TestKeyVisibilityPostgres` (group grants, cursor paging).

---

## 2026-09-29 — Key access: one decision, four layers, enforced usage (4.0.0-beta)

**Decision.** The owner asked for CipherTrust-level key granularity ("not
directly copied", "strong key activity", no existing feature lost) and for
the design to be implemented "properly and strictly". Key access is one
keycore decision for every interface: usage mask, lifecycle phase, grant or
label policy, conditions, and explicit deny, which always wins. The model,
its enforcement points and the strict implementation rules are in
[SECURITY/KEY_ACCESS_MODEL.md](SECURITY/KEY_ACCESS_MODEL.md). 4.0.0-beta
starts phase 0: keycore refuses tokenless requests, and its access and
key-management routes go through `pkg/route` with permissions, owner-or-admin
for grant changes, and the actor from the token.

**Why.** CipherTrust stores dates like protect-stop and usage bits without
acting on all of them, and splits KMIP, NAE and CTE metadata into separate
tabs that can disagree. A single decision fed by the same fields for every
protocol can't drift, and each layer refuses with its own reason, so the
audit trail explains every denial. Reviewing it found that keycore's
management routes had no permission check and accepted tokenless requests,
which moved the route work to the front.

**Rejected.**
- *Copying CipherTrust's screens and 26 flat usage checkboxes.* Usages are
  grouped, filtered by algorithm, and offered only where an operation
  enforces them. EMV cryptogram usages are left out until payment implements
  them.
- *Label policies in `services/policy`.* That service is the tenant
  guardrail layer; putting grants there adds a network hop to every crypto
  operation. Label policies live in keycore next to grants (pending the
  owner's confirmation, model section 13).
- *Migrating the key-management handler bodies in the same change.* They
  carry domain logic that the rotation scheduler and playbooks share. They
  go through the kernel via a thin adapter now (permission, tenant check,
  `audit.key.<action>_requested` including refusals), and the service keeps
  its domain events. Moving the bodies onto `route.Call` is the rest of
  keycore's migration.
- *Keeping `updated_by` / `created_by` accepted but ignored.* Rejected: a
  client that sends an actor has a bug or is forging one; a 400 surfaces it.

**Enforced by.** `TestTokenlessManagementRequestsAreRefused`,
`TestReadonlyUserCannotManageKeys`, `TestKeyGrantsChangeOnlyByCreatorOrAdmin`,
`TestAccessRoutesTakeActorFromTokenOnly`,
`TestCreateKeyRefusesAnotherTenantInBody`, and `routetest.RefusalsAudited`
on both new routers. The model's section 10 rules bind later phases, and
CLAUDE.md points to it.

---

## 2026-09-29 — CARAF in keycore, readiness folded into Crypto Agility (5.4.0-beta)

**Decision.** The risk assessment lives in keycore beside the migration
policy (same router, permissions and match vocabulary), with threats and
assets entered by the customer. The pqc service stays the scan and
execution engine, now behind the route kernel (5.2.0-beta), and its UI is a
view of the Crypto Agility tab instead of a separate tab.

**Why.** One home per view: policy, risk and execution are one workflow.
Assets link keycore keys directly, so exposure uses live algorithms.

**Rejected.**
- *Product-supplied rating bands or threat dates (CARAF's example tables).*
  The customer decides; exposure is plain X + Y against Z in their years.
- *Gate "accept" behind a governance approval.* Kept simple: an acceptance
  must name an owner and a future review date and lapses visibly. A
  Playbook on `crypto_risk_decision_recorded` can require approval.
- *Keep the old tab's readiness score and PQC-policy switches.* The score
  was an unsourced weighting; the switches are enforced nowhere.
- *Add a governance tenant-tier setting.* A migration rule already expresses
  every floor, with a date.

---

## 2026-09-29 — Crypto agility: the customer's policy decides; no standards quoted (5.1.0-beta)

**Decision.** The owner: "avoid quoting direct sources, drafts, references
let customer decide when and what he wants to migrate as per his policy".
This supersedes the dated schedule of the 3.2.0-beta entry below. The
catalogue keeps technical facts only (strength, post-quantum category,
quantum vulnerability, weak). Each tenant writes migration rules (what, from
when, to what); keycore enforces them on every key operation, and the
tenant minimum algorithm tier is enforced beside them.

**Why.** Migration timing depends on the customer's risk, data lifetime,
contracts and regulator, not on the vendor. A product that ships dates makes
the vendor's reading of a draft the customer's policy.

**Rejected.**
- *Ship the standards dates as a default rule set.* Still the vendor
  deciding; the customer starts from an empty policy and adds rules.
- *Record rules without enforcing them.* A rule that changes nothing is the
  "stored but never enforced" failure (learning.md 2026-09-29).
- *Refuse lifecycle operations under `disallowed`.* A key must stay
  exportable and destroyable so it can be retired.

**Enforced by.** `TestCryptoPolicyEnforcedOnKeyOperations`,
`TestTenantMinAlgorithmTierEnforced`, `TestAgilityPostureAgainstCustomerPolicy`,
`TestAgilityPolicyRulesValidatedAndAudited`,
`TestTimelineIsTheCustomersPlanDeadlines`, and the tab's Playwright spec,
which fails on any standards reference.

---

## 2026-09-29 — Crypto agility: one cited NIST catalogue, drafts shown as proposed (3.2.0-beta)

**Decision.** The owner asked for the Crypto Agility tab to follow NIST
crypto agility guidance and the CARAF paper (Ma et al., *Journal of
Cybersecurity* 2021, cited by CSWP 39 §5), then "as per the updated doc"
(CSWP 39-upd1). Every algorithm fact (strength, quantum vulnerability, NIST
status and dates) now comes from `pkg/cryptocatalog`, copied from SP 800-57,
SP 800-131A Rev. 3 (ipd), IR 8547 (ipd) and FIPS 186-5/203/204/205, each row
citing its table. The tab measures live keys against that schedule. The
agility score is removed.

**Why.** CSWP 39-upd1 §5.2 asks for one machine-consumable crypto policy kept
in step with NIST, and its 2026 update (§2.3, Appendix C) moves the
quantum transition dates to IR 8547 and SP 800-131A Rev. 3. Four
hand-kept lists disagreed and one of them drove policy enforcement
(docs/SECURITY/ALGORITHM_TRANSITIONS.md, learning.md 2026-09-29).

**Rejected.**
- *Keep a 0–100 agility score.* Its weights (0.6 per legacy point, 0.2 per
  non-PQC point, "20% quantum-safe" target) had no source. Counts against a
  cited schedule say the same thing and can be checked.
- *Wait for the final SP 800-131A Rev. 3 and IR 8547.* CSWP 39-upd1 already
  points to them; the dates are shown as proposed, and a test pins each row
  so finalisation is a one-file change.
- *Classify by substring (contains "RSA", "KYBER").* That is how SLH-DSA,
  hybrids and RSA-4096 were mislabelled. The catalogue parses exact names; a
  name without a parameter set is not assessed.
- *Keep `classical-128` as RSA-2048's tier so existing floors keep passing.*
  That keeps a false label on an enforcement path. Tenants who accept
  112-bit keys say so with `classical-112`.
- *Supply CNSA 2.0 or EU dates.* They are not in the documents CSWP 39-upd1
  cites and the ones in pqc were wrong; plans against other standards must
  pass an explicit deadline.

**Enforced by.** `TestCatalogMatchesNISTTables` and the other
`pkg/cryptocatalog` tests, `TestMeetsFloorFailsClosed`,
`TestCryptoFloorUsesNISTStrengths`, `TestUnknownFloorRefusedAndAudited`,
`TestAgilityPostureAgainstNISTSchedule`, `TestTimelineMilestonesAreSourced`,
`TestPlanDeadlineMustBeSourced`, `TestDiscoveryLabelsFollowTheCatalogue`.

**Next.** The CARAF assessment on the same tab: a threat register (Z),
asset profiles for the eight inventory factors (sensitivity, shelf-life X,
ownership, implementation, location), X/Y/Z and cost ratings, a decision per
asset (secure, accept with expiring approval, phase out, compensating
control), a roadmap on the pqc engine, and a CSF-tier maturity view
(CSWP 39 §6.5).

---

## 2026-09-28 — Audit integrity: sign the chain head, no Merkle trees (3.0.0-beta)

**Decision.** The owner: "let go off the merkle tree and sign the logs",
"remove every instance of merkle". Audit tamper evidence is the hash chain,
a per-event HMAC under a key derived from the audit master key, and signed
checkpoints: every 10 minutes each node signs `{tenant, chain, sequence,
chain_hash, signed_at}` of each chain it writes with ECDSA-P384. The Merkle
epochs (audit), the certificate tree (certs) and the anchor's `merkle_root`
(keycore) are removed.

**Why.** The chain hash already commits to every earlier event, so one
signature over the head proves the same thing a Merkle root did, with no
extra tables. The Merkle layer added nothing: no root left the database,
and verify trusted the caller's root. Nobody used inclusion proofs.

**Rejected.**
- *Signing each event, or signing with the root key.* The owner first
  suggested the root key. A key that protects other keys must not sit on a
  path used thousands of times a day in a network-facing service, and key
  separation (one key, one purpose) is what a FIPS reviewer checks.
- *A checkpoint key stored in keycore or sealed under the MEK.* Nothing
  needs the private key after the process ends; storing it only creates
  something to steal and to re-wrap on rotation. The key lives in memory
  and its public key is an audit event, trusted only while that event's
  hash and HMAC verify.
- *Keeping `AUDIT_EVENT_SIGNING_KEY_B64` and generating it in installers.*
  Rule 6 keeps service keys out of the environment; the MEK already exists,
  is keycore-protected and is the same on every cluster node.
- *Fixing the Merkle tree* (RFC 6962 hashing, consistency proofs, root
  export). More code for a property the signed head already gives.

**Enforced by** `TestVerifyChainCatchesRewriteWithHMACKey`,
`TestTargetIntegrityRejectsTampering`, `TestCheckpointKeyTrustedOnlyThroughRegistration`,
`TestCheckpointVerifiesOutsideTheService`,
`TestEventHMACKeyFromMasterKeySurvivesRestart`. **Open:** the tail after the
latest checkpoint (up to 10 minutes), and a full rewrite by someone with the
HMAC key and database access, are caught only by the copies in the
customer's SIEM ([SECURITY/AUDIT_INTEGRITY.md](SECURITY/AUDIT_INTEGRITY.md)).

## 2026-09-28 — The KMS hands over an SBOM; it does not track vulnerabilities (2.19.0-beta)

**Decision.** The owner: tracking vulnerabilities is "not the job of [an]
enterprise key management product… it has to be vulnerability management".
The sbom service keeps generating, diffing and exporting the platform's SBOM
(CycloneDX, SPDX) and the tenant's CBOM. CVE matching (OSV, Trivy, offline
advisories), its routes, table, dashboard tab and bundled Trivy binary are
removed. Compliance's hard-coded `/compliance/sbom*` copy goes with it.

**Why.** A vulnerability feed has to be current, complete and triaged to be
worth anything. The customer's vulnerability-management tool does that
across their whole estate; a second, partial feed inside the KMS competes
with it and gives auditors two answers. The matcher also pulled a scanner
binary and outbound OSV calls into a FIPS-targeted appliance, and it needed
repeated fixes to stay honest (see learning.md).

**Kept, because they are key management:** the CBOM and PQC readiness,
quantum-vulnerable algorithm classification, and keycore's compromise
advisories (an advisory against an algorithm or key marks the affected keys
compromised). Scanning our own release (`govulncheck`,
`infra/security/cve-scan.sh`) is vendor release evidence, not a product
feature, and stays in CI.

**Rejected.** Keeping the tab as a labelled preview: it would still be a
capability the product should not have. Keeping offline advisories for
air-gapped sites: those sites run their own vulnerability tooling offline
against the exported SBOM.

**Enforced by** `TestSBOMVulnerabilityRoutesRemoved`,
`TestComplianceSBOMRoutesRemoved`, and the CLAUDE.md rule under "How we
build".

## 2026-10-01 — Posture needs 14 days of the tenant's own history before it scores or compares (7.19.0-beta)

**Decision.** The owner asked how many events posture needs before it gives a
baseline, and said 5, 10, 100 or 1000 cannot be accurate. An event count is
the wrong measure. Posture now needs **14 complete days** (28 for a stable
baseline) of the tenant's own audit history, and a rate signal needs **385
events** of its kind. Until then the risk score is `assessed: false` and no
comparison is made. After that, "unusual" is a significance test against the
tenant's own daily mean and variance (p < 0.001 and a per-signal floor), not
"twice yesterday". Full rules: docs/SECURITY/POSTURE_BASELINE.md.

**Why days, not events.** A baseline has to capture normal variation,
including the weekly cycle. Volume in one burst carries none of that; a
quiet tenant's two weeks carry all of it.

**What was wrong underneath.** The "baseline" was the previous 24 hours. A
new install raised spike findings on day one. With no finding the score was
`events / 200`. The sync took the newest 500 audit events a minute and
dropped the rest. Most signal patterns matched no subject the platform
emits, so failed logins, key destroys and expiries had always counted zero.

**Rejected.**
- A minimum event count (for example 1000) as the gate: fast tenants would
  qualify in an hour with no notion of a normal day.
- Same-weekday comparison: 14 to 28 days give two to four observations per
  weekday, too few. The negative binomial absorbs the weekly swing instead.
- Keeping `events / 200` as a "low" default: activity is not risk, and the
  rule is "not assessed", never a guess.
- Keeping the cluster drift and replication signals at zero: nothing emits
  them, so they are removed.

**Cost accepted.** Existing risk snapshots become unassessed and drop out of
the trend chart; they had no baseline behind them. A deployment with at
least 14 days of audit history is assessed again as soon as the first sync
has caught up, because the baseline is built from the audit trail.

**Enforced by** `TestCountNeedsMinBaselineDays`,
`TestRateNeedsEnoughBaselineEvents`, `TestScanNotAssessedWhileBaselineBuilds`,
`TestBusyHealthyTenantScoresZero`, `TestSignalSubjectsAreEmitted`,
`TestSyncReadsEveryEventFromCursor`, and the Posture smoke test.

## 2026-09-30 — Analytics windows from a day to since uptime, counted by the server (7.17.0-beta)

**Decision.** Every analytics view (Audit Log → Activity, Alert Center →
Analytics, Posture) offers the same windows: since uptime, last day, week,
month, 6 months and year. The server counts the whole window. The audit
service has `GET /audit/activity/stats` (SQL `GROUP BY` and `SUM(CASE ...)`, portable
across Postgres and SQLite). Reporting streams every alert in the window
(`ScanAlerts`, no cap). Posture returns the latest risk snapshot per bucket.
Buckets come from `pkg/timebucket`, one rule for every service. A drill-down
asks the server for the same filters it counted with, paged 100 at a time.
"Since uptime" means no lower bound: everything recorded since the platform
started.

**Why.** The owner asked for windows up to a year and since uptime. The old
Activity panel paged the newest 2000 events in the browser, and alert
statistics read the newest 5000 alerts. Over a year either one would have
charted a sample and called it the total.

The route is `/audit/activity/stats`, not `/audit/stats`: that path was the
removed audit alert store's, which returned alert counts under a name that
promised event statistics (2.16.0-beta). `TestAuditAlertStoreRemoved` keeps
it unserved.

**Rejected.** Raising the browser sample limit: a year of audit events can
be millions of rows. Grouping time buckets with `date_trunc`/`strftime`:
dialect-specific. Cumulative `SUM(CASE WHEN timestamp >= start)` columns give
each bucket by subtraction in one portable query.

**Still bounded.** MTTD looks up each alert's audit event, so it measures the
newest 5000 linked alerts in a window and says when the window had more.
Posture charts findings detected in the window, paged in full up to 5000, and
says when it had more.

**Enforced by** `TestAuditStatsWindows`, `TestAlertStatsWindows` and
`TestRiskTrendWindows` (each also on Postgres): every chart count equals its
drill-down's list. Also `pkg/timebucket` tests and the smoke test, which
checks that "Last year" sends a 365-day window and "Since uptime" sends none.

## 2026-09-30 — Charts live beside their entries and drill into them (7.15.0-beta)

**Decision.** Audit charts moved from Overview → Analytics to Audit Log →
Activity, and alert charts to Alert Center → Analytics. Overview → Analytics
keeps key inventory and operations. Every chart segment (bar, slice, point,
count row) is clickable and lists exactly the entries it counts. An entry
opens its existing detail: the audit event modal, the Alert Center triage
card (Acknowledge and Escalate work from the drill-down), or the Posture
finding modal. A posture risk point or the gauge opens that snapshot's
scores and signals.

**How the counts stay equal.** Each drill is a predicate over the same rows
the chart was built from, using bucket functions shared with the chart
(`riskBucket`, `findingSeverityBucket`, and so on). Alert charts come from
reporting's aggregates, so the panel also pages through the same newest 5000
alerts that `AlertStats`, `MTTRStats`, `MTTDStats` and `TopSources` read, and
filters them with predicates that mirror the Go code (`normalizeSeverity`,
UTC creation day, set `resolved_at`).

**Why.** The owner wants to go from a number to the records behind it in one
click. A chart in a separate Analytics tab made that a hunt through another
tab's filters, and some groupings (risk bucket, hour, top actor) had no
filter at all.

**Rejected.** Having a click switch to the Events or Alerts list with its
filters set. Those lists filter only on some dimensions (not risk bucket,
hour or MTTR), and the Alerts list hides informational alerts that the
charts count. The two would have disagreed.

**Amends** the 2026-09-28 decision below: charts no longer all live in
Overview → Analytics.

**Enforced by** the CLAUDE.md rule "Every chart drills into its entries" and
`tests/smoke-tabs.spec.ts` ("analytics, alerts and audit each have a single
home"). That test clicks a top-actor row and a severity slice and asserts
that the drill-down lists only the matching entries.

## 2026-09-28 — One home per kind of view (2.12.0-beta)

**Decision.** Charts and trends live only in Overview → Analytics (Key
inventory, Operations, Audit activity, Alerts). Alerts are triaged only in the
Alert Center (reporting's store). The Audit Log is the record and its
integrity (Events, Forensics, Merkle). Compliance shows what the compliance
assessment measured, plus its reports. Posture keeps operational drift cards.
The cryptographic asset inventory is SBOM / CBOM.

**Why.** The owner found Analytics in two places, alerts in two places, and a
Compliance page full of numbers that weren't compliance: alert MTTD/MTTR,
operational cards copied from Posture, a phantom FROST card and a
browser-scored inventory. Each copy drifted and none was obviously the real
one.

**Rejected.** Keeping the Audit Log Alerts tab as a second view of the audit
service's own alert table. It is a separate store from the Alert Center's,
so the two lists disagreed. Retiring or merging that backend store is a
separate change; the UI no longer shows it.

**Enforced by** `tests/smoke-tabs.spec.ts` ("analytics, alerts and audit each
have a single home") and the CLAUDE.md rule under "How we build".

## 2026-09-28 — Webhooks and SIEM are Playbooks connections; compliance holds every outbound credential (2.10.0-beta)

**Decision.** The owner asked for webhooks and SIEM inside Playbooks, not a
separate tab. There is one store of outbound endpoints and credentials:
compliance's sealed connections. It holds Slack, Teams, webhook, Jira,
ServiceNow, and the SIEM types from `pkg/siem`. Three things use it:

- playbook actions, including the new `send_siem_alert`;
- audit event streams, shown under Playbooks → Event streaming;
- governance approval notices.

The audit service and governance hold a connection ID only. They open the
connection through `POST /compliance/connections/{id}/resolve`, which
admits only their service identities and audits every release.

**Why.** The same kind of credential lived in three places with three
security postures: sealed and exposure-tracked in compliance, sealed
separately in audit, and plaintext in governance. One store gives one
validation path, one exposure register, one rotation story and one screen.

**Rejected.**
- *Continuous SIEM streaming as a playbook action.* A SIEM needs every
  event, not incidents. As a playbook it would create one run per audit
  event, and each unattended run re-checks the person's authority with
  auth. Each delivery also emits an audit event, so a playbook matching
  every event would trigger itself. Streaming stays in the audit service,
  which already excludes its own delivery events. Only its credentials and
  UI moved.
- *Compliance delivers on the audit service's behalf* (a `deliver` endpoint,
  so secrets never leave compliance). The kernel audits every call, so each
  streamed event would add a compliance event, and a `*` stream would loop.
  It would also add a per-event internal hop. The audit service now opens
  the connection itself, caches it for 60 seconds, and one
  `connection_resolved` event covers many deliveries.
- *Connections owned by the audit service.* Compliance already had the
  sealed store, tests, exposure register, the jira/servicenow types, and the
  UI. Moving it would have been the larger migration for the same result.

**Enforced by.**
- `TestConnectionResolveRestrictedToAuditAndGovernance`: every other
  caller, admins included, is refused and audited.
- `TestStreamAPIRequiresConnection`: inline URLs and secrets are refused.
- `TestGovernanceSettingsRequireNotifyConnection`.
- The migration tests in audit and governance.
- The Playwright spec `playbook-streams.spec.ts`: the Webhooks tab is gone,
  and a stream sends no credential.

---

## 2026-09-28 — The generated product map is checked, not auto-committed (2.9.0-beta)

**Decision.** `make conformance` runs `generate_product_map.py --check` and
fails when `docs/generated/` is stale. The author reruns the generator and
commits the result with the change.
*Rejected:*
- CI regenerating and committing to `main` (a bot writing to `main`, and a
  commit that didn't pass the checks run on its parent).
- Not committing the output (reviewers and other tools read it from the
  repo).
- A warning instead of a failure (it drifted for five releases while
  nothing failed).

---

## 2026-09-28 — Playbook follow-ups: stored thresholds, required approval policy, tampering on the stream (2.6.0-beta)

- **Threshold counts are stored, in a replicated table the primary
  writes.** This supersedes 2.5.0's in-memory counts. Only events that
  match a threshold playbook's trigger and filters are written, not every
  audit event, which was the cost that earlier decision avoided. Rows older
  than the window are pruned on each write. *Rejected:* rebuilding counts on
  a new primary by replaying the stream (the durable consumer has already
  acknowledged those messages).
- **The playbook approval policy is required.** Disabling or narrowing it is
  refused, and a copy disabled under 2.5.0 is switched back on (audited).
  *Rejected:* letting admins disable it and making gated steps skip
  approval (that removes dual control without anyone deciding to), and
  leaving it disableable with a warning (a silent outage of every gated
  step).
- **The cooldown is stored too (2.7.0-beta)**, as `last_fired_ms` on the
  playbook row and claimed with a conditional `UPDATE ... WHERE
  last_fired_ms <= now - cooldown`. That makes it atomic without a lock
  table. *Rejected:* a separate firings table (one row per playbook is
  enough).
- **`chain_broken` goes through the stream.** Ingest records it once, the
  same way every other event is recorded. If the publish fails, it is
  written directly, so a break is never lost. *Rejected:* recording it
  directly and also publishing it (ingest would store it twice).

---

## 2026-09-28 — Playbooks as the response layer (2.5.0-beta)

**Decision.**
- **Incidents stay in reporting.** Playbooks respond to its
  `incident_opened` and `alert_created` events, act on incidents and alerts
  through its routes, and record the incident on the run. The dashboard
  joins them (incident → runs). *Rejected:* a playbook-owned incident
  record, which would be a second, competing incident list.
- **Authority is re-checked by auth at run time.** Auth owns users and roles
  (`POST /auth/delegated/authority`, kms-compliance only), and an
  unreachable auth fails the run closed. *Rejected:* storing the saver's
  token or a refresh token (a long-lived user credential at rest), and
  copying role data into compliance.
- **Delegated operations** (disable user, revoke API key or client) are
  auth routes that only kms-compliance may call, naming the person. Auth
  verifies that person now, and never targets the person themself, the last
  full administrator or a platform identity. The person is a delegation
  auth verifies, not an identity it trusts: the caller's identity is its
  verified token (CLAUDE.md rule 4). *Rejected:* letting auth admit the
  compliance identity on its admin routes (power over every user in every
  tenant).
- **Approvals are governance requests, resumed from governance's own
  events.** `quorum_reached` only prompts compliance to read the request
  back; the run continues if it is approved and bound (target, action,
  requester, payload hash of the action as now defined). *Rejected:*
  governance callbacks that execute on approval (the approver's vote would
  become the executor), and polling.
- **Credentials live in connections under the compliance MEK** (`pkg/mek`,
  like audit webhooks), and existing inline values are migrated and
  recorded as exposed. *Rejected:* sealing values in place inside
  `actions_json` (every playbook edit would handle secrets), and dropping
  existing values (a silent outage).
- **Email goes through governance's SMTP**, only to active users of the
  tenant. *Rejected:* an SMTP client in compliance (a second mail
  configuration), and arbitrary recipients (a mail relay for anyone who can
  write a playbook).
- **Thresholds count in memory on the primary** (superseded in 2.6.0-beta:
  now stored). A lost count after a failover delays a threshold trigger; it
  never invents one. *Rejected:* a
  replicated counter table written on every audit event.
- **No chains.** Events whose actor is kms-compliance, correlated to a run,
  or alerts raised from them don't fire playbooks; the per-playbook cooldown
  is the backstop for legacy emitters that carry neither.

---

## 2026-09-28 — Playbooks run on a person's authority, from a catalogue of real events (2.4.0-beta)

**Decision.** Playbook actions keep running as the compliance service
identity (keycore and certs admit service principals), but a playbook
borrows that identity only on the authority of a person who holds the same
permissions. Saving an enabled playbook, or running one by hand, needs every
permission its actions use; `authorized_by` records the saver, and automatic
runs are refused while it is empty. Triggers and actions come from one
catalogue (`playbook_catalog.go`) that the API validates against, the
executor runs from and the dashboard renders from `GET .../catalog`. A
trigger lists only subjects a service emits, checked by
`TestTriggerSubjectsAreEmitted`.

*Rejected:*
- **Running actions with the saver's own token.** Tokens expire, and a
  stored refresh token would be a long-lived user credential at rest. This
  is the right end state for actions whose target service won't admit a
  service principal (`disable_user`, `revoke_api_key`); it needs delegated,
  scoped credentials (step 2), so those actions are removed until then.
- **Letting auth admit the compliance identity for user and API key
  changes.** It would give one service account power over every user in
  every tenant.
- **Keeping `destroy_key` and ticking keycore's pre-destroy
  acknowledgements automatically.** Those checks exist so a person confirms
  an irreversible act; a playbook confirming them defeats them.
- **Keeping trigger names nothing emits "for later".** A trigger that can't
  fire is a feature that pretends (rule 8).
- **Rewriting stored action names in a migration.** The tables are
  replicated, so a data rewrite would also run on members; names are mapped
  on read instead.
- **Re-checking the saver's current grants at trigger time.** It needs a
  service-side lookup of another user's permissions that auth doesn't offer
  yet. Until then a playbook keeps its authorization after its author loses
  the permissions; saving it again, or disabling or deleting it, is the
  control. Closed in 2.5.0-beta: auth re-checks the person before every automatic run.

**Also:** outbound actions go through `pkg/ssrfguard`, not the svctls
router, so they never present the service's mTLS certificate; triggered runs
happen on the primary only; events older than 15 minutes don't fire. The
watchdog raises incidents and acts on nothing; its `audit.health.incident`
is the `service_health_degraded` trigger.

---

## 2026-09-28 — Operations metrics: any metered event, cluster-wide on the primary, no backfill (2.2.0-beta)

**Decision.** An event is counted when its details carry
`pkg/audit.MeteredOp`. Each operation is metered once, by the service
whose code does the cryptography. The primary counts members' operations
from the relay of their replicated events, and history before 2.1.0 is not
backfilled.

**Why.** A metering flag on the event, instead of a list of actions in the
audit service, lets every service and every kernel route (`Spec.Metered`)
join without changing the consumer. Metering where the crypto runs keeps one
request from being counted by both the front service and keycore. The relay
cursor already delivers each member event to the primary exactly once. Doing
the metric write in the same transaction as the cursor gives the same
guarantee with no new transport or node-to-node endpoint. The primary's
ingest still skips the relayed copy, so nothing is counted twice.

**Rejected.**
- Metering from `pkg/auditmw`'s generic request event. It is whole-ms, can
  be switched off with `AUDIT_CAPTURE_HTTP_REQUESTS`, cannot tell a refusal
  from a failure, and misses payment's TCP server.
- Replicating `ops_metrics_hourly`. Rows are upserted on every node, which
  logical replication with a single writer per row doesn't allow.
- Computing metrics by query over `audit_events`. It reads millions of rows
  per page load, and percentiles need Postgres-only functions.
- Backfilling from old events. Before 2.1.0 a wrap was logged as an
  encrypt, a MAC as a sign, with no duration and no refusals, so the
  history would be relabelled guesses (CLAUDE.md rule 8). The dashboard
  shows `recorded_since` instead.

**How.** `TestOpsMetricsCountAnyServicesMeteredEvents`,
`TestRelayCountsMemberOperationsOnce`, `TestMeteredRouteMarksEveryEvent`,
`TestDataProtectOperationsMetered`, `TestPaymentOperationsAuditedAndMetered`,
`TestLocalCertificateSigningMetered`, `TestCryptoOpsAuditedWithOutcomeAndDuration`.

**Closed in 2.3.0-beta.** A member forwards its Operations metrics reads to
the primary (`clusterroute.ForwardReads`). Batch calls add their `count`
to `value_count`. An operation is still one request, and values are
reported next to it rather than inflating the operation count or
distorting per-operation latency.

## 2026-09-28 — Operations metrics come from audit events, shown in Analytics (2.1.0-beta)

**Decision.** Key-operation throughput, latency and errors are the
Operations section of Analytics, not a tab of their own. The audit service
builds them from the `audit.key.<op>` events keycore emits for every key
operation. Latency percentiles come from a fixed-bucket histogram.

**Why.** The owner asked whether the tab needed to be separate. Analytics
already answers "how are our keys doing", and operations are the usage half
of that answer. The audit event is the one record every operation already
has to produce (CLAUDE.md rule 2), so deriving metrics from it gives one
source of truth and no second write path to drift from it.

**How.** Keycore's crypto entry points defer `auditCryptoOp`, which names
the event after the operation that ran and carries `duration_ms` and
`result`. Audit's `ProcessEvent` calls `recordOpMetric` after the event is
persisted, so an event that fails to persist is not counted. Enforced by
`TestCryptoOpsAuditedWithOutcomeAndDuration` (keycore) and
`TestOpsMetricsBuiltFromIngestedKeyOpEvents` (audit).

**Rejected.** Keeping the removed record endpoint (`/ops-metrics/record`) and having keycore call
it: that is a second path, and any authenticated caller could post
numbers. Estimating percentiles from the average: that is fabricated data
(rule 7). Storing every sample for exact percentiles: that is unbounded
growth on a hot path. Histogram bounds are the honest resolution.

**Closed in 2.2.0-beta.** Metrics were per node; see the next entry.

---

## 2026-09-28 — Threat & Exposure folded into Keys, Posture and Reporting; leak scanner removed (2.0.0-beta)

**Decision.** The Threat & Exposure tab is removed.
- Keycore keeps threat detection, because the usage trail lives there, and
  runs it every minute on every node.
- Signals leave keycore only as `audit.keycore.threat_signal_raised`.
  Posture raises a finding per signal, and Reporting raises critical and
  high signals as alerts, both from the audit pipeline they already
  consume.
- Canary keys are created from Keys.
- The leak scanner and the credential → key binding registry are deleted.

**Why:**
- Detection that ran only while the tab was open could not alert anyone.
- Posture already has findings, risk scoring, remediation and approvals,
  and Reporting already feeds the header's unread count. A separate
  console duplicated both.
- A KMS scanning pasted text or a folder on its own host is not credible
  secret scanning. That belongs in CI tooling that sees repositories and
  images, and the owner's rule is to remove what isn't really built
  rather than leave it half-done.

*Rejected:*
- **Posture calls a keycore threat API.** That adds a second client and
  identity, where the audit pipeline already carries the signal to Posture
  and Reporting by construction.
- **Sweeping only on the primary.** `key_usage_events` and
  `threat_signals` are node-local and crypto runs on every node, so a
  primary-only sweep would miss member traffic. Every node sweeping its
  own trail writes nothing replicated. The cost is that volume baselines
  are per node.
- **A canary as a real key with material.** A decoy that resolves would
  answer the attacker's crypto requests. The not-found decoy trips on the
  first reference and reveals nothing.
- **Keeping the leak scanner as a Posture sub-view.** The owner chose
  removal.

**Enforced by:**
- `TestThreatSweepCoversEveryTenantSeparately` and the `TestThreat*` tests
  (keycore);
- `TestThreatSignalBecomesFindingOnce` (posture);
- `TestThreatSignalsBecomeAlertsOnScheduledSync` and
  `TestListAlertsDoesNotSyncOnMember` (reporting);
- `TestCanaryRoutesRefusalsAudited`.
## 2026-09-28 — One Health view, in Administration (1.39.0-beta)

**Decision.** Platform > Health and Administration > Health are merged into
Administration > Health. The live service list (auth's discovery and TCP
checks, with restart) stays on top. Watchdog heartbeats, incidents and
reconciler status sit under it as their own sections.

**Why.** They answer the same operator question ("is the platform up?")
from different signals: probes from outside versus liveness each service
reports. Two tabs with one name that disagreed was confusing, and one of
them never worked. Restart is an administration action, so the merged view
belongs there.

**How.** The watchdog and reconciler serve their reads through `pkg/route`
with a new `health.read` permission, instead of reusing `auth.self.read` as
`/auth/system-health` does. Incidents and controller errors are operational
detail, not something every user needs. The dashboard calls them directly
through Envoy (`/svc/watchdog`, `/svc/reconciler`); auth does not proxy
them.

**Rejected.** Aggregating everything in auth's `/auth/system-health`: it
would couple auth to two more services and hide which one failed.

## 2026-09-27 — A key's history comes from its audit trail, shown on the key (1.38.0-beta)

**Decision.** Source Traceability (a discovery-owned `lineage_events` store
with its own graph, provenance, custody and tamper-check views) is removed.
A key's history is its audit events. They are verified per key by the audit
service (`GET /audit/targets/{id}/integrity`), and its callers come from
keycore's `key_usage_events` (`GET /keys/{id}/consumers`). Both appear in
one **History & usage** panel in the key detail view, where people look
before they rotate or delete.

**Why:** lineage had one writer, a manual form, so it recorded claims, not
events. Its tamper check could not fail. The audit trail already records
every key operation with an actor, and it is already tamper-evident (hash
chain, per-event HMAC, Merkle epochs), so a second store would only drift
from it. The usage trail is what keycore itself writes on every crypto
operation.

*Rejected:*
- fixing lineage in place (it would still need a real writer that duplicates
  audit, and a second integrity scheme to certify);
- a separate "history" tab (the question comes up on a key, right before a
  rotate or delete);
- verifying on every panel open (each run is itself audited against the
  key; verification runs when the user asks);
- merging usage across cluster nodes in this change (`key_usage_events` is
  node-local by design; the response says `node_local: true`).

Enforced by `TestTargetIntegrityRejectsTampering` (each way stored data can
be altered is rejected), `TestEventMerkleProofUsesSealedRoot`, and
`TestKeyConsumersFromUsageTrail`.

---

## 2026-09-27 — Built-in approval policy for posture escalation (1.35.0-beta)

**Decision.** Governance creates **Posture escalation (built-in)** in a
tenant on the first escalation that finds no active covering policy. Its
approvers are tenant administrators (`admin`, `tenant-admin`) other than the
requester, and one approval is enough. The policy has a fixed per-tenant ID.
Editing or disabling it is the administrator's choice and is kept (a
disabled one is never recreated); deleting it is refused.

**Why:** 1.34.0-beta made escalation dual-controlled, but a fresh tenant had
no policy, so the feature was refused everywhere until someone found the
setup step. Tenant admins are the one role every tenant has, and requiring
a second admin keeps the dual control real.

*Rejected:*
- seeding at tenant creation (tenants live in auth; governance learns of a
  tenant only when it is used);
- a code-only fallback with no row (`approval_requests.policy_id` references
  a policy, and admins could not see or change it);
- recreating after a delete (it would silently undo an administrator's
  decision);
- letting posture create the policy (policy changes need a tenant
  administrator, never a service).

Creation runs on the primary only (`approval_policies` is replicated).

---

## 2026-09-27 — Posture remediation: one real executor, governance-bound approvals (1.34.0-beta)

**Decision.** Posture executes only action types it can perform against a
named object. Today that is `escalate_remediation`, which changes the overdue
finding it names. The other eight types are no longer created: their
findings are aggregate counts, so there is no connector, client, credential,
HSM profile or certificate to act on. The unconsumed
`audit.posture.runbook.execute` event and `POSTURE_AUTO_REMEDIATE` are
removed. Approvals are governance requests posture opens as its service
identity, with the verified caller as requester, bound by target and payload
hash to one action. The executor must be the requester. *Rejected:*
- a labelled preview for the eight types (rule 8 prefers removal, and the
  finding's recommended action already carries the guidance);
- executors that guess a target (for example quarantining the most active
  client);
- governance callbacks that execute on approval (the executor would be the
  approver's vote, not a verified caller);
- trusting a client-supplied approval ID, as before;
- letting any user run on another user's approval (dual control means one
  person asks, another approves, and the asker executes).

Legacy rows are corrected by an idempotent primary-only job, since
`posture_actions` is replicated and a SQL migration would also run on
members.

---

## 2026-09-27 — sbom and reporting on the route kernel (1.33.0-beta)

**Decision.** Both handler files are migrated whole to `pkg/route`, not
patched with `tenantcheck.Enforce` on the three routes that lacked it. The
tenant and actor come from the kernel; the old `requested_by` / `actor` body
fields are rejected (400) rather than silently ignored, so a client relying
on them learns it. A body `tenant_id` is still accepted when it matches the
token, since the kernel verifies it.

**Alert operations share one pattern,** `PUT /alerts/{id}/{op}`, audited as
`alert_updated` with `operation`. Four literal patterns
(`/alerts/{id}/resolve`, ...) conflict with `PUT /alerts/rules/{id}` in Go's
mux (neither is more specific), and moving rule updates would break clients.

**The platform SBOM needs the platform tenant to change.** Snapshots are
shared by every tenant; a tenant admin elsewhere holds
`sbom.write` through `*` and must not change what all tenants see. Rejected:
a new platform-admin permission (no role grants it yet, so it would lock
everyone out).

**Request audit moves from the service to the kernel.** Where the reporting
service published `audit.reporting.<x>` for an API request, the kernel now
emits the same subject (with the verified actor), so consumers keep working
and nothing is emitted twice. Events for background work (scheduled runs,
alert ingestion, snapshot generation) stay in the service.

---

## 2026-09-27 — Posture on the route kernel (1.32.0-beta)

**Decision.** All posture routes are kernel routes with three permissions:
`posture.read`, `posture.write` and `posture.action.execute`. Posture does
**not** join `route.CoarseDomains`: it is an analytics and remediation plane
whose actions change controls, so `kms.read`/`kms.write` API-client grants
don't reach it. The wildcard tenants `*` and `all` are refused on every
engine route, including for tenant-less root tokens and service principals,
because the kernel binds exactly one tenant and `*` is the row key of the
cross-tenant aggregate snapshot; the all-tenant scan runs only in the
in-process scheduler. `main` wraps the kernel in a claims-only middleware
that forwards a missing or invalid token without claims, so the kernel
refuses it and audits it under the route's action, and posture refuses to
start without a JWT key. *Rejected:* `jwtauth.MustWrap` (its 401 is only
seen by the generic request log, not as `audit.posture.<action>`
`unauthenticated`); keeping an unauthenticated path for reporting (it has a
provisioned `kms-reporting` identity); serving `*` to root admins (no UI
uses it, and it would be the only cross-tenant read in the API). A batch
item naming another tenant refuses the whole batch rather than being
dropped, so a caller never gets a partial success it didn't ask for.

---

## 2026-09-27 — Attested key release: seal to a key the evidence commits to

**Decision** (1.30.0-beta). A release goes to a public key generated inside
the enclave and committed to by *verified* evidence (Nitro `public_key`; OIDC
nonce = base64url(SHA-256(DER))). Keycore seals the material to it with
RSA-OAEP-256 + AES-256-GCM (SP 800-56B key transport, approved in FIPS mode),
and only the confidential service identity may ask.

**Why.** Binding the output to the enclave's own key makes the release safe
against replayed evidence and a compromised caller: the sealed blob is useless
outside the enclave. RSA is what Nitro recipients use (AWS KMS's own Nitro
recipient flow), and the hybrid construction carries any key size.

**Rejected.** Returning plaintext to the caller after an allow (anyone with
the evidence could fetch the key); HPKE/X25519 (not approved in FIPS strict
mode); letting any `kms-*` service release keys.

---

## 2026-09-27 — OpenAPI specs: remove the fabricated one, check the rest (1.29.0-beta)

**Decision.** The `ai` OpenAPI spec is deleted rather than rewritten as an
`ai-gateway` spec, and the other four specs are checked by
`scripts/check-doc-routes.py` in conformance: servers must be edge
`/svc/<name>` paths and every operation must be a registered route of that
service. **Why:** rule 8 prefers removing what is not real, and a new
hand-written spec for 30 ai-gateway routes would be another unchecked
contract (only paths are checked today). `ai-gateway` routes are listed in
the generated route index in `docs/API_REFERENCE.md`. *Rejected:* keeping
`http://localhost:<port>` servers labelled "direct" (services are reached
through Envoy, not plain HTTP); a separate OpenAPI checker (it would duplicate
the route and Envoy-prefix resolution the doc check already has).

---

## 2026-09-27 — Closing the 1.27 open items (1.28.0-beta)

**Microsoft DKE.** Entra ID tokens are verified with `pkg/oidc` against the
Entra tenant's key set, which is derived from the issuer's tenant ID on
`login.microsoftonline.com` (never from a URL in the token). The issuer has to
be listed in the endpoint's `valid_issuers`, and audience and authorized users
are required, not optional. An Entra token without them would admit anyone
the tenant can mint a token for. The Vecta tenant is found from the
endpoint that trusts the issuer, because Office calls the key URL as
configured in the label and sends no Vecta tenant. Several tenants
trusting one issuer is refused, not guessed. The wire format follows
Microsoft's reference service. The public key is anonymous only on the
configured DKE host. *Rejected:* discovering keys through the token's `iss`
URL (an unverified value would choose the key server); decrypting a
non-current version with the current key (a wrong key, not a real
decrypt).

**Google CSE authentication audience.** Explicit
`authentication_client_ids` per config; existing configs fail closed until
set. *Rejected:* accepting any Google ID token for the domain, which is
what the missing check allowed.

**Governance approver roles.** Roles are expanded to users when the request
opens and stored as its approvers (tokens), consistent with "approvers are
fixed by the request". *Rejected:* checking the voter's role at vote time,
because email-link votes carry no token claims and a later role change would
shift a running quorum.

**JCA provider.** Offer only what the KMS API does: key wrapping under a TDE
key (`Cipher.VectaKeyWrap`). *Rejected:* keeping AES-GCM, Signature and
KeyStore by adding server routes to match. They were never real, and a
remote `AES/GCM/NoPadding` that cannot honour caller IVs is a mislabel. The
SDK zip embeds the source (`go:embed`) so it cannot drift. The provider runs
on OpenJDK; Oracle JDK needs an Oracle JCE signing certificate.

**Docs.** A route-existence check in conformance instead of hand review:
`scripts/check-doc-routes.py` reads the routers and Envoy prefixes. A plain
word matches a route parameter only when no sibling route has a literal
there. Invented sections are removed, not marked.

---

## 2026-09-27 — Second fake sweep: identity only from verified credentials; remove what cannot load

**Context.** The second sweep (1.27.0-beta) found services that took identity
from the TLS peer (hyok, EKM), from request bodies (governance votes, signing),
or from unverified tokens (SAML, OIDC, KACLS), and client artefacts that no
consumer could use (PKCS#11 provider, JCA `VectaQRNG`).

**Decisions.**
- *Identity comes only from a credential the service verifies* (a JWT against
  the platform key or an IdP's JWKS, an XML signature against a configured
  certificate). The internal mTLS peer identifies the calling service; behind
  Envoy it is always Envoy, so it is never a user or tenant identity. Customer
  client-certificate auth (hyok `mtls`) is refused rather than kept, because the
  edge does not verify client certificates; it can return when Envoy validates
  them and services check `x-forwarded-client-cert` from the Envoy peer only.
- *One verifier package.* `pkg/oidc` does discovery, JWKS and claim checks for
  SSO, signing and KACLS, so the rules (asymmetric algorithms only, exact
  issuer, audience, expiry) are the same everywhere.
- *SAML uses goxmldsig* (v1.6.1, with beevik/etree) rather than hand-written
  canonicalisation: XML-DSig is easy to get subtly wrong, and the library returns
  the verified element so signature wrapping cannot slip values past it.
- *Remove, don't rebuild, the PKCS#11 provider.* A correct module (function
  list, attributes, mechanisms, sessions, tested with pkcs11-tool and
  SunPKCS11) is a project of its own. REST, KMIP and the JCA provider cover
  application access; rebuilding it is for the owner to request.
- *TDE via KMIP only.* Vecta's real path for a database's master key is its
  KMIP server; engines without a KMIP key manager are documented as unsupported.

**Rejected.** Keeping peer-certificate identity "for direct connections":
services only accept internal-CA clients, so no customer can connect directly.

## 2026-09-27 — Fake capabilities: make real where the path exists, otherwise remove
**Decision** (1.26.0-beta, owner directive "fix all of this"):
- **Made real** where a real dependency already existed:
  - FF1 (NIST SP 800-38G on the module's AES);
  - `hsm-trng` (the tenant HSM's `C_GenerateRandom` through hsm-connector);
  - discovery (TLS handshakes, the cloud service's live inventory, the certs
    list, a mounted code tree);
  - PQC migration (successor keys in keycore);
  - playbook `trigger_assessment` / `snapshot_posture` (run in-process);
  - AI gateway health (a database ping and detector self-checks).
- **Removed** where no real path exists:
  - Feature Forge, which had no environments to stage or deploy to;
  - FF3-1, withdrawn by NIST's SP 800-38G Rev. 1 draft;
  - the QKD and QRNG random sources;
  - playbook actions without an executor;
  - the SBOM fallback CVE list;
  - the invented cost figure and "entropy" score;
  - dead code (`pkg/hwtoken`, `pkg/caim`, unwired keycore types).
- **Relabelled** where the capability is real but was overclaimed:
  confidential compute returns a *verdict*, not a key release; watchdog
  incidents are alerts with a recommendation.

**Why:** CLAUDE.md rule 8 (preferring removal over a stand-in) and rule 7
(never fabricate evidence), including audit events that certified work that
never happened.

**Rejected:**
- *Keeping Feature Forge with a "preview" label.* It stored nothing a preview
  could honestly describe, and its guardrails and apply path were broken.
- *Mapping FF3-1 to FF1.* Its ciphertext would silently change meaning.
- *Building attested key release now* (wrapping to the enclave's public key).
  It needs a keycore export-to-recipient endpoint restricted to the
  confidential service identity; it is recorded as open in
  REAL_CAPABILITY.md.
- *Deleting keys whose material was faked.* They are relabelled
  (`INVALID-MATERIAL`, or the real algorithm) and audited instead, so nothing
  is destroyed without the customer's decision.

**Migration:** pre-1.26.0 FPE ciphertext is readable through decrypt-only
`LEGACY-FF1` / `LEGACY-FF3-1` (audited), then re-encrypted with FF1. This is a
per-value migration, never a silent switch (CLAUDE.md rule 6).

**Enforced by:**
- NIST FF1 vector tests;
- refusal tests for each removed path;
- a real TLS server in the discovery tests and real SoftHSM2 in the HSM
  random tests;
- `make conformance` `real-capability` (now also `MOCK_*` constants and
  `newMock…` constructors).

## 2026-09-27 — Webhook credentials: one sealed envelope, key opened in the background

- **Decision:** the secret and all header values of a webhook go into one
  envelope under a `pkg/mek` master key for the audit service. Header names
  stay in plaintext (the API shows them).
- **Rejected: one envelope per field.** `pkg/mek` tracks one wrapped DEK per
  row, and a single envelope keeps rotation and the backup re-wrap simple.
- **Binding:** the sealed payload includes the tenant and webhook ID, which
  are checked on open. That gives the effect of AAD without changing the
  shared envelope format.
- **Rejected: refuse to start until the key is open**, as secrets, certs,
  cloud and ekm do. Audit is the sink, and blocking it on keycore would
  suspend the audit trail during exactly the incidents it must record.
  Instead, credential writes and credentialed deliveries fail closed until
  the key is open, and a key mismatch disables them without stopping ingest.
- **Existing plaintext rows:** sealed on the primary, and recorded in the
  exposure register (`plaintext_storage`) before sealing, because a database
  copy made before the change still has them.
- **Retiring an entry:** the entry is retired only when every credential has
  been replaced. Rotating the secret alone leaves a Splunk token exposed.

---

## 2026-09-27 — Rotation policies and webhook delivery: how they run

**Rotation.** A trigger rotates keys *as the caller*, so the caller's key
grants and the policy service decide each key. A scheduled run needs an
identity with no user present. It uses an in-process keycore service
principal, set in code, never from a request, so it can't be forged (rule 4).
The rejected alternative was to replay the policy creator's identity: a user
removed later would still rotate keys, and a stored identity can be spoofed.
The authority therefore comes from `key.rotation.write`, which only admins
hold by default, and every scheduled run is audited with its counts. Only
keys are supported. Secrets and certificates rotate in their own services;
a policy there would be a record with nothing behind it. The scheduler runs
on the primary only, because policies and runs are replicated tables.

**Webhooks.** Delivery hooks into `ProcessEvent` after the event is
persisted, so only events in the chain are delivered, and each one exactly
once, on the node that ingested it. Relayed duplicates are skipped before
processing. A separate JetStream consumer was rejected: it would see
unpersisted and duplicate events. Subscriptions are audit action patterns
(`audit.key.*`) rather than a parallel event vocabulary. The old names
(`key.created`) matched nothing and would have needed a mapping kept in sync
by hand. Delivery audits (`audit.audit.webhook_*`) are excluded from matching
so a `*` subscription can't loop. Members record attempts in node-local
`webhook_deliveries` and leave the replicated `webhooks` row to the primary.
The outbound client dials only SSRF-checked addresses, follows no redirects
and requires TLS 1.3, so a validated URL can't be re-pointed at an internal
host by DNS or redirect.

---

## 2026-09-27 — Service mTLS: per-service policy by published file, restart to apply
**Decision:**
- **Where the policy lives:** each internal identity's certificate key and
  key-exchange profile are stored in certs (`cert_internal_mtls_policy`,
  replicated) and published as a public file on the trust volume every
  service already mounts.
- **Applying it:** a service reads it before enrolling and restarts itself
  when its entry changes. A rotation is a generation bump: the old
  certificate is revoked and the service restarts.
- **Reporting:** services report what they run to `platform_mtls_observed`
  through the connection they already use for the FIPS mode.

**Why:**
- **Before enrolment.** A file can be read before the service has a
  certificate. A policy endpoint would need mTLS to fetch the policy that
  mTLS depends on.
- **No audit noise.** A polling route would audit about one event a second.
- **Restart, not hot swap.** A restart drops every session made with the
  old key, and it is the same graceful path the FIPS mode change already
  uses.
- **The page shows reports.** It shows what services report, not what was
  requested.

**The profile governs the server side.** Clients always offer every group.
- Envoy offers only `X25519MLKEM768` among the post-quantum groups. If the
  choice restricted clients too, or ML-KEM-1024 were offered as a profile,
  one click could make services unreachable through the gateway.
- "PQC required" is enforced where it can't break a caller: the service
  refuses classical-only peers.

**Rejected:**
- A policy endpoint on the enrolment listener.
- Hot-swapping certificates without a restart: sessions under the old key
  would survive.
- Per-group lists: they can break callers.
- ML-DSA certificate keys: the certified module v1.0.0 has none.

**Resolved (owner, 2026-09-27): PQC certificates removed** (1.19.0-beta).
Certificates and CAs requested as PQC (ML-DSA, SLH-DSA, XMSS/LMS) or hybrid
got ECDSA keys while recorded and audited as PQC (rule 8). They can't be made
real on the certified module, so the feature is removed rather than kept as
a preview:
- Such requests are refused and audited (`audit.cert.pqc_issuance_refused`).
- The PQC routes, profiles and stateful-signature counters are gone.
- Existing records are relabelled to their real key and deleted PQC
  profiles are audited.

---

## 2026-09-27 — Envelope encryption: KMS generates and wraps DEKs, never stores them
**Decision:** envelope encryption is `POST /keys/{id}/generate-data-key`
(fresh DEK, plus the DEK wrapped under a keycore key) and `/unwrap` to recover
it. The caller stores the wrapped DEK with its data. The keycore KEK/DEK
"hierarchy" tables are removed.

**Why:**
- Envelope encryption exists so bulk data never crosses the wire to the KMS.
  Only the 32-byte DEK is wrapped and unwrapped.
- The KEK is an ordinary keycore key, so it gets real versions, rotation,
  access policy, FIPS mode, HSM backing and audit for free.
- A KMS-side DEK registry would either hold wrapped DEKs the KMS cannot
  usefully rewrap without the data owner, or leak usage metadata. AWS KMS,
  GCP KMS and Vault Transit don't keep one either.

**Rejected:**
- Making the old `/envelope/*` tables real. That would duplicate keycore key
  lifecycle in a second, weaker model.
- A separate `decrypt-data-key` route: `/unwrap` already does exactly this
  and is audited.

**Enforced by:** `TestGenerateDataKeyRoundTripsThroughUnwrap`,
`TestGenerateDataKeyRefusalIsAudited`, `TestDataKeyRoutesRefusalsAudited`.

---

## 2026-09-26 — Re-key the CRWK on a passphrase change, don't just re-seal it
**Decision:** when the certs CRWK passphrase changes, including the
migration off the retired public default, certs:
1. generates a **new random CRWK**;
2. rewraps every CA signer's DEK and the internal PKI cache under it;
3. only then replaces `crwk.sealed` and deletes the retired key and the
   previous passphrase.

**Why:**
- Re-sealing the same CRWK under the new passphrase would be one file
  write. But any copy of the old `crwk.sealed` (a volume backup or
  snapshot) would still open, with the public passphrase, every CA signer
  in the current and future database.
- With a new CRWK, an old sealed file only opens database rows from before
  the rotation. Those are covered by rotating the CAs, which the docs say
  to do if such copies may exist.

**Also decided:**
- **Resumable in place.** Both keys are held, selected by
  `signer_kek_version`, while the rewrap runs. `crwk.sealed.next` survives
  a crash. Nothing is deleted until every row is rewrapped, so a failure
  loses nothing and is retried on the next start.
- **The passphrase is generated inside the volume** by a script the start
  scripts and installer share (`infra/scripts/crwk-passphrase.sh`). It
  never crosses the host, and there's no `.env` copy to leak.
- **The retired value is recognised by its SHA-256.** The literal can then
  be banned from code by `no-retired-public-secret`.

**Rejected:**
- A startup flag to "accept" the public passphrase for a grace period: that
  is a fallback, which rule 3 forbids.
- Rewrapping in the helper container: it has no Argon2id, and the rewrap
  needs the database.

**Open:**
- The passphrase file sits on the same volume as `crwk.sealed`, so the
  volume alone opens the CRWK. A host-held or TPM-sealed passphrase would
  separate them.
- ~~`CERTS_CRWK_USE_TPM_SEAL` isn't real~~ **Resolved in 1.15.0-beta:**
  it only recorded a flag, so it was removed rather than implemented (rule
  8). Real TPM sealing would be a new feature, built end to end.
- Cluster members don't rewrap; the primary's rows replicate.

---

## 2026-09-26 — Internal PKI before the database; FIPS mode from a file (slice 2)
**Decision:**
- **Internal PKI:** the certs service keeps the runtime root and Sub CA in a
  sealed cache on its key volume (signing keys wrapped by the certs root
  wrapping key, as in the database). It issues its own and the daemons'
  certificates before connecting to Postgres, then records them.
- **Existing installs:** the start script exports the two CA rows once, over
  Postgres' Unix socket.
- **FIPS mode:** services read the platform mode from a file governance
  writes, not from the database.

**Why:** Postgres now requires internal mTLS, which creates two cycles.
- *CA ↔ database:* the CA lived only in the database the CA now secures.
- *FIPS mode ↔ TLS:* reading the mode needed a TLS handshake, which is
  cryptography done before the mode is decided.

**Rejected:**
- *A bootstrap self-signed Postgres certificate pinned by certs*: certs
  would still have no client certificate, so it couldn't do mTLS.
- *Retiring the existing root and starting a new one*: every client trusting
  it (payment terminals, KMIP) would break.
- *Keeping the database read with a TLS fallback*: that is plaintext by
  another name.

**Also removed:**
- etcd (no consumer).
- pgbouncer (no DSN pointed at it).
- The Consul Connect bootstrap (no service used Connect).

A daemon nothing uses is still an open port.

**Enforced by:**
- `TestBootstrapCreatesThenReusesTheInternalPKI`,
  `TestPKICacheReadsPsqlRowToJSON`,
  `TestBootstrapEnrolmentAndInfraCertsBeforeTheDatabase`,
  `TestReconcileRecordsBootstrapStateAndSwitchesToTheDatabase`,
  `TestReconcileRefusesADifferentCAWithTheSameName`;
- `TestPlatformFIPSModeFromFile`, `TestSyncPlatformFIPSModeFile`,
  `TestPendingReaderHoldsPrimaryJobs`;
- the live wire checks recorded in `docs/SECURITY/INTERNAL_TLS.md`.

## 2026-09-26 — How internal mTLS is wired (slice 1)
**Decision:**
- **Enrolment proof:** an HMAC over the CSR under the identity's
  platform-derived API key (`servicetoken.DeriveAPIKey`). The certs service
  checks it itself, so enrolment doesn't depend on auth, which needs a
  certificate too.
- **Clients:** one routing transport installed as `http.DefaultTransport`
  instead of editing about 60 client call sites. Platform hosts go over mTLS
  and plain `http://` to them is refused; other hosts keep public-CA trust.
- **Envoy:** it routes `/svc/*` and `/auth` straight to the services, so it
  is the only component holding an internal client identity for UI traffic.
  The dashboard's nginx serves static files only.
- **Certificate reload:** Envoy's certificates reload through file-based SDS
  with a watched directory, and nginx through a certificate-watch reload.

**Why:**
- The shared transport changes every client at once, and the refusal
  enforces the rule at runtime.
- One owner of the internal client identity for UI traffic means one place
  to rotate it.
- Certificates renew every few days, so every consumer has to reload them.

**Rejected:**
- *Trusting both public roots and the internal CA in one pool*: an internal
  certificate could then pass as a public host. Trust is split by host
  instead.
- *Making nginx an mTLS proxy to every service*: it would be a second client
  identity, and duplicate Envoy's routing.
- *Enrolling through auth-issued JWTs*: a cyclic dependency at start-up.

**Enforced by:** `pkg/svctls` tests (real handshakes: missing, foreign or
plain; the hybrid group asserted), the certs enrolment tests, and the
`make conformance` `tls-only` rule.

## 2026-09-26 — Internal mTLS from an internal-services Sub CA, keys enrolled by CSR
**Decision:** every internal connection moves to mTLS.
- **CAs:** a new Sub CA, `vecta-internal-services`, is created under the
  existing `vecta-runtime-root` at deployment, and every internal
  certificate comes from it.
- **Enrolment:** each service generates its key and enrols with a CSR,
  authenticated by its platform service identity.
- **Controls:** rotation and mechanism choice (including the PQC hybrid
  groups `X25519MLKEM768`, `SecP256r1MLKEM768` and `SecP384r1MLKEM1024`) are
  per service in the dashboard. The swap is a graceful drain and re-exec,
  or a forced restart.

**Why:**
- The owner's directive: nothing is HTTP, and internal traffic uses
  internal-CA mTLS.
- Service calls carry key material today over plain HTTP. The fake "mTLS
  Mesh" hid that gap.
- A Sub CA keeps the root out of daily issuance, and lets the internal
  certificate estate be rotated or revoked on its own.

**Rejected:**
- *Issuing from the root directly*: it puts the root in the hot path.
- *Writing every service's key into the shared `runtime-certs` volume*: one
  compromised service could read every key.
- *A sidecar mesh (Istio or Consul Connect)*: it adds a second, unmanaged
  PKI and control plane. Go's TLS in the certified module already covers
  the need.
- *ML-DSA certificates*: the certified Go Cryptographic Module v1.0.0 has no
  ML-DSA (Go's TLS supports it from module v1.26.0). PQC is offered for key
  exchange only, and labelled that way.

**Plan:** four slices (docs/SECURITY/INTERNAL_TLS.md), each tested against
real TLS handshakes and real dependencies.

## 2026-09-26 — Replace the fabricated DR drill with backup verification
**Decision:** delete keycore's DR drill, which marked every step passed with
synthetic RTO/RPO. Add `POST /governance/backups/verify`, which opens a real
backup through restore's own code path (`openBackup`) and reports what it
holds, without applying it.

**Why:**
- Rule 7: no fabricated evidence.
- "Can we recover?" is answered by "does our backup open with the keys we
  hold?", and the platform can prove that for real.

**Rejected:**
- *A full restore drill into a throwaway environment*: restore overwrites
  the live database, so isolating it needs new work across governance and
  keycore (several days).
- *Scheduled automatic drills*: software-mode backup keys aren't stored and
  may be split across guardians, so an unattended job can't open them.
- *Keeping the drill as a preview*: its schedules never ran, so nothing of
  value would remain.

**Open:**
- Verify doesn't prove services can re-wrap retired-key rows; restore
  checks that before applying.
- A timed, isolated restore (real RTO) is still future work.

**Enforced by:** `TestVerifyBackupPostgres`,
`TestVerifyBackupRouteAuthAndActor`.

## 2026-09-26 — Remove the CT log monitor rather than label it a preview
**Decision:** delete the CT log monitor (backend, tables, dashboard tab). It
generated synthetic certificates and mis-issuance alerts. Certs migration
011 drops its tables, and with them every fabricated entry.

**Why:**
- CLAUDE.md rule 7: a feature must never invent security evidence.
- A preview may store settings, but it may not produce results.
- Removing the simulator would have left only a domain list that does
  nothing.

**Rejected:**
- *Keep it as a preview*: without the simulator nothing is left to show.
- *Build real RFC 6962 / crt.sh polling now*: it only matters for public
  domains, while Vecta mostly manages internal and private PKI.

**Later:** the owner may add certificate discovery and scanning (network
TLS scan, CT for public domains, inventory reconciliation). If CT returns,
it must:
- read real logs over TLS 1.3 and verify signed tree heads;
- take the tenant from the verified caller;
- audit every action and alert;
- test against a real log client.

## 2026-09-26 — Guardian shares for the backup key instead of a general escrow workflow
**Decision:** remove keycore's escrow workflow entirely. Instead, a
software-mode backup key can be split M-of-N with Shamir secret sharing, one
share per named guardian, at backup creation. Restore needs M shares, and the
rebuilt key must match the stored fingerprint.

**Why:**
- The escrow workflow only kept records, and its votes were forgeable.
- The real recovery risk is the backup key: one operator holds the only
  copy, so it can be lost, or that one person can restore everything.
- A split covers both risks with no new stored secret.

**Rejected:**
- *Fixing the escrow workflow* (binding votes, sealing per-key shares to
  guardians with ML-KEM): per-key and legal-hold recovery is worth that cost
  only when customers need it.
- *Splitting in keycore over REST*: the backup key would travel to another
  service. Shamir moved into `pkg/crypto`, so governance splits locally.
- *Splitting an HSM-bound key*: it never leaves the HSM, so the request is
  refused.
- *Storing shares for later redistribution*: that would put the key back in
  the database.
- *Guarding the split behind `fips140.Enforced()`*: secret sharing isn't an
  encryption algorithm. It uses the module DRBG and splits a key that
  software mode already hands out whole, so it stays available in `only`
  mode (docs/SECURITY/FIPS.md). A reviewer may classify it differently.

**Enforced by:** `TestSplitBackupKeyRestorePostgres`,
`TestSplitBackupKeyNeedsThresholdShares`,
`TestValidateBackupKeySplitRejectsBadSplits` and the `pkg/crypto` Shamir
tests ([SECURITY/BACKUP_KEYS.md](SECURITY/BACKUP_KEYS.md)).

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
