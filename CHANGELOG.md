# Changelog

All notable changes to Vecta KMS are recorded here. Versions follow the
`MAJOR.MINOR.PATCH[-beta]` scheme; the canonical version lives in the
[`VERSION`](VERSION) file and is published as a git tag (`vX.Y.Z`).

## [7.13.0-beta] — 2026-09-30

### Crypto Discovery never scans or lists the KMS's own internal services
- **Changed:** the network scan refuses any endpoint that is a KMS platform
  host (every service, Envoy, the dashboard, Postgres, NATS, Valkey,
  Consul, and the HSM CLI container) or resolves to one, and discovery's own
  addresses. The check runs on the address actually dialled, after DNS
  resolution, and now covers `DISCOVERY_TLS_ENDPOINTS` as well as tenant
  targets. Adding a bare platform hostname (`keycore`, `postgres`) as a
  target is refused as `platform_target`. Customer hosts that only share a
  label (`auth.example.com`) are allowed, and so are private (RFC 1918)
  addresses.
- **Changed:** the certs source skips `cert_class: internal-mtls`, the
  platform's own service certificates. Assets that earlier scans stored for
  platform services are hidden from the inventory, the summary and
  `GET /discovery/assets/{id}`. Those certificates are in the PKI tab (CA
  hierarchy, service mTLS certificates).
- **Why:** closes the gap left open in 7.11.0-beta, where a tenant target
  could reach an internal service. Before it, a tenant could use the scan to
  see which internal ports answer.
- **Tests:** `TestPlatformHostTargetRefused`, `TestPlatformAddrsRefusedAtDial`,
  `TestTenantTargetDialGuard` (operator endpoints too),
  `TestCertsScanSkipsInternalServiceCerts`, `TestStoredPlatformAssetsHidden`,
  `TestTargetRoutesAudited` (`platform_target` refusal audited).

## [7.12.0-beta] — 2026-09-30

### Every JWT refusal is audited, on raw-mux services too
- **Fixed:** services still on a raw `http.ServeMux` (audit, backup,
  compliance, policy, signing, and `platform.Boot` services whose handler
  isn't a kernel router) answered a missing or bad token with a 401 from
  `pkg/jwtauth.MustWrap`, and only the generic request log saw it.
  `MustWrap` now takes the service's audit client and emits
  `audit.<service>.request_refused` with `result: refused`, `reason`
  `unauthenticated` or `invalid_token`, the source IP, method, path and any
  `requested_tenant`. This completes 7.10.0-beta, which covered kernel
  services only.
- **Changed:** `platform.Boot` serves a handler that is a kernel router
  (`jwtauth.PublicRouter`) through `MustWrapRouter`, so its refusals are
  audited under the route's own action.
- **Test:** `TestLegacyWrapperAuditsTokenRefusals`.

## [7.11.0-beta] — 2026-09-30

### Crypto Discovery: ECDSA-P256 is no longer "vulnerable"; add TLS targets from the page
- **Fixed:** the algorithm catalogue had one non-ready class, `vulnerable`,
  for both "weak today" and "broken by a quantum computer". An ECDSA-P256
  certificate (128-bit, sound today) was therefore shown in red next to
  RSA-1024, and the "Quantum-vulnerable" card counted weak algorithms too.
  `cryptocatalog.Assess` now returns `weak`, `quantum_vulnerable`, `strong`
  or `unknown`, and discovery adds `exposed` for a secret found in code. The
  page shows weak and exposed in red and quantum-vulnerable in amber, with a
  card for each. Discovery derives the class from the algorithm on every
  read, so rows stored as `vulnerable` show the right class without a rescan.
  The summary's `classification_counts` keys change to match. pqc gives all
  four non-ready classes the same risk weight as the old `vulnerable`.
- **Added:** TLS targets. A `discovery.write` holder adds a host (DNS name or
  IP) and port on the Crypto Discovery page (`GET`/`POST
  /discovery/targets`, `DELETE /discovery/targets/{id}`). The network scan
  handshakes with them, as well as with `DISCOVERY_TLS_ENDPOINTS`, and records
  the key exchange, protocol, cipher and certificate key. Before, the only
  way to name a target was that operator environment variable. Loopback,
  link-local (including cloud metadata), multicast and unspecified addresses
  are refused when the target is added, and again at dial time after DNS
  resolution. At most 256 targets per tenant.
- **Audit:** `audit.discovery.targets_list`, `target_add` and
  `target_remove`, with refusals `invalid_target`, `target_exists`,
  `target_limit`, `permission_denied` and `tenant_mismatch`.
- **Tests:** `TestTargetRoutesAudited`, `TestTenantTargetIsScanned`,
  `TestTenantTargetDialGuard`, `TestRefuseReservedAddr`,
  `TestNormalizeTarget`, `TestStoredVulnerableIsReclassifiedOnRead`.
- **Schema:** discovery migration 004 adds `discovery_scan_targets`
  (replicated under discovery).

## [7.10.0-beta] — 2026-09-30

### A missing or bad token is audited as its own event on kernel services
- **Fixed:** on services fully on the route kernel, the JWT middleware
  answered a request with no token, or a token that failed verification,
  with a 401 itself. Only the generic HTTP request log recorded it. Now
  `pkg/jwtauth.MustWrapRouter` hands the request to the kernel, which refuses
  it and emits `audit.<service>.<action>` with `result: refused` and `reason`
  `unauthenticated` or `invalid_token`. A bad token is refused on Public
  routes too. A request that matches no route still gets a plain 401, so an
  unauthenticated caller learns nothing about which paths exist.
- **Services:** confidential, discovery, keyaccess, pqc, reconciler,
  reporting, sbom and watchdog move from `MustWrap` to `MustWrapRouter`
  (workload already used it). Services on a raw mux keep `MustWrap`; they
  get this when they migrate.
- **Test:** `TestKernelWrapperAuditsTokenRefusals`.

## [7.9.0-beta] — 2026-09-30

### Workload Identity, Confidential Compute and Crypto Discovery are back in the dashboard
- **Fixed:** the three services ran and were enforced, but had no page. The
  Workload Identity and Confidential Compute tabs were unregistered from the
  shell in f8e7162c4 (March), and Discovery's view went with the DSPM tab in
  1980954dd (June). Workload Identity and Confidential Compute are under
  Data & integrations, and a new Crypto Discovery page under Keys &
  lifecycle runs scans (network, cloud, certs, code), lists the inventory
  and scan history with each source that wasn't scanned and why, and records
  reviews. Each page appears when its feature is enabled.
- **Fixed:** the Confidential Compute release form was pre-filled with an
  invented AWS account, image digest, nonce, claims and measurements. The
  fields are now empty with placeholders. The Workload Identity Refresh
  button was passed to a prop `Section` doesn't read, so it didn't show.

### Discovery: verified caller, permission and audit on every route (breaking)
- **Security:** discovery verified no token. Its `tenantcheck.Enforce` calls
  skipped every request because nothing put claims in the context, and scans
  and classifications ran for whatever tenant the body named. Every route
  now needs a verified platform JWT and goes through `pkg/route`:
  `discovery.read` (GETs) or `discovery.write` (scan, review), with the
  tenant taken from the token. Each request emits `audit.discovery.<action>`,
  refusals included. Discovery leaves the route-kernel burn-down list.
- **Changed:** `PUT /discovery/assets/{id}/classify` records a review
  (`status`, `notes`). A `classification` other than the algorithm
  catalogue's is refused (`409 classification_is_catalogue`, audited),
  because a label must match the algorithm.
- **Removed:** the summary's `posture_score` (a hand-weighted blend) and
  `average_qsl`; `POST /discovery/pii/scan` and `GET /discovery/pii/patterns`
  (content inspection, out of the KMS's scope since 7.5.0-beta);
  `GET /discovery/data-inventory` and the `GET /discovery/posture` alias,
  which nothing called.
- **Tests:** `TestDiscoveryRoutesRefusalsAudited`,
  `TestDiscoveryWritesNeedPermissionAndOwnTenant`,
  `TestDiscoveryRelabelRefusedAndAudited`.

## [7.8.0-beta] — 2026-09-30

### Every internal client sends its service token (enforced)
- **Fixed:** nine internal clients called other services without a token,
  were refused, and treated the refusal as "no data": compliance → certs and
  policy; dataprotect, discovery, kmip and sbom → certs; hyok → policy; pqc
  and sbom → discovery. Each now sends its own service token.
- **Enforced:** new `make conformance` check `service-token`. An internal
  client that builds an HTTP request must call `servicetoken.Authorize`, or
  carry a `servicetoken-exempt:` comment naming the credential it uses
  instead.

## [7.7.0-beta] — 2026-09-30

### Compliance no longer scores over missing audit data
- **Fixed:** when audit events or alert stats couldn't be read, compliance
  treated them as empty. Posture recompute, audit correlations, anomalies and
  the assessment delta's "new failing connectors" now return an error, and
  the dashboard shows it, instead of a score or list built from nothing.
- **Fixed:** compliance read alert stats from `/alerts/stats` on the audit
  URL, a route audit doesn't have, so it always got nothing. It now reads
  them from reporting (`REPORTING_URL`, default `https://reporting:8140`).
- **Tests:** `TestAuditFailureIsNotEmptyData`, `TestAlertStatsReadFromReporting`.
- Closes both items left open in 7.6.0-beta.

## [7.6.0-beta] — 2026-09-30

### Alert Center shows alerts again
- **Fixed:** the Alert Center was empty. Reporting builds alerts by reading
  audit events, but its audit client sent no credential. Since audit started
  requiring a JWT on every read (`91a9be084`), every one-minute alert sync
  failed on audit's plain-text `401`, logged as `alert sync tenant=root:
  invalid character 'u' looking for beginning of value`, and no alert was
  ever created.
- Reporting now sends its `kms-reporting` service token to audit
  (`/audit/events`) and to compliance (`/compliance/posture`, which fed the
  posture section of generated reports and failed the same way, silently).
- Compliance's audit client had the same gap: its assessments read audit
  events without a token and treated the refusal as "no events". It now
  sends the `kms-compliance` service token.
- An upstream refusal now reads as `401 Unauthorized: …` in the log, not
  as a JSON syntax error.
- **Tests:** `TestAuditAndComplianceCallsCarryServiceIdentity` (reporting),
  `TestAuditReadsCarryServiceIdentity` (compliance).
- **Still open:** compliance's `fetchEvents`, `fetchAlertStats` and the
  connector-delta read still turn an audit error into an empty result, and
  `AlertStats` calls `/alerts/stats` on the audit URL, a route audit
  doesn't have. A failed source should show "unavailable".

## [7.5.0-beta] — 2026-09-30

### AI security gateway removed (breaking)
- **Removed:** the `ai-gateway` service, the "AI Security Gateway" tab, the
  `ai_gateway` deployment feature, its compose service, Envoy routes
  (`/api/ai-gateway`, `/svc/ai-gateway/`), service identity and cluster
  tables. Also removed the dead `ai_llm` feature flag, "AI / LLM" REST
  catalog entries and docs, and the "AI Protect" developer entries: they
  pointed at the `ai` service that was already gone.
- **Why:** content inspection is not a KMS job. The detectors were keyword
  regexes sold as prompt-injection and toxicity protection. Provider API
  keys were stored in plaintext under an `encrypted at rest` comment, and the
  list API returned part of each key. It also used `crypto/hmac` directly and
  audited only a generic request event. The dashboard's DLP view called a
  service that didn't exist.
- **Moved to:** KMS Extension `seeds/services/ai-gateway` (commit `5c75fde`),
  with these defects listed as promotion blockers.
- **What the KMS offers AI workloads instead:** secrets for provider
  credentials, workload identity for agents, tokenization/FPE/masking before
  data reaches a model, signing for model artifacts, BYOK/HYOK for cloud AI
  services. All already exist; [docs/AI_WORKLOADS.md](docs/AI_WORKLOADS.md)
  maps each need to its routes.
- **Upgrade:** drop `ai_gateway` / `ai_llm` from `deployment.yaml`. The
  `ai_gateway_*` tables are left in place; drop them once you no longer need
  their data.

## [7.4.0-beta] — 2026-09-30

### Dataprotect on the route kernel: a permission on every route (breaking for custom roles)
- **Before:** once authenticated (7.2.0-beta), any token, even a readonly
  user's, could change the data protection policy, delete token vaults and
  masking policies, complete a wrapper registration (asserting governance
  approval), or detokenize and decrypt. No route checked a permission.
- **Now:** every route is registered through `pkg/route` with a
  permission: `dataprotect.read` (lists, reads, stats, audit log, SDK),
  `dataprotect.use` (tokenize, detokenize, FPE, mask, redact, field,
  envelope and searchable encryption, leases and receipts),
  `dataprotect.write` (vaults, policies, profiles, wrapper registration,
  lease revoke, KDF migration) and `dataprotect.delete`. Which keys a caller
  may use is still decided by keycore from the caller's own grants. Each
  request emits `audit.dataprotect.<action>`, refusals included. The wrapper
  runtime routes still accept a wrapper's `X-Wrapper-Token` alone; without
  one they need the permission. `services/dataprotect/handler.go` leaves the
  route-kernel burn-down list.
- **Upgrade note:** admins (`*`) are unaffected; custom roles that use Data
  Protection need the new grants.

## [7.3.0-beta] — 2026-09-30

### Crypto agility under a stable key ID (NIST CSWP 39)
- **Rotation can change a key's algorithm.** `POST /keys/{id}/rotate` takes
  `target_algorithm`: the new version uses it under the same key ID, so
  applications change nothing. Older versions keep their own algorithm
  (`key_versions.algorithm`, migration 034) and keep decrypting and verifying
  what they protected. Keycore refuses (`409 algorithm_change_refused`) a
  target that is unknown or weak, can't serve an operation the key serves, or
  an HSM-resident key; the FIPS mode and the tenant's migration policy are
  checked against the target. Audited: `audit.key.algorithm_changed`,
  `audit.key.algorithm_change_refused`. Keys → Rotate has a "Change
  algorithm" field.
- **Decrypt and verify honour `version`.** They always used the current
  version, so ciphertext and signatures from before any rotation could not
  be processed, although the API reference said `keyVersion` was accepted.
  An older version now serves decrypt, verify and unwrap while `active` or
  `deactivated` (SP 800-57), never encrypt or sign.
- **`POST /keys/{id}/rewrap`** (`key.rewrap`) moves ciphertext onto the
  current version inside keycore; the plaintext never leaves it. Audited
  `audit.key.ciphertext_rewrapped`, refusals included.
- **PQC migrations keep the key ID.** An executed pqc plan now rotates a
  keycore key onto its target (step `algorithm_changed`) and rolls back by
  rotating it back. Only when keycore refuses the change, or the key was
  discovered outside keycore, does it create a successor key as before.
- **Removed: keycore's record-only migration plans** (`/agility/migration-plans`,
  table `agility_migration_plans` dropped by migration 034). Their progress
  counted every live key on the source algorithm in the tenant, so deleting
  a key read as "migrated" and creating one set progress back. Migrations
  run in Readiness & execution.
- **CARAF assessment measures, not only records:** each asset lists the
  callers of its linked keys (key usage trail, this node), and the
  assessment lists live keys on threatened algorithms that no asset links,
  with a finding for each.

## [7.2.0-beta] — 2026-09-30

### Security: dataprotect verifies who is calling (critical fix)
- **Before:** dataprotect booted with the platform JWT check off
  (`SkipJWT`) and no route checked a token, and `/svc/dataprotect/` is
  routed through the gateway. Anyone who could reach it could tokenize,
  detokenize, FPE-encrypt or decrypt, mask and read policies with any key
  (a tokenless `POST /fpe/encrypt?tenant_id=…` returned ciphertext). The
  6.0.0-beta delegation (keys used as the user) also never engaged in
  dataprotect, because no verified user token was in its context.
- **Now:** every route needs a verified platform token, which is forwarded
  to keycore so the user's own key grants decide. The field-encryption
  wrapper runtime routes (lease, receipt, renew, resolve for a named
  wrapper) still accept a wrapper's `X-Wrapper-Token` alone, verified
  against its registration. Wrapper registration now needs an operator
  token (completing it asserts a governance approval). Every refusal is
  audited as `audit.dataprotect.request_refused` (`unauthenticated` or
  `invalid_token`). Dataprotect refuses to start without the key that
  verifies tokens.
- **Upgrade note:** a client that called dataprotect without a bearer
  token (other than a registered wrapper on its runtime routes) now gets
  `401`; send the user's or service's platform token.

## [7.1.0-beta] — 2026-09-30

### Payments: sources kept in KMS Extension; removal finished
- The payment sources removed in 7.0.0-beta are kept as a seed in the KMS
  Extension repository (`seeds/services/payment`, `seeds/pkg/payment`, with
  its dashboard tab, client, gRPC contract and API docs; KMSExtension
  `fa2ae8c`), with the conditions for promoting it: it does its own
  cryptography on raw key material, and its key-by-ID path never worked
  against the real keycore. The last KMSBeta commit that contains it is
  `4146dc70c`.
- CLAUDE.md: development stays in KMSBeta; a feature the owner cuts may be
  copied to `KMSExtension/seeds/` when the owner asks (amends the
  2026-09-26 "never commit to KMSExtension" rule).
- `pkg/delegation` no longer accepts the `export`, `sign`, `verify` and `mac`
  usages: only payment sent them. The accepted usages are the ones a
  remaining service enforces (dataprotect, certs, ekm).
- The audit-events register drops the payment rows (their tests left with
  the service) and lists `audit.auth.service_identity_retired`.
- The runtime control-flow doc no longer describes a payment flow.

## [7.0.0-beta] — 2026-09-30

### Removed: the payment service (breaking)
- **Owner decision (2026-09-30):** payment HSM functions leave the core product.
- **Removed:**
  - `services/payment`: TR-31, PIN, MAC, ISO 20022, AP2 and key injection;
  - its compose service, Envoy route and Makefile target;
  - the Payment and Payment Policy tabs;
  - the `translate-*` delegation usages, which only payment enforced;
  - its API reference sections.
- **Kept:** `pkg/payment`, because keycore's TR-31 key import uses its
  parser.
- **Service identity:** auth now revokes the `kms-payment` service identity at
  every start: it deletes the API keys and revokes the registration. This is
  audited once as `audit.auth.service_identity_retired`
  (`TestBootstrapRetiresRemovedServiceIdentities`).
- **Recovery:** the sources remain in KMSBeta's git history; see the commit
  that removes them.

## [6.26.0-beta] — 2026-09-30

### Composite signature keys
- Keycore creates `ML-DSA-65+ECDSA-P256` and `ML-DSA-87+ECDSA-P384` keys and
  signs with both halves; a signature verifies only when both component
  signatures do (stripping or corrupting either fails). Refused in strict
  FIPS mode with ML-DSA (impact catalogue updated).
- Closed, by decision: stateful hash-based signatures through an HSM. No
  testable PKCS#11 library implements HSS/XMSS, and HSM integrations are
  tested only against a real library (docs/DECISIONS.md). The automation
  guide has no open items left.

## [6.25.0-beta] — 2026-09-30

### Operator cryptoperiods
- Each tenant sets its own cryptoperiod per key category (symmetric
  encryption, MAC, key wrapping, signing, DEK/ephemeral, master/KEK), 1–3650
  days: `GET /rotation/cryptoperiods`, `PUT|DELETE
  /rotation/cryptoperiods/{category}` (`key.rotation.read|write`), and
  Rotation → Cryptoperiods in the dashboard. The key lifecycle scan rotates on
  the tenant's period instead of the built-in SP 800-57 default. New table
  `cryptoperiod_overrides` (migration 033, replicated with keycore). Audited:
  `audit.key.cryptoperiods_listed`, `cryptoperiod_set`, `cryptoperiod_reset`,
  refusals `invalid_days`, `unknown_category`, `not_custom`.

### Hybrid key establishment: X25519MLKEM768
- Keycore creates `X25519MLKEM768` keys (ML-KEM-768 and X25519 as one key)
  and encapsulates/decapsulates with them: a 64-byte secret, ML-KEM-768 then
  X25519. Refused in strict FIPS mode (added to the impact catalogue); strict
  mode now applies keycore's FIPS algorithm check before generating any key.
  Other composites are still refused.
- Stateful hash-based signatures (XMSS, LMS, HSS) stay refused by design:
  SP 800-208 requires hardware generation and signing (docs/DECISIONS.md).

## [6.24.0-beta] — 2026-09-30

### Docs
- `docs/AUTOMATION_ALKM_PQC.md` no longer lists migration risk ratings as
  open: the CARAF assessment (keycore `caraf.go`) has shipped. Still open:
  cryptoperiods have no operator setting; hybrid keys and stateful
  hash-based signatures are not implemented.

## [6.23.0-beta] — 2026-09-30

### Keycore no longer parses the posture minimum algorithm tier
- 5.4.0-beta removed the tenant minimum-tier check (governance never stored
  `posture_min_algorithm_tier`), but keycore still parsed the field. It is
  gone. A floor is a policy's `spec.minAlgorithmTier` or a Crypto Agility
  migration rule.

## [6.22.0-beta] — 2026-09-30

### Threat alerts reach every tenant, including one that never used reporting
Closes the 2.0.0-beta open item. The scheduled alert sync covered only
root and tenants reporting already held rows for, so a new tenant's first
critical or high threat signal became an alert only after someone opened
its Alert Center.
- **Reporting now asks auth for the tenant list.** It calls the new
  `GET /internal/tenant-ids` as `kms-reporting` every minute on the primary.
  The response holds active tenant IDs only.
- **Only reporting can call it.** Any other caller is refused and audited
  (`audit.auth.tenant_ids_listed`, `reason: service_identity_required`).
- **If auth can't be reached,** the sync still covers root and the known
  tenants, and logs the error.

## [6.21.0-beta] — 2026-09-30

### sbom reads never write
- `GET /sbom/latest`, `GET /sbom/history` and `GET /cbom/latest` (and the
  CBOM summary/readiness views built on it) generated and stored a snapshot
  when none existed, a write on a read path that also ran on cluster
  members. 1.37.0-beta fixed only `/cbom/history`. Now `latest` returns 404
  and `history` returns `[]` until `POST /sbom/generate`,
  `POST /cbom/generate` or the scheduler creates one
  (`TestBOMReadsWriteNothing`).

## [6.20.0-beta] — 2026-09-30

### HYOK: an unreachable policy service refuses (fail closed)
With `HYOK_POLICY_FAIL_CLOSED=false`, a HYOK proxy or DKE public-key request
ran when the policy service couldn't be reached (`policy_unavailable_fail_open`).
The setting is removed: the request is refused with `424 policy_unavailable`
and audited as `audit.hyok.request_denied` (`reason: policy_unavailable`,
`result: refused`). Until now that refusal wasn't audited at all. **Breaking:**
`HYOK_POLICY_FAIL_CLOSED` is ignored. The status field `policy_fail_closed`
is always `true`. Test: `TestHYOKPolicyUnavailableFailsClosed`.

## [6.19.0-beta] — 2026-09-30

### Keycore enforces the key lifecycle state table (breaking)
- **What was wrong.** `SetKeyStatus` and immediate activation
  (`POST /keys/{id}/activate`, used by playbook `activate_key`) accepted any
  target status from any live status. The state table in
  `lifecycle_state.go`, which says a compromised key only moves to destroyed,
  was consulted only by compromise detection's auto-suspend, so an operator
  or playbook could put a compromised key back into use.
- **Now.** Both paths check `CanTransition(from, to, false)`. A refused move
  returns `409 status_transition_refused` and emits
  `audit.key.status_transition_refused` (`from`, `to`, `reason`,
  `result: refused`); nothing changes and no success event fires. A playbook
  `activate_key` step on a compromised key fails with that status.
- `disabled` joins the table as an operator hold like suspended
  (active ↔ disabled, disabled → deactivated or compromised), and
  pre-active → compromised is allowed.
- Breaking: setting a key to its current status, and moves outside the
  table (for example deactivated → disabled), are now refused.
- Test: `TestSetKeyStatusEnforcesLifecycleTable`.

## [6.18.0-beta] — 2026-09-30

### Keycore serves an asymmetric key's public key; EKM TDE public keys work
- **New `GET /keys/{id}/public-key`** (keycore, route kernel, any verified
  identity; kernel event `audit.key.public_key_read`): the current
  version's public key as PEM SubjectPublicKeyInfo (`format: spki-pem`,
  with `version` and `algorithm`). The decision is the per-key read: the
  key must be visible to the caller (KEY_ACCESS_MODEL.md section 8); a
  hidden key is `404` and `audit.key.access_refused` (`not_visible`).
- **Where the key comes from.** An HSM key pair's version holds its PKIX
  public key. A software key pair holds only its encrypted PKCS#8 private
  key, so keycore derives the public half and zeroizes the private
  material. An imported public component is served as itself (PKCS#1 is
  re-encoded as SPKI).
- **Refused, and audited as refused:** a key with no public half (`409
  not_asymmetric`), a deleted key (`409 key_deleted`), and a public key with
  no SubjectPublicKeyInfo encoding in this release (`409 spki_unavailable`:
  ML-KEM, ML-DSA and SLH-DSA are held as raw bytes and are never labelled as
  SPKI).
- **EKM reads it for the user it serves.** `GET /ekm/tde/keys/{id}/public`
  asks keycore on every call, forwarding the caller's verified token with
  the new delegated usage `read` (pkg/delegation), so keycore decides by the
  user's view of the key. Before, keycore had no public-key route, so after
  6.12.0-beta the endpoint refused (`424 public_key_unavailable`) for every
  TDE key. Keycore's refusal is passed on with its status and reason (`403`,
  or `404` for a key the user can't see); anything else is still `424`.
  `audit.ekm.tde_key_accessed` carries `key_version` on success and
  keycore's reason on refusal.
- **Fixed: a stale public key after rotation.** ekm served its cached copy
  first, which after a rotation was the old version's key. The cache is now
  cleared by the rotation, refreshed from keycore, and never served in place
  of a keycore read. TDE key creation fills it from the same route.
- **A delegated `read` can't use a key.** Keycore refuses a delegated
  request with usage `read` on any key operation (`403`,
  `audit.key.access_refused` `reason: delegation_usage_mismatch`), so a read
  grant can't be turned into a use by a service.
- **Dashboard:** Keys > key detail has "Public key (PEM)" for asymmetric
  keys, which downloads the file from the new route and shows keycore's
  refusal if there is one.

### Tests
- keycore: `TestPublicKeyReadReturnsTheKeysSPKI` (the PEM is the public
  half of the stored private key), `TestPublicKeyReadRefusals`,
  `TestPublicKeyReadOfAHiddenKeyIsRefused`,
  `TestDelegatedPublicKeyReadUsesTheUsersView`,
  `TestDelegatedReadCannotPerformAKeyOperation`,
  `TestPublicKeyRouteRefusalsAudited`; `TestHSMResidentSigningKeys` now
  checks the route serves the HSM's own public key (run on real SoftHSM2).
- ekm: `TestTDEPublicKeyFollowsRotation`,
  `TestTDEPublicKeyKeycoreRefusalPassedOn`,
  `TestTDEPublicKeyReadCarriesTheUsersToken`,
  `TestHTTPKeyCoreClientPublicKey` (client against keycore's response and
  error shape). The ekm keycore fake no longer returns `public_key_pem` from
  `GET /keys/{id}`, which the real keycore never did.

### Open
- Post-quantum public keys (ML-KEM, ML-DSA, SLH-DSA) have no SPKI encoding
  here yet and are refused rather than served in another format.

## [6.17.0-beta] — 2026-09-30

### Reconciler: manifest policies converge
- **What was wrong.** The tenant reconciler POSTed every manifest policy to
  `POST /policies` on each 30 s tick. The policies table is unique on
  (tenant, name), so after the first apply every tick got a 400 that was
  only logged, and an edit to a policy's YAML in the manifest was never
  applied.
- **Now.** Each tick lists the tenant's policies and, per manifest entry
  (matched on `metadata.name`), creates it when absent, `PUT`s it when the
  YAML differs, and does nothing when identical, so unchanged ticks emit no
  policy create/update audit. A manifest edit now reaches the policy service
  as a new policy version; the manifest wins over UI edits to policies it
  names.
- **Failures surface.** List, parse and write failures are returned from the
  controller and appear as its `last_error` in `GET /reconciler/status`
  instead of only in the log.
- **Removal does not delete.** A policy removed from a manifest stays and is
  no longer managed (docs/AUTOMATION_ALKM_PQC.md).
- Tests: `TestManifestPoliciesConverge`, `TestManifestPolicyFailuresSurface`
  (`services/reconciler`).

## [6.16.0-beta] — 2026-09-29

### EKM agent: unused `rotate_path` setting removed
- The Go agent read `rotate_path` / `EKM_ROTATE_PATH` and filled in a
  default, but never called it. The setting is removed and ignored if
  still set. The deploy package's shell and PowerShell scripts keep their
  own `VECTA_ROTATE_PATH`, which they do call.

## [6.15.0-beta] — 2026-09-29

### EKM agent: the TDE key never leaves the KMS; dead export path removed
- **Removed** the agent's local key cache. At start-up `TryExportKey` called
  `GET /ekm/tde/keys/{id}` and `POST /ekm/tde/keys/{id}/export`. Neither
  route exists, and EKM TDE keys have no export setting. So with
  `key_cache_enabled: true` the agent only logged a fetch error and carried
  on without a cache. Its local `Encrypt`/`Decrypt` had no callers. The
  agent sends every DEK wrap and unwrap to the KMS
  (`POST /ekm/tde/keys/{id}/wrap`, `/unwrap`), where keycore decides each
  use.
- **Removed with it:** `pkg/keycache`, `samples/05-export-key-local-crypto.go`,
  the `key_cache_enabled` / `key_cache_ttl_sec` settings and their
  `KEY_CACHE_*` environment variables, and the dashboard's "Guide: Key
  Cache" page. An old config file that still sets them is ignored, not
  rejected: the settings never did anything.
- **REST catalogue corrected:** the TDE create example no longer sends
  `export_allowed`, which EKM ignores. It uses `name` and the real default
  algorithm (RSA-3072). The public-key example shows what the route really
  returns, including `424 public_key_unavailable`.
- **Enforced by** `TestAgentCallsOnlyRegisteredEKMRoutes`: every EKM path
  the agent calls, from its default config or a literal in its code, must be
  a route that `services/ekm` registers. `TestAgentHasNoKeyExportPath`
  keeps the export path from coming back. Both fail on the removed code.

## [6.14.0-beta] — 2026-09-29

### No plain HTTP at the edge
- **Port 80 is gone.** Envoy's redirect listener, the compose `80:80`
  mapping and install.sh's "Public HTTP port" prompt are removed. Clients
  use `https://` directly. This finishes INTERNAL_TLS.md slice 4.
- `make conformance` (`tls-only`) now fails if compose publishes port 80 or
  Envoy configures a redirect or a port-80 listener.

### KMIP certificate: runtime root, a PKI CA, or an external CA
- The KMIP listener's certificate has its own source in Certificates / PKI
  > Service mTLS > KMIP certificate, like the HTTPS edge: `listener: "kmip"`
  on `PUT /certs/edge-tls/certificate`, `POST /certs/edge-tls/csr` and
  `POST /certs/edge-tls/certificate/install`. `GET /certs/edge-tls` returns
  it as `kmip_certificate`. An unknown listener is refused
  (`invalid_listener`).
- KMIP reloads its certificate on the next handshake after certs replaces
  it (checked at most once a second); a replacement that doesn't load keeps
  the one in force. Client certificates still come from the KMIP client CA.

### Security: KMIP fails closed
- **Fixed:** a missing or unreadable KMIP certificate file made the
  listener fall back to a self-generated development certificate that
  accepted any client certificate unverified, and KMIP takes the caller's
  identity from that certificate. KMIP now waits up to 3 minutes for certs'
  files and otherwise refuses to start.
- **Removed:** `KMIP_CLIENT_CERT_VERIFY_DISABLED` (it did the same on
  request) and `pkgcrypto.DevServerCertWithCA`.
- **Fixed:** a configured `KMIP_CLIENT_CRL_FILE` that couldn't be read was
  ignored, so revoked clients were accepted. It now refuses start.

### Docs
- The deployment guide in the dashboard said the dashboard was at
  `http://localhost:5173` and tested login with plain HTTP to port 8001; it
  now says `https://localhost` and uses the HTTPS edge. Its port table
  lists what compose publishes.

### Tests
- `TestKMIPTLSFailsClosed`, `TestKMIPServerCertificateReloadsAndClientsAreVerified`
  (kmip, real handshakes: a client without a certificate or from another
  CA is refused, a replaced certificate is served without a restart, a
  broken one is ignored); `TestKMIPCertificateSource` (certs);
  `TestEdgeProfileAppliedByRealEnvoy` runs the Envoy config without the
  port-80 listener.

### Breaking
- Nothing answers on port 80; `http://` URLs and bookmarks stop working.
  `HTTP_PORT` is no longer read by install.sh.
- KMIP refuses to start without its certificate files, and
  `KMIP_CLIENT_CERT_VERIFY_DISABLED` no longer exists.
- After changing the KMIP certificate's source, KMIP clients must trust
  the new issuing CA.

## [6.13.0-beta] — 2026-09-29

### Edge certificate: runtime root, a PKI CA, or an external CA
- **Choose what the HTTPS edge serves** in Certificates / PKI > Service
  mTLS > Edge certificate (`PUT /certs/edge-tls/certificate`, root tenant):
  `vecta-runtime-root` (the default), a software CA from the PKI tab
  (issued, installed on every node and renewed by certs), or an external
  CA. This was INTERNAL_TLS.md slice 4.
- **External CA without moving the key.** Each node generates its key and
  a CSR (`POST /certs/edge-tls/csr`); the customer's CA signs it; the
  certificate is installed on that node (`POST
  /certs/edge-tls/certificate/install`) only if it is for that key, valid
  now, allows server authentication and is signed by the given chain. Both
  routes run on the node that receives them (`pkg/clusterroute.Local`).
  Envoy reloads the files through SDS. An expired external certificate is
  replaced by a runtime-root one rather than served expired.
- **Served, measured.** The edge probe now pins the certificate certs
  installed, so "served" in the dashboard means a handshake saw exactly
  that certificate.
- **Refused:** an unknown or inactive CA, the internal-services Sub CA, and
  HSM CAs (they sign only for a user; renewal is unattended).
- The source is stored in the new replicated table `cert_edge_certificate`
  (migration 015).

### The PQC inventory reports the external listeners
- `GET /pqc/inventory` returns `listeners`: each external listener as certs
  measured it (`accepted_groups`, `negotiated_group`, `measured_at`),
  classified from `pkg/cryptocatalog`: `classical` if it accepts any
  quantum-vulnerable group, `hybrid` if only hybrid ML-KEM groups.
  `interfaces` is `measured`, `not_measured` or `unavailable` (was always
  `not_assessed`). The pqc service reads `GET /certs/edge-tls/measurement`
  (any verified caller) with its service token. Compliance > PQC Migration
  Gaps shows "N of M accept classical".
- `pkg/cryptocatalog` knows Go's TLS group names (`CurveP256`, `CurveP384`,
  `CurveP521`, `secp256r1`...).
- **Fixed:** pqc's certs client sent no credential, so the certificate
  list in the inventory depended on certs accepting an anonymous call. It
  now sends the service token.

### X25519 is measured in every FIPS mode
- With FIPS mode on, Go won't offer X25519 alone, so the edge probe could
  not measure it. The probe now sends its own TLS 1.3 ClientHello offering
  only X25519 and reads the group the ServerHello selects. It performs no
  key exchange (the share is random bytes), so no non-approved
  cryptography runs. The probe also measures every group whatever the
  process's FIPS mode; before, its list came from the FIPS-filtered
  profile.

### Tests
- `TestEdgeCertificateFromPKICA`, `TestEdgeExternalCertificateFlow`,
  `TestEdgeCertificateRoutesAudited` (certs);
  `TestHelloProbeReadsSelectedGroup`, `TestProbeMeasuresX25519InFIPSMode`,
  `TestProbeRefusesAnotherCertificate` (svctls, real handshakes);
  `TestInventoryReportsMeasuredListeners`, `TestCertsClientEdgeMeasurement`
  (pqc); `TestTLSGroupNames` (cryptocatalog).
- `TestEdgeProfileAppliedByRealEnvoy` now also installs an external CA's
  certificate through the CSR flow and checks Envoy serves it, and checks
  X25519 is measured; it passes with certs in FIPS off, on and only. Its
  certificates live in a named Docker volume, because a macOS bind mount
  doesn't deliver the rename Envoy's SDS watch reacts to.

### Open
- Port 80 still redirects to HTTPS (the rest of slice 4).
- The KMIP listener's certificate stays on `vecta-runtime-root`.

## [6.12.0-beta] — 2026-09-29
### EKM no longer invents TDE public keys (breaking)
`GET /ekm/tde/keys/{id}/public` returned `"EKM-PUBLIC-"` plus a truncated
SHA-256 of tenant and key ID whenever keycore gave no public key, stored it
as the key's public key (`format: opaque`), and audited
`audit.ekm.tde_key_accessed` as a success. TDE key creation stored the same
value. Keycore's `GET /keys/{id}` never returns a public key, so **every EKM
TDE key** carried this invented value. It was derived from identifiers, not
key material (CLAUDE.md rules 6 and 8).

- `buildPublicKeyFallback` is removed. Key creation stores only a public key
  keycore returned, and otherwise leaves it empty.
- **Without a public key from keycore the endpoint refuses** with
  `424 public_key_unavailable`, records a `failed` key access log entry, and
  emits `audit.ekm.tde_key_accessed` with `result: refused`,
  `reason: public_key_unavailable` (severity warning). The success event now
  carries `result: success`. Because keycore exposes no public key over HTTP
  today, the endpoint refuses for every key until it does.
- **Stored values revoked:** migration `services/ekm/migrations/007_clear_invented_public_keys.sql`
  clears every `ekm_tde_keys.public_key_cache` starting `EKM-PUBLIC-`, with its
  format. Key listings and the gRPC key map show an empty public key for
  those keys.
- **Dashboard:** the EKM tab called this endpoint every 15 seconds for each
  assigned key only to show the key's algorithm. It now reads the new
  `assigned_key_algorithm` field of `GET /ekm/agents/{id}/status`, taken from
  the ekm key record, and `getEKMTDEPublicKey` is removed.
- No agent, SDK or JCA provider consumed the invented format.
- Tests: `TestTDEPublicKeyUnavailableRefuses`,
  `TestTDEPublicKeyUnavailableHTTP424`, `TestTDEPublicKeyFromKeycore`,
  `TestMigrationClearsInventedPublicKeys` (the migration also checked on
  Postgres 16), `TestAgentStatusCarriesAssignedKeyAlgorithm`.
- **Upgrade note:** a database that read its TDE public key from this
  endpoint now gets `424`; the value it had before was not a public key.

## [6.11.0-beta] — 2026-09-29

### Workload signing keys are sealed under the workload master key (security)
Each tenant's SPIFFE root CA private key and JWT-SVID signer private key
were stored as plaintext PEM in `workload_identity_settings`
(`local_ca_key_pem`, `jwt_signer_private_pem`). A database copy, volume
snapshot or governance backup was enough to mint SVIDs for any workload in
any tenant. CLAUDE.md rule 6.

- **Sealed at rest.** Both keys are one AES-256-GCM envelope per tenant
  (`pkg/crypto`, module-generated IVs) in new `signing_*` columns, with a
  random data key per row wrapped by the workload service master key. The
  key comes from keycore through `pkg/mek` (catalog entry `workload`,
  identity `kms-workload-identity`, purpose `workload-mek`), pinned and
  checked on every start, re-wrapped on keycore rotation. The sealed payload
  names its tenant. The service doesn't start without the key; it needs
  `KEYCORE_URL` (added to compose) and the `kms-workload-identity` service
  identity (added to auth's internal service clients).
- **Existing plaintext rows (per key, not a silent switch).** On start,
  before serving, and every 15 minutes, the primary
  (`clusterstate.RunsPrimaryJobs`) seals each plaintext row: the tenant goes
  into the exposure register first (`source: plaintext_storage`,
  `audit.workload.mek_exposure_recorded`), then one conditional update
  writes the envelope and empties both plaintext columns
  (`audit.workload.mek_signing_keys_sealed`). A row that can't be sealed is
  left unchanged and audited as `audit.workload.mek_signing_keys_seal_refused`;
  on the startup pass that stops the start. Members only read.
- **Rotation.** `POST /workload-identity/settings/rotate-signing-keys`
  (`workload.write`, `audit.workload.signing_keys_rotated`) replaces both
  keys in the same trust domain and closes the tenant's exposure entry; so
  does a trust-domain change. The dashboard has **Rotate Signing Keys** on
  Workload Identity → Overview. SVIDs issued under the old keys stop
  verifying.
- **Exposure register.** `GET /svc/workload/mek/exposure` and the
  acknowledge route (`workload.exposure.acknowledge`); Administration →
  Tenant → Security → Key exposure register lists "Workload signing keys".
- **Backups.** Governance refuses to capture a backup while any row still
  holds plaintext signing keys (`backup_create_refused`, naming
  `kms-workload-identity`), via the new `mek.Table.Plaintext`. Restoring an
  older backup is allowed; the workload's periodic pass seals the restored
  rows and records them as exposed.
- **Upgrade action:** rotate each tenant's signing keys once the upgrade
  has sealed them. Earlier copies of the database still hold the old keys.
- **Cluster:** `workload_mek_state` and `workload_mek_exposure` are
  replicated under `workload`.
- **Tests:** `TestSigningKeysSealedAtRestSQLite` / `…Postgres` (added to CI
  integration-postgres), `TestRotateSigningKeys`,
  `TestBackupRefusesPlaintextSigningKeys` / `…Postgres`,
  `TestCatalogIsValidAndMigrated`, and the dashboard's exposure-register
  catalogue test.

## [6.10.0-beta] — 2026-09-29

### Key access justifications fail closed in EKM, cloud BYOK and HYOK (breaking)
Until now ekm and cloud turned any key access error into an allow, and hyok
did so unless `HYOK_POLICY_FAIL_CLOSED` was set, because a caller could not
tell "keyaccess isn't deployed" from "keyaccess is down" (`KEY_ACCESS_URL` is
set in every deployment). Since 6.9.0-beta evaluation authenticates, so an
error now really means unreachable.

- **A real deployment signal.** `docker-compose.yml` passes the deployment's
  `COMPOSE_PROFILES` (which the installers and `start-kms.sh` / `.ps1` derive
  from `infra/deployment/deployment.yaml`) to ekm, cloud and hyok as
  `VECTA_DEPLOYED_PROFILES`. `run-local.sh`, which always starts keyaccess,
  sets it to `key_access_justifications`. Each service logs
  `key access justifications deployed=<bool>` at start.
- **Deployed, or unknown (unset or empty):** keyaccess decides. If it can't
  be reached, returns an error, or answers without an action, the operation
  is refused with `424 key_access_unavailable` and audited with
  `result: refused`, `reason: key_access_unavailable`:
  `audit.ekm.key_access_denied` (new), `audit.cloud.key_access_denied`,
  `audit.hyok.request_denied`. `HYOK_POLICY_FAIL_CLOSED` now governs only the
  policy engine.
- **Not deployed:** the operation runs, and its success event
  (`audit.ekm.tde_key_accessed`, `tde_key_rotated`, `audit.cloud.key_imported`,
  `key_rotated`, `sync_started`, hyok's request event) records
  `key_access_reason: key_access_not_deployed`, not an unexplained allow.
- **EKM deny decisions on unwrap and rotate are now audited**
  (`audit.ekm.key_access_denied`); before, only wrap's was, as
  `tde_key_accessed` with `status: denied`, which it no longer is. Cloud's
  deny events now carry `result: refused`.
- One gate, `pkg/keyaccess.Gate`, holds the decision for all three services;
  its zero value refuses.
- **Upgrade note:** enable or disable key access justifications in
  `deployment.yaml` and restart with `start-kms`. A profile added only with
  `docker compose --profile` isn't seen by the callers.

Docs: IDENTITY_AND_PQC (open item removed), API_REFERENCE,
SECURITY/AUDIT_EVENTS_2026-09, OPERATIONS_GUIDE, DECISIONS.

## [6.9.0-beta] — 2026-09-29

### Workload identity, key access and confidential: every route authenticates the caller (breaking)
The workload and keyaccess services and confidential's policy, summary,
evaluate and release-history routes sat on a legacy mux. Workload verified no
token at all: anyone who reached it could change a tenant's trust settings
and issue SVIDs, X.509 private keys included, for any tenant named in
`tenant_id` / `X-Tenant-ID`. Keyaccess and confidential verified a token but
checked no permission, and keyaccess took the tenant from the request. All
three are now on the `pkg/route` kernel and leave the route-kernel burn-down
list:

- **The tenant comes from the verified token.** A `tenant_id` naming another
  tenant is refused (`tenant_mismatch`) and audited.
- **New permissions:** `workload.read`, `workload.write`, `workload.issue`
  (issuing an SVID; an X.509 response carries the private key);
  `keyaccess.read`, `keyaccess.write`, `keyaccess.evaluate`;
  `confidential.read`, `confidential.write`, `confidential.evaluate`
  (`confidential.release` unchanged). Roles holding `*` or `<domain>.*` keep
  working; none of the three domains is covered by `kms.read` / `kms.write`.
- **Every request emits its own event**, refusals included:
  `audit.workload.<action>`, `audit.keyaccess.<action>`,
  `audit.confidential.<action>`. Existing subject names are kept. New:
  `audit.workload.settings_viewed`, `audit.confidential.policy_viewed`,
  `summary_viewed`, `releases_viewed`, `release_viewed`.
  `audit.keyaccess.approval_required` is gone: `decision_evaluated` carries
  `approval_required` and `approval_request_id`. Actor fields (`updated_by`,
  confidential `requester`) come from the token, never the body.
- **New playbook triggers:** `workload_svid_issued`, `workload_trust_changed`,
  `key_access_policy_changed`, `attestation_policy_changed`.

### Workload token exchange: the SVID is the credential (breaking)
`POST /workload-identity/token/exchange` needs no bearer token, so a workload
holding only an SVID can call it, and it now really authenticates that SVID
(docs/DECISIONS.md, 2026-09-29):

- **X.509-SVIDs need proof of possession.** A certificate chain is public,
  so it used to buy a token for anyone who had seen it. The request now
  carries `x509_svid_proof` (`signed_at`, `signature` by the SVID's private
  key over the tenant, leaf SHA-256 and time), accepted once within two
  minutes. The dashboard signs it in the browser for an SVID it just issued.
- **An SVID gets only its own registration.** A `registration_id` for
  another workload used to hand over that workload's permissions; now 403
  `svid_registration_mismatch`.
- **The audience must be one the tenant allows,** even when the request
  names it. Before, naming any audience skipped the `allowed_audiences`
  check.
- **Federated bundles apply only while `federation_enabled` is on.** The
  setting was recorded but never consulted.
- `client_id` was removed from the request: the minted token's client is the
  registration. Refusals are audited under `audit.workload.token_exchanged`
  with the verified SPIFFE ID as actor, and a reason (`svid_invalid`,
  `audience_not_allowed`, `svid_proof_*`, `registration_not_found`, …).

### Keyaccess evaluate: only ekm, cloud and hyok, with their service token
`pkg/keyaccess` sent no `Authorization` header, and keyaccess sat behind its
JWT middleware, so **every evaluation got 401**. EKM and cloud treated that
as "service unavailable" and allowed the operation; HYOK (fail-closed by
default) refused it. The client now sends the caller's service JWT, and
`POST /key-access/evaluate` answers only the `kms-ekm`, `kms-cloud` and
`kms-hyok-proxy` identities, each for its own service
(`evaluator_identity_required`, `service_mismatch`). Once deployed, a tenant
with justification enforcement on gets real decisions in ekm and cloud
instead of silent allows.

### Record-only settings removed (breaking)
- Workload `disable_static_api_keys` and `rotation_alert_enabled` /
  `rotation_warn_hours` / `rotation_critical_hours`: nothing acted on them.
  The dashboard checkbox and the Posture line that quoted it are gone.
  Sending them is now a 400. The `disable_static_api_keys` column stays in
  the table, unread.
- Keyaccess rule `allowed_time_windows` / `outside_window_action`: in the
  API type, never stored or enforced.
- `requested_by` on SVID issue and the confidential evaluate `requester`
  field in the dashboard (the verified caller is recorded).

### Workload key usage says "unavailable" instead of 0
Usage, the summary's key-use counts and the graph's usage edges are read
from the audit log. The workload service called it with no token, so they
were always empty or 0. It now forwards the caller's verified token.
When the audit log can't be read, the summary and graph carry
`key_usage_unavailable`, `GET .../usage` returns 502 `audit_unavailable`, and
the dashboard shows "unavailable". Settings TTLs edited in the dashboard are
now sent as numbers (a string used to fail the save).

### Kernel
`route.Router.Public(r)`, `route.Call.Authenticated(actor, type)` (a Public
route records the identity it verified itself) and
`pkg/jwtauth.MustWrapRouter`.

### Open (documented, not fixed here)
- The workload CA and JWT signer private keys are still stored as PEM, not
  sealed under `pkg/mek`. *(Fixed in 6.11.0-beta.)*
- EKM and cloud still allow an operation when keyaccess can't be reached,
  and HYOK does unless it is fail-closed.
- The X.509 proof replay cache is in the primary's memory; a restart inside
  the two-minute window forgets it.
## [6.8.0-beta] — 2026-09-29

### The external edge's key exchange is a real, measured control
- **One profile for both external listeners.** Certificates / PKI > Service
  mTLS > External edge key exchange sets the TLS 1.3 groups the HTTPS edge
  (Envoy, 443) and the KMIP listener (5696) accept: PQC required (hybrid
  ML-KEM only), PQC preferred (the default) or classical. Until now Envoy's
  edge set no `ecdh_curves` and KMIP no `CurvePreferences`, so both used
  their library's defaults and nothing in the product chose them.
- **Applied without dropping connections.** Certs publishes the profile in
  `mtls-policy.json` (`edge`) and Envoy's group list in `edge-ecdh-curves`.
  The new `infra/envoy/entry.sh` writes the list into the edge listener and
  hot-restarts Envoy (`--restart-epoch`) when it changes; an invalid list is
  refused at start and ignored later. KMIP reads the profile on every
  handshake (`svctls.WatchEdge`).
- **Measured, not assumed.** Certs completes a TLS 1.3 handshake with each
  listener once per group (`svctls.ProbeGroups`) and records what it
  accepts, the group it negotiates and its certificate serial. "In force"
  and `audit.certs.edge_tls_applied` come only from that measurement.
- **FIPS.** With FIPS mode on, X25519 alone is dropped from the edge
  profiles, as for internal mTLS, and is not measured. The FIPS impact
  notes say so.
- **Audit.** `audit.certs.edge_tls_read`, `audit.certs.edge_tls_policy_updated`
  (refusals `not_root_tenant`, `invalid_policy`, `unchanged`),
  `audit.certs.edge_tls_applied`.
- **Fixed:** certs' `platform_mtls_observed` upsert dropped
  `last_handshake_group` and `last_handshake_at`.
- **Tests.** `TestEdgeProfileAppliedPerHandshakeAndMeasured`,
  `TestEdgePolicyUnreadableKeepsCurrent`, `TestEnvoyCurves` (svctls, real
  handshakes); `TestEdgeTLSRoutesPublishAndAudit`,
  `TestEdgeTLSAppliedOnlyWhenMeasured`, `TestEdgeProbeUnreachableIsNotApplied`
  (certs); `TestEdgeProfileAppliedByRealEnvoy` runs Envoy v1.39.1 with the
  repository's `envoy.yaml` and `entry.sh`, measures pqc-required then
  classical through a hot restart, and checks an invalid list is ignored
  (CI step "Edge key exchange through a real Envoy");
  `TestMTLSStorePostgres` covers the edge rows on Postgres.

### Removed: interface records no listener read
- **Keycore's interface ports and TLS defaults are gone.** `GET/POST
  /access/interface-ports`, `DELETE /access/interface-ports/{name}` and
  `GET/PUT /access/interface-tls-config` stored a bind address, port,
  protocol, "enabled" flag and certificate source per interface. No
  listener, Envoy config or certificate materializer read them: ports come
  from the deployment and the edge and KMIP certificates from
  `vecta-runtime-root`. Saving showed "TLS defaults updated and applied to
  TLS-enabled interfaces", which was not true.
- **Migration 032** drops `key_interface_ports` and
  `key_interface_tls_defaults`; 004 no longer creates the first, and 006,
  007 and 031 are deleted.
- **Dashboard.** System Administration > Interfaces lists the ports the
  container runtime reports as published, read-only. The "Configure TLS"
  dialog in Runtime Crypto is gone.
- **Tests.** `TestInterfacePortRoutesRemoved`,
  `TestInterfacePortTablesDroppedPostgres` (fresh and upgraded schema).

### Breaking
- The five interface routes return 404. Their audit subjects
  (`interface_ports_listed`, `interface_port_upserted`,
  `interface_port_deleted`, `interface_tls_config_read`,
  `interface_tls_config_updated`) are no longer emitted.
- The Envoy container's entry point is `infra/envoy/entry.sh`; a custom
  deployment that runs Envoy with its own command gets the `envoy.yaml`
  default (PQC preferred) and no hot restart.

### Open
- Choosing another CA for the edge certificate (INTERNAL_TLS.md slice 4) is
  not built; the certificate comes from `vecta-runtime-root`.
- The pqc inventory still reports interfaces as `not_assessed`; the edge
  measurement is on the Service mTLS page.

## [6.7.0-beta] — 2026-09-29

### Keycore: destroying an HSM key with no HSM connector is audited
An HSM-resident key destroyed while the platform ran no HSM connector
(disabled after the key was made) skipped HSM cleanup without a word: the
objects stayed on the token and no event said so. It now emits
`audit.key.hsm_destroy_failed` (critical, `result: failure`,
`reason: hsm_not_configured`) naming every version's label, as the
unreachable-HSM case already did, and never `hsm_objects_destroyed`. Remove
the objects in the HSM, or re-enable the connector and confirm with
`POST /keys/{id}/destruction-check`. Test:
`TestDestroyWithoutHSMConnectorIsAudited`.

## [6.6.0-beta] — 2026-09-29

### Docs: the identity and PQC guide describes what the product does
`docs/IDENTITY_AND_PQC.md` was audited section by section against the code,
following each claim to the route that serves it. Most of it described
features that don't exist. It was rewritten to what the product does, and
its "Removed claims" section lists what went:

- **Workload identity:** no agent, Workload API, `svid-tool`, or Kubernetes,
  cloud, Docker, Unix or TPM attestor exists. Registration `selectors` are
  recorded, never checked. The token exchange isn't RFC 8693, and SVIDs
  can't be federated into AWS, GCP or Azure. X.509 SVID private keys are
  generated by the KMS and returned in the issue response.
- **Attested key release:** verification covers AWS Nitro COSE documents
  and Azure MAA / GCP Confidential Space JWTs. It doesn't cover raw TDX
  quotes or SEV-SNP reports. The service issues no nonces. The release
  seals with `RSA-OAEP-256+A256GCM` through `POST /confidential/release`,
  not an `action: key_release` on `/evaluate`.
- **Key access justifications:** they gate EKM, cloud BYOK and HYOK
  operations only. Keycore decrypt never consults them. There's no
  `X-Key-Access-Justification` header and no built-in code catalogue.
- **PQC:** hybrid/composite keys, hybrid KEM wraps, hybrid-KEK backups and
  a hybrid root CA were presented as features. Keycore refuses any
  algorithm containing `+`, certs refuses PQC and hybrid certificates, and
  platform backups are AES-256-GCM (HSM-wrapped or operator-held key). The
  real hybrid is TLS key exchange (`X25519MLKEM768` and the other ML-KEM
  groups). ML-DSA sizes were the pre-standard Dilithium values and are now
  the FIPS 204 ones. Agency deadlines, "Recommendation" lines and
  unmeasured SLH-DSA timings are gone.

`docs/API_REFERENCE.md`'s workload, confidential (policy / evaluate /
history) and keyaccess sections carried the same invented fields
(attestors, RFC 8693 `subjectToken`, `allowedProviders` with TDX and SEV,
`requireNonce`, pagination tokens) and a `JUSTIFICATION_REQUIRED` error that
no code returns. They now list the real routes, fields and response keys.
`docs/README.md`'s index lines no longer promise "no static API keys".

### Open (documented, not fixed here)
- The workload and keyaccess routes, and confidential's policy, evaluate
  and history routes, don't authenticate the caller. They sit on a legacy
  mux with the tenant taken from `tenant_id` / `X-Tenant-ID`, and the
  gateway has no JWT filter. Only `POST /confidential/release` is on the
  `pkg/route` kernel.
- The workload CA and JWT signer private keys are stored as PEM in the
  workload database, not sealed under `pkg/mek`. *(Fixed in 6.11.0-beta.)*
- EKM and cloud allow the operation when keyaccess can't be reached, and
  so does HYOK unless it is fail-closed. `disable_static_api_keys`,
  `rotation_alert_*` and the rule time-window fields are record-only.
## [6.5.0-beta] — 2026-09-29

### Keycore: the destruction check reports what it checked, not "zeroization verified"
`POST /keys/{id}/zeroize-verify` answered `"zeroization_verified": true`
when the key cache held no entry for the key, or when there was no cache.
That claimed FIPS 140-3 SSP zeroization from a check that looked at
neither the stored material nor the HSM, and the cache holds only key
metadata, never material. It could not even answer for a destroyed key:
destroy sets the status to `deleted`, the handler wanted `destroyed`, and
`GetKey` answers 404 for a deleted key, so every call got 404 or 409. It
also forced a Go GC and reported `gc_forced`, which zeroes nothing.

- **Breaking: replaced by `POST /keys/{id}/destruction-check`** (same
  `key.integrity.verify` permission, key must be visible). For a destroyed
  key it counts the remaining `key_versions` rows (the only table holding
  material) and, with the HSM connector enabled, lists every HSM object
  under the key's label prefix. Destroy clears the row's HSM labels, so the
  check goes by label, not by what the row says. `result` is `removed`,
  `material_remains` or `incomplete` (HSM unreachable). Every answer
  carries `not_covered`: the check can't see database pages until vacuumed,
  backups or process memory, and never claims they were overwritten.
- **Audit:** `audit.key.destruction_checked` replaces
  `audit.key.zeroize_verify_requested`, with the result and counts;
  `material_remains` is critical. A live key is refused (409
  `key_not_destroyed`) and audited as refused.
- `Service.ConfirmKeyMaterialZeroized` is removed.
- docs/CLUSTERING.md no longer says keycore's zeroization check runs on
  every node; that scheduler was removed in 5.3.0-beta.
- The dashboard never displayed the field; only the generated API catalogue
  listed the route.
- **Open:** on a cluster the check runs on the primary (the default for
  POST). Checking each member's replica is not built.

## [6.4.0-beta] — 2026-09-29

### Interfaces: the record-only PQC mode is removed
- **Removed keycore's per-interface `pqc_mode`** (`inherit`, `classical`,
  `hybrid`, `pqc_only`) from `POST /access/interface-ports`, its responses,
  the `interface_port_upserted` audit details, the store, and System
  Administration → Interfaces (the "Quantum Mode" column and selector and
  the "PQC Mode Effect" line). No listener read it: Envoy, svctls and the
  KMIP listener never consulted it, the pqc inventory stopped reporting it
  in 6.3.0-beta, and `inherit` pointed at the tenant PQC policy removed in
  6.3.0-beta. It was not kept as a preview because the real control already
  exists for the listeners the KMS owns.
- **Where key exchange is really set.** Each internal identity's TLS 1.3
  groups come from its svctls `kx_profile` (`pqc-required`: hybrid ML-KEM
  only; `pqc-preferred`, the default; `classical`), chosen in Certificates /
  PKI → Service mTLS, applied by a restart and audited. Envoy's connections
  to services offer `X25519MLKEM768` first (`infra/envoy/envoy.yaml`).
- **Migration 031** drops `key_interface_ports.pqc_mode`; migration 008,
  which added it, is deleted.
- **Tests.** `TestInterfacePortPQCModeRemoved` (a write that sends
  `pqc_mode` is rejected with 400 and audited as a failure, nothing is
  stored; a normal upsert carries no `pqc_mode` in the response or the
  event), `TestInterfacePQCModeDroppedPostgres` (031 on real Postgres, on a
  fresh schema and on one that still has the column).

### Breaking
- `POST /access/interface-ports` with a `pqc_mode` field returns
  `400 bad_request` (unknown field). Drop the field.

### Open
- The external edge listener (Envoy `DownstreamTlsContext`) sets no
  `ecdh_curves`, so its key exchange is Envoy's default and the product
  offers no control over it. A real control would be a node-wide edge
  profile written into the Envoy config and proved by a handshake test, not
  a per-tenant interface row.

## [6.3.0-beta] — 2026-09-29

### PQC: the record-only policy and the invented readiness scores are gone
5.4.0-beta hid the pqc policy switches and the readiness score in the
dashboard but left them in the API. They are now removed from the pqc
service:

- **Removed: `GET`/`PUT /svc/pqc/pqc/policy`** and the `pqc_policies`
  table (migration 003). Per field: `require_pqc_for_new_keys` never reached
  key creation; `profile_id`, `default_kem`, `default_signature` and
  `hqc_backup_enabled` changed only recommendation text;
  `certificate_default_mode` changed nothing; `interface_default_mode` was
  reported as the TLS mode of interfaces nobody measured; and
  `flag_classical_usage`, `flag_classical_certificates` and
  `flag_non_migrated_interfaces` only hid findings from the inventory. None
  was kept as a preview: the real control already exists. **To require
  post-quantum for new protection, add a Crypto Agility migration rule**
  (`match_kind: quantum_vulnerable`, `action: decrypt_only`), which keycore
  enforces on every key operation.
- **Removed invented scores.** `readiness_score` (scans: 55% PQC-or-hybrid
  share + 30% average QSL + 15% hybrid share; inventory: 85% of a readiness
  percent that counted hybrid as 0.7, plus 15%), `quantum_readiness_percent`,
  and a plan summary's `estimated_risk_reduced` (an average of hand-picked
  priority weights). The measured counts they blended remain:
  `total_assets`, `pqc_ready_assets`, `hybrid_assets`, `classical_assets`,
  and per-inventory `{total, classical, hybrid, pqc_only}`.
- **Interfaces are "not assessed".** The inventory reported an interface
  whose `pqc_mode` was `inherit` as having the policy's default mode (hybrid
  by default), which presented an unmeasured TLS mode as a measurement.
  `interfaces` is now always `"not_assessed"`, and `non_migrated_interfaces`
  is gone. Every classical key and certificate is always listed.
- **Dashboard.** Compliance → PQC Migration Gaps shows "N of M classical"
  instead of "x/100", key PQC/hybrid counts instead of the policy profile,
  and "Interface TLS: not assessed". The Command Center KPI shows
  "PQC or hybrid assets N / M" from the latest scan. The recommendation check
  "PQC readiness has been assessed" passes when a scan exists, not on a
  score threshold. System Administration → Interfaces says the per-interface
  PQC mode is recorded only (it previously said "Classical + PQC handshake
  path enabled").
- **Audit.** `audit.pqc.policy_viewed`, `audit.pqc.policy_updated` and the
  kernel actions `policy_read` / `policy_update_requested` are gone with the
  routes. `audit.pqc.scan_completed` and `audit.pqc.inventory_viewed` carry
  counts, not a score.
- **Tests.** `TestPQCPolicyRemovedAndNoInventedScores`,
  inventory counts in `TestPQCServiceReadinessPlanExecuteRollback`,
  `TestPolicyAndScoreDroppedPostgres` (real Postgres).

### Breaking
- `/pqc/policy` returns 404. Clients reading `readiness_score`,
  `quantum_readiness_percent`, `policy`, `non_migrated_interfaces`,
  `effective_pqc_mode` or `estimated_risk_reduced` must use the counts.
  `proto/pqc.proto` reserves `ReadinessScan` field 9.

### Open
- Keycore's per-interface `pqc_mode` (System Administration → Interfaces) is
  still recorded and not enforced at any listener. It should be removed,
  made a preview, or enforced. (Removed in 6.4.0-beta.)

## [6.2.0-beta] — 2026-09-29

### Crypto Agility: risk overview
- **Sensitivity × exposure.** The risk assessment's `heatmap` counts assets
  by the sensitivity the customer recorded (critical, high, medium, low,
  unknown) and their timeline (exposed, at the limit, time to spare, not
  assessed, no threat). The Risk assessment view shows it under the
  summary cards.
- **Profile completeness.** `profile` counts the assets that carry each
  value the assessment rests on: owner, shelf life (X), migration time (Y),
  cost, sensitivity, a link to at least one live key, and all of them
  together. A value left `unknown` is not counted, so gaps show as gaps
  rather than as a score.
- Both are computed by keycore's `computeCarafAssessment` from the
  customer's own records (`TestCarafAssessmentComputation`); the
  dashboard test's fixture is recomputed from that function.

## [6.1.0-beta] — 2026-09-29

### Crypto Agility: algorithm-swap drill
- **What it does.** Crypto Agility → Swap drill rehearses a move from one
  algorithm to another before you schedule it. Keycore generates throwaway
  keys for both with its own key generation. It runs each algorithm's
  operation (sign and verify, encrypt and decrypt, or encapsulate and
  decapsulate) through the same engine functions your keys use and checks
  every round trip. It records median key-generation, operation and check
  times on the node that served the request, plus the real sizes of the
  private key, public key and output. The keys stay in memory and are
  zeroised. Nothing enters the key inventory.
- **Same rules as a real key.** Both algorithms must pass the tenant's FIPS
  mode; in `only` mode a drill naming ML-DSA or SLH-DSA is refused, as the
  key would be. The target must be allowed for new protection by the
  tenant's migration policy: a `disallowed` or `decrypt_only` rule refuses
  the drill with the same reasons key operations use (`policyRefusal` is
  now shared). A name without a parameter set (`RSA`) is refused, so a
  measurement is never labelled with a name that doesn't say what was
  generated. ECDH has no round trip keycore can run and is refused.
- **API.** `POST /agility/drills` (`from_algorithm`, `to_algorithm`,
  `iterations` 1–10, default 5) and `GET /agility/drills` (latest 50).
  Kernel events `audit.key.agility_drill_run` (details `from_algorithm`,
  `to_algorithm`, `iterations`, `drill_result`, `drill_error`; refusals
  `fips_mode_violation`, `crypto_policy_disallowed`,
  `crypto_policy_decrypt_only`) and `audit.key.agility_drills_listed`. One
  drill runs at a time per keycore process (`409 drill_in_progress`), and
  each algorithm gets 20 seconds so a drill finishes inside the 60-second
  server and gateway timeouts; `round_trips` says how many rounds ran.
- **Storage.** Migration `030_agility_drills.sql`, replicated under keycore
  (`pkg/clustercatalog`). A drill is a write, so a cluster member forwards
  it and it runs on the primary.
- **FIPS impact catalogue.** The ML-DSA / SLH-DSA entry now names drills.
- **Not built:** a maturity-tier view. Tiers would be a scale taken from a
  standards document, which the customer-decides rule keeps out of the
  product (docs/DECISIONS.md).

## [6.0.0-beta] — 2026-09-29

### Security: services acting for a user now use keys as that user
- **What was wrong.** dataprotect (FPE, tokenization, field, envelope and
  searchable encryption), payment (PIN and TR-31 translation, PVV/CVV/MAC,
  ISO 20022) and certs (CA signing) called keycore with their own service
  identity, and keycore lets a service identity use any key in the tenant.
  So anyone who could reach one of those services could use any key there,
  whatever their grants.
- **Fix (`pkg/delegation`).** These services now forward the user's own
  verified token (`X-Vecta-Delegated-Token`) and the usage they perform
  (`X-Vecta-Key-Usage`) on the keycore call that decides: dataprotect's
  per-operation meter, payment's key export and ISO 20022 operations, and
  certs' signatures. Keycore verifies the token itself, accepts it only from
  a service identity, for a user (not a service token) of the key's tenant,
  and decides as that user: grants must allow the usage. Refusals are
  audited as `audit.key.delegation_refused` (`delegation_by_non_service`,
  `delegation_token_invalid`, `delegation_token_is_service`,
  `delegation_tenant_mismatch`, `delegation_usage_invalid`) or
  `audit.key.access_refused` with `via` and `usage`; every keycore event
  for a delegated request carries `on_behalf_of`, `via` and `usage`.
  Envoy strips both headers from outside requests.
- **New grant operations:** `fpe-encrypt`, `fpe-decrypt`, `tokenize`,
  `detokenize`, `translate-wrap`, `translate-unwrap`, `translate-encrypt`,
  `translate-decrypt`, `certificate-sign`, `crl-sign`.

### Breaking
- A user's grants now decide these operations. A user with only `encrypt`
  on a key can't FPE-encrypt with it through dataprotect; grant
  `fpe-encrypt` (or `all`). Signing with an HSM CA as a non-admin needs
  `certificate-sign` / `crl-sign` on the CA's key. Admins and key creators
  are unaffected. Requests with no user behind them (schedulers, ACME/EST,
  OCSP) still act as the service.

### Known issue (not introduced here): payment operations by key ID
- Payment fetches key material with `POST /keys/{id}/export` and reads a
  plaintext `material` field; keycore's export only returns material
  wrapped under a `wrapping_key_id`. Every payment operation that names a
  key by ID therefore fails (`keycore_export_failed`); only inline
  `material_b64` works. Payment's tests used a fake keycore that returned
  the field. The fix needs an owner decision
  ([KEY_ACCESS_MODEL.md](docs/SECURITY/KEY_ACCESS_MODEL.md) section 5a).

## [5.4.0-beta] — 2026-09-29

### Crypto Agility: risk assessment (CARAF) and readiness & execution
The tab now has three views: **Migration policy** (5.1.0-beta), **Risk
assessment** and **Readiness & execution**.

- **Risk assessment (CARAF).** Keycore `/agility/caraf/*`, tables
  `caraf_threats` and `caraf_assets` (migration 029). The customer records:
  - threats (the algorithms each breaks and the years until they expect it,
    Z);
  - assets (ownership, implementation, post-quantum support, location,
    jurisdiction, sensitivity, the years their data or device must stay
    protected X, the years a migration would take Y, cost, and linked keycore
    keys whose live algorithms are read from keycore).

  Keycore computes per asset whether X + Y exceeds the soonest applicable
  Z (exposed, at the limit, time to spare, not assessed), suggests a
  mitigation from the CARAF matrix, and tracks the decision (secure, accept
  with a future review date, phase out, compensating control) with owner,
  due date and status. It also keeps a roadmap by date and findings for
  exposed-undecided assets, lapsed acceptances, overdue decisions and
  linked keys no longer live. Every value is the customer's; the product
  supplies no threat dates or defaults. Every write is audited
  (`audit.key.caraf_*`), and a recorded decision is the Playbooks trigger
  `crypto_risk_decision_recorded`.
- **Readiness & execution** replaces the orphaned Post-Quantum tab
  (`PostQuantumTab.tsx` deleted). It shows the pqc service's scan across
  keys, certificates, discovered TLS endpoints and cloud keys; the assets to
  migrate with targets; and execution plans with dry run, execute (a
  successor key per key step; other steps manual) and rollback. The old
  tab's 0-100 readiness score and its PQC-policy switches (require PQC for
  new keys, HQC backup, default modes) are not shown: the score was an
  unsourced weighting and the switches are stored by pqc but enforced
  nowhere.
- **Removed: the tenant minimum algorithm tier check (5.1.0-beta).** It read
  `posture_min_algorithm_tier` from governance, which has no such setting,
  so it could never fire. A floor is a migration rule:
  `quantum_vulnerable → decrypt_only` requires post-quantum algorithms for
  new protection (`TestQuantumVulnerableRuleActsAsPQCFloor`).
- **Open:** the pqc policy's record-only switches and readiness score remain
  in the pqc API; enforce or remove them.
## [5.3.0-beta] — 2026-09-29

### Automation/ALKM/PQC: the guide now matches the code, and dead or fake code is gone
`docs/AUTOMATION_ALKM_PQC.md` was audited row by row against the code.
Most of its "At a glance" table described code that was never wired, did
nothing, or was named for something it didn't do. The guide is rewritten,
with a "Removed claims" table naming each former claim and what the code
really did. The code behind those claims is removed in this release's
commit (recoverable from git history before it):

- **Removed, never called or never wired:** keycore's migration planner and
  Y2Q score (and `pkg/migration`), `ComputePQCKCV`, the unused ML-KEM/ML-DSA
  wrappers in `pqc_primitives.go`, the dependency checker, the wake self-test
  registry, keycore's workflow-template table, keycore's and KMIP's
  auto-taggers, and the cold-tier archiver (`KEYCORE_ARCHIVE_DIR`,
  `KEYCORE_ARCHIVE_KEK_B64`).
- **Removed, ran but did nothing:** the zeroization scheduler (it called a
  store method that didn't exist; `KEYCORE_ZEROIZATION_SCHEDULER_ENABLED` is
  gone). The on-demand `POST /keys/{id}/zeroize-verify` stays.
- **Removed, audited work that never happened:** keycore's `POST
  /tenants/onboard` provisioned nothing but emitted `audit.tenant.onboarded`
  every 30 s per manifest; `POST /keys/{id}/archive` answered
  `archive_queued` and queued nothing. The reconciler no longer calls them.
- **Removed, harmful:** the KMIP auto-decommission (`GET
  /kmip/clients/decommission-candidates`, `POST
  /kmip/clients/{id}/decommission`). It judged "no traffic in 90 days" from
  the client row's `updated_at`, which KMIP traffic never changes, so every
  KMIP client was set dormant, and then refused at connect, 90 days after it
  was created, however busy it was.
- **Removed, mislabelled:** the audit "HNDL detector" counted raw encrypt
  volume per tenant for any algorithm (its byte count was never reported);
  it did not measure harvest-now-decrypt-later exposure.
- **Renamed:** `audit.security.auto_quarantined` is now
  **`audit.security.sustained_risk_detected`** (nothing was ever quarantined).
  It carries the key or target as `target_type` / `target_id` and is a new
  playbook trigger, **`sustained_risk_detected`**, so a playbook can disable
  or deactivate the key. SIEM rules on the old subject need the new one.
- **Key lifecycle reconciler: rotation only.** Keycore's
  `GET /keys/due-for-lifecycle` returns only active keys due for rotation
  (operator expiry, cryptoperiod, 80% of `ops_limit`). It used to return
  "destroy" for compromised keys and for deactivated keys past 30 days, but
  keycore refused every such call (the reconciler sent no pre-destroy
  acknowledgements), and an unattended, irreversible destroy belongs behind
  a governance approval.
- **Reconciler errors are visible.** A refused lifecycle scan, or a failed
  tenant quota apply, is now the controller's `last_error` in System
  Administration → Health instead of being swallowed. The reconciler's
  unused `KMIP_URL` / `AUDIT_URL` are dropped from compose.
- **Posture:** keycore no longer parses four posture fields governance never
  stored and nothing read (`posture_hndl_detection_enabled`,
  `posture_auto_quarantine_enabled`, `posture_auto_migration_enabled`,
  `posture_zeroization_interval_mins`).
- **Correction to 5.1.0-beta:** the tenant minimum algorithm tier it says
  keycore now enforces comes from governance posture
  (`posture_min_algorithm_tier`), which **governance does not store or
  return**. In a deployment the value is always empty, so that check never
  fires; its test injects the value directly. Governance needs the setting
  (with UI and audit), or the check should go. A floor that takes effect
  today is a policy's `spec.minAlgorithmTier` or a migration policy rule.
- The audit event catalogue drops entries for events nothing emits
  (`wake_kat_failed`, `hbs_exhausted`, `dependency_blocked_destroy`,
  `predictive_rotation_scheduled`, `lifecycle_auto_transition`,
  `zeroization_verified`, `archive_*`, `tenant.onboarded`,
  `kmip.client_dormant|revoked`, `pqc.attestation_recorded`).
- README, `docs/RECOMMENDED_FEATURES.md` (composite keys, dependency-aware
  destruction and auto-quarantine were listed as existing),
  `docs/SECURITY/ALGORITHM_TRANSITIONS.md`, `docs/SECURITY/KEY_ACCESS_MODEL.md`
  and `docs/API_REFERENCE.md` are corrected to match.
- Tests: `TestSustainedRiskPublishedOnceWithTarget`,
  `TestEvaluateLifecycleRotatesAndNeverDestroys`,
  `TestDueForLifecyclePostgres`, `TestDecommissionRoutesRemoved`,
  `TestLifecycleScanFailureIsReportedAndArchiveIsNotCalled`, and the
  removed routes in `TestTokenlessRoutesAreOnlyTheDeclaredOnes`.

Still open (in the guide): `SetKeyStatus` doesn't enforce the lifecycle
state table, so a compromised key can be set active again; manifest
policies are created once and later edits aren't applied.

## [5.2.0-beta] — 2026-09-29

### Security: the pqc service verified no token and checked no permission
- **What was exposed.** The pqc service (readiness scans, migration plans,
  plan execution and rollback) was a raw mux with no JWT verification: the
  tenant came from the query string or body, no permission was checked, and
  the actor recorded for a plan execution (which creates successor keys in
  keycore under the pqc service identity) was whatever the body's `actor`
  said.
- **Fixed.** Every route now goes through the `pkg/route` kernel behind
  `pkg/jwtauth`: the tenant is bound to the verified token, `pqc.read` /
  `pqc.write` are enforced, each request emits `audit.pqc.<action>` with
  refusals, and the actor is the verified caller. `services/pqc/handler.go`
  leaves the route-kernel burn-down list.
- Needed before the Crypto Agility tab offers plan execution (next release).

## [5.1.0-beta] — 2026-09-29

### Crypto agility: the customer's migration policy, enforced
The owner: "avoid quoting direct sources, drafts, references; let customer
decide when and what he wants to migrate as per his policy".

- **Removed: standards schedules and citations.** `pkg/cryptocatalog` now holds
  only technical facts (strength, post-quantum category, quantum
  vulnerability, `weak`: broken, under 112 bits, ECB or FF3). The 3.2.0-beta
  approval schedules, deadlines, source list and "draft/proposed" labels are
  gone from the catalogue, the API and the tab.
- **Added: migration policy rules** (keycore `GET|POST /agility/policy/rules`,
  `PUT|DELETE /agility/policy/rules/{id}`, table `agility_policy_rules`,
  migration 028). A rule covers an algorithm, a family, every
  quantum-vulnerable or weak algorithm, or everything below a strength, and
  from the customer's `effective_date` makes those keys `deprecated`,
  `decrypt_only` (new protection refused, existing data still readable) or
  `disallowed` (every cryptographic operation refused; export and destroy
  still work), with an optional target algorithm.
- **Enforced on every key operation** in keycore's `checkPolicy`; a refusal is
  `403 policy_denied` and `audit.key.crypto_policy_refused` with the rule.
- **Fixed: the tenant minimum algorithm tier (governance posture) was stored
  but never enforced.** Keycore now refuses new keys and new protection below
  it, and fails closed on a value that isn't a tier.
- **Crypto Agility tab:** your migration policy (add/edit/delete rules, with a
  live "covers N keys" preview and a warning when a rule takes effect
  immediately), your migration schedule, the inventory with "your policy
  today" and the next change, keys no rule covers, and findings. No
  standards documents or drafts are quoted.
- **Playbooks:** new triggers `crypto_policy_refused` and
  `crypto_policy_changed`.
- **pqc:** the timeline is the customer's plan deadlines (`upcoming`,
  `due_within_year`, `overdue`, `met`); a plan without a deadline has none
  (it defaulted to a standards date). Classification is `vulnerable`,
  `strong` or `unknown`.
- **Breaking:** `/agility/posture` and `/agility/algorithms` return policy
  fields (`policy_status`, `policy_rule`, `target_algorithm`, `next_change`,
  `weak`, `uncovered_keys`, `min_algorithm_tier`) instead of `nist_status`,
  `schedule` and `sources`. X25519 is no longer tiered `deprecated` (it is a
  128-bit quantum-vulnerable scheme).

## [5.0.0-beta] — 2026-09-29

### Key visibility: you see the keys you can use (owner decision, option A)
- `GET /keys` lists, and every per-key read (`GET /keys/{id}`, versions,
  KCV, usage, approval, IV log, rotation metrics, health, consumers, access
  policy, HSM inspect, and the fingerprint check) returns, only keys the
  caller can see: keys they created, keys an active grant gives them
  (directly or through a group), keys their workload is bound to, or every
  key for tenant admins, service identities and holders of the new
  **`key.inventory.read`** permission (for auditors). The filter runs in the
  database query, so pages stay full and cursors reach every visible key.
- A hidden key answers exactly like a missing one (`404 not_found`), and the
  refusal is audited as `audit.key.access_refused` with `operation: read`,
  `reason: not_visible`. Another tenant's key is refused as a tenant
  mismatch before any lookup.
- Grants accept a new **`read`** operation (dashboard: "Read (view only)"):
  the key is visible, and no operation on it is allowed.
- Tenant-wide views over every key need `key.inventory.read`:
  `/inventory/keys|orphans|duplicates|dependencies`, `/rotation/analytics`
  and `/overdue`, `/enterprise/summary`, `/health/summary`,
  `/compromise/events` (GET), `/analytics/usage|hotspots|trends`,
  `/enterprise/dspm/findings|events`, `/enterprise/compliance/dashboard`,
  `/enterprise/cost/optimization`.

### Security: keycore's remaining writes required no permission
- 4.0.0-beta put keycore's access and key-management routes on the route
  kernel. The rest still took any verified token: reporting a compromise
  (which suspends the key), rotating any key through `POST
  /enterprise/orchestration/runs`, reading another key's KCV through `POST
  /enterprise/verification/fingerprint`, ceremonies, scheduling jobs,
  enterprise controls, inventory and analytics writes, attestation,
  integrity checks and the FIPS self-test.
- They now go through the kernel with `key.ceremony.read|write|share`,
  `key.compromise`, `key.rotate` (orchestration runs), `key.enterprise.read|
  write`, `key.scheduling.read|write`, `key.inventory.write`,
  `key.analytics.write`, `key.health.write`, `key.rotation.write`,
  `key.usage.meter`, `key.attest`, `key.integrity.verify` and
  `key.fips.selftest`; per-key ones also require the key to be visible.
  Each emits `audit.key.<action>`, refusals included. Left on the legacy
  mux, each guarded another way: crypto operations (per-key grants), the
  cluster master-key transfer (cluster-manager identity), and the token-only
  reads of the attestation public key, RNG health, tags and algorithm
  benchmarks, plus hash and random.

### Docs
- `docs/generated/` lists keycore's routes again: 4.0.0-beta registered 19
  of them through a helper the product-map generator doesn't read. Every
  kernel route is now a literal `r.Handle(...)` line.

### Breaking
- Non-admin users stop seeing keys they neither created nor hold a grant
  on. Give auditors `key.inventory.read`; share a key view-only with a
  `read` grant. Custom roles need the permissions above for the routes they
  use.

## [4.0.0-beta] — 2026-09-29

### Security: keycore management routes required no token and no permission
- **What was exposed.** Keycore's key-management and access-management
  routes had no permission check, and a request **without any token**
  reached them (`tenantcheck` skips when no token is present). Envoy routes
  `/svc/keycore/` from the public listener without validating JWTs. Without
  a token, or with any user's token (including `readonly`), a caller could
  make a key exportable (`PUT /keys/{id}/export-policy`), rewrite its grants
  (`PUT /keys/{id}/access-policy`), change access settings (`PUT
  /access/settings`), drop a key's approval requirement (`PUT
  /keys/{id}/approval`), rotate it, or reach the destroy handler. Key
  *use* (encrypt, decrypt, export of material) was not affected: it already
  required a verified token and a grant.
- **What to check on existing deployments.** Review the audit log for
  `audit.key.export_policy_updated`, `audit.key.access_policy_updated`,
  `audit.key.access_settings_updated`, `audit.key.approval_updated`,
  `audit.key.access_group_members_updated`, `audit.key.rotate`,
  `audit.key.destroy_scheduled` and `audit.key.destroyed` before this release, especially with `updated_by: "api"` or
  no actor. Reset any export policy, grant or approval you didn't make.
- **Fix.**
  - Keycore refuses every request without a verified token (`401`, audited
    as `audit.key.request_refused`, `reason: unauthenticated`), except the
    three reconciler routes that authenticate with the internal token.
  - The 16 access-management routes (`/keys/{id}/access-policy`,
    `/access/groups`, `/access/settings`, `/access/interface-*`) are on the
    `pkg/route` kernel with `key.access.read`, `key.access.manage` and
    `key.access.admin`. Changing a key's grants also needs the caller to
    have created the key or be a tenant admin (`403`, `reason:
    not_key_owner`).
  - The 22 key-management writes (create, import, form, bulk, update,
    rotate, activate, deactivate, disable, destroy, versions, export policy,
    approval, usage limit and reset, IV mode, tags) are on the kernel with
    `key.create`, `key.import`, `key.form`, `key.update`, `key.rotate`,
    `key.activate`, `key.deactivate`, `key.disable`, `key.destroy`,
    `key.export_policy_update`, `key.approval_update`,
    `key.usage_limit_update` and `key.tags.write`. Each emits
    `audit.key.<action>_requested`, refusals included. `POST /keys` now
    refuses a `tenant_id` in the body that differs from the token's.
- **Breaking.** Callers without a token get `401`. Users whose role lacks
  these permissions get `403`; built-in `admin` / `tenant-admin` hold `*`,
  and custom roles need the permissions above. `updated_by` / `created_by`
  in the access-policy and group bodies are rejected (`400`); the actor is
  the token's. The dashboard no longer sends them.

### Key access model (design, binding)
- [docs/SECURITY/KEY_ACCESS_MODEL.md](docs/SECURITY/KEY_ACCESS_MODEL.md):
  one decision for every interface (usage mask, lifecycle phase, grants and
  label policies, conditions, explicit deny), the full key-usage vocabulary
  with the enforcement point of each usage, KMIP properties (contact,
  application namespaces, custom attributes, alternative names, aliases,
  links, dates), separation of duties, and the phases. Still open from phase
  0: enforcing the declared usage, delegated usage with the user's token
  (dataprotect, payment, certs), step-up MFA from a verified claim instead
  of the `X-Step-Up-Auth` header, and key visibility.

## [3.2.0-beta] — 2026-09-29

### Crypto agility measured against NIST's transition schedule (CSWP 39-upd1)
NIST CSWP 39-upd1 (*Considerations for Achieving Crypto Agility*, updated
2026-06-29) §2.3 defers to IR 8547 and SP 800-131A Rev. 3 for the move off
quantum-vulnerable algorithms, and §5.2 asks for one machine-consumable crypto
policy. The platform now has one: `pkg/cryptocatalog`
([docs/SECURITY/ALGORITHM_TRANSITIONS.md](docs/SECURITY/ALGORITHM_TRANSITIONS.md)).

- **Added: `pkg/cryptocatalog`.** For each algorithm: SP 800-57 security
  strength, NIST post-quantum category, quantum vulnerability and the
  approval schedule (acceptable / deprecated / disallowed / legacy use), each
  fact citing its table. RSA-2048 and other 112-bit schemes are acceptable
  through 2030, deprecated from 2031-01-01 and disallowed from 2036-01-01;
  every quantum-vulnerable scheme is disallowed from 2036-01-01. SP 800-131A
  Rev. 3 and IR 8547 are initial public drafts, so their dates are shown as
  proposed. A name without a parameter set (`RSA`, `AES`, `Dilithium3`) is
  **not assessed**, never guessed.
- **Crypto Agility tab rebuilt on it.** Instead of a 0–100 score with
  invented weights, it shows live keys that are quantum-vulnerable,
  post-quantum, no longer allowed for new protection, or not assessed; the
  NIST deadlines that reach your keys (date, status, key count, algorithms,
  citation); per-algorithm strength, PQC category, status today and next
  change; cited findings; and the source documents with their draft status.
  Plan targets offered are ones keycore generates (ML-DSA-44 is gone).
  `web/dashboard/tests/crypto-agility.spec.ts` asserts the deadlines,
  citations, draft labels, the not-assessed row, and "unavailable" (no
  figures) when keycore fails.
- **Breaking: keycore `GET /agility/score` is replaced by
  `GET /agility/posture`** (`audit.key.agility_posture_read`).
  `GET /agility/algorithms` returns catalogue fields (`assessed`,
  `security_bits`, `pqc_category`, `quantum_vulnerable`, `post_quantum`,
  `nist_status`, `next_change`, `schedule`) instead of `is_legacy` and
  `is_quantum_safe`.
- **Fixed: four classifiers disagreed.** keycore called RSA-2048 and
  AES-128-CBC "legacy" and SLH-DSA not quantum-safe; pqc and discovery rated
  RSA-4096 and ECDSA "strong", did not recognise SLH-DSA as post-quantum,
  counted hybrids as pure PQC, and would have migrated an SLH-DSA signing key
  to ML-KEM-768. All now read the catalogue.
- **Fixed (enforcement): CBOM tiers were one level too high.** The policy
  floor (`spec.minAlgorithmTier`) let RSA-2048 (112-bit) meet
  `classical-128` and RSA-3072 meet `classical-192`, and refused HMAC,
  Ed25519 and ECDH under every floor. Tiers are now SP 800-57 strengths; new
  tiers `classical-112` and `not-assessed`. **Existing policies with a
  `classical-128` floor now deny RSA-2048**; set `classical-112` to allow it.
- **Fixed: a policy with an unknown floor enforced nothing.** It is now
  refused on create and update (`audit.policy.floor_refused`), and at
  evaluation an unknown floor is met by nothing.
- **Audit:** a floor denial now emits `audit.policy.crypto_floor_violation`
  (catalogued HIGH and documented for alerting, but never emitted before),
  and `audit.policy.violated` carries `result: refused` (was `success`),
  the `algorithm` and the denying `rules`.
- **pqc: invented deadlines removed.** The timeline showed "CNSA 2.0 hybrid by
  2028", an "EU crypto-agility baseline 2029-06-30" and EU 2031-12-31, with
  status from a readiness score. Milestones are now the catalogue's dated
  changes that reach scanned assets (affected count, citation). A plan
  defaults to `timeline_standard: nist-ir-8547-ipd`, deadline 2035-12-31;
  any other standard needs an explicit `deadline`. `qsl_score` is 100 when
  quantum-resistant and allowed today, else 0 (was hand-picked 35–100). Scan
  risk items skip assets that are already quantum-resistant and allowed. New
  phase `classical_replacement` (e.g. 3DES to AES-256).
- **discovery:** `strength_bits` is the security strength (RSA-2048 is 112),
  not the key or parameter size; ML-DSA certificates count as PQC-ready.
- **Open:** the tenant-wide `MinAlgorithmTier` posture control is stored but
  not enforced by keycore; the CARAF assessment (threats, asset profiles,
  X/Y/Z timeline and cost, decisions, roadmap) is the next slice.

## [3.1.0-beta] — 2026-09-28

### Removed: the keycore audit-chain anchor preview
- `GET|POST /svc/keycore/enterprise/audit-chain/anchors`, the
  `key_audit_chain_anchors` table (keycore migration 027 drops it; the 3.0.0
  migration of the same number that only dropped a column is replaced, and
  018 is removed), the `keycore.audit_chain_anchor` preview entry (backend
  and dashboard catalogue), the `audit.key.audit_chain_anchored` event and
  the "Blockchain-Backed Audit Chain" roadmap row. It stored a reference in
  a local chain of its own records and anchored nothing.
- The real mechanism is the audit service's ECDSA-P384 signed checkpoints
  (3.0.0-beta, [docs/SECURITY/AUDIT_INTEGRITY.md](docs/SECURITY/AUDIT_INTEGRITY.md)).
  Exporting checkpoints to an RFC 3161 timestamp authority or WORM storage
  is listed as open in RECOMMENDED_FEATURES.md.
- Recoverable from git history before this commit.

## [3.0.0-beta] — 2026-09-28

### Audit integrity: signed checkpoints replace Merkle trees (breaking)
- **Removed:** the audit service's hourly Merkle epochs and the certs
  service's certificate "transparency" tree, with their routes
  (`POST /audit/merkle/build`, `GET /audit/merkle/epochs[/{id}]`,
  `POST /audit/merkle/verify`, `GET /audit/events/{id}/proof`,
  `POST /certs/merkle/build`, `GET /certs/merkle/epochs[/{id}]`,
  `GET /certs/merkle/proof/{id}`, `POST /certs/merkle/verify`), tables (audit
  migration 013, certs migration 014; the creating migrations 002 and 006
  are deleted) and dashboard views (Audit Log → Merkle, Certificates →
  Certificate Transparency). They proved nothing: no root ever left the
  database, both verify endpoints checked a proof against the root the
  caller sent, and the tree duplicated odd leaves without domain separation.
- **Added: signed checkpoints.** Every 10 minutes each node signs the head of
  each tenant chain it writes (`{tenant, chain, sequence, chain_hash,
  signed_at}`) with ECDSA-P384, using a key generated in memory at start and
  never stored. The public key is the audit event
  `audit.audit.checkpoint_key_created`; each checkpoint is
  `audit.audit.checkpoint_signed`; failures are
  `audit.audit.checkpoint_refused`. All reach event streams (SIEM).
  `GET /audit/checkpoints` lists them re-verified, with the exact signed
  message, signature and public key for verification with openssl. The
  Audit Log's new **Checkpoints** tab shows them.
- **Verification uses them:** `GET /audit/chain/verify` checks every
  checkpoint (new break reasons `checkpoint_key_unknown`,
  `checkpoint_signature_invalid`, `checkpoint_head_mismatch`), and
  `GET /audit/targets/{id}/integrity` seals each event against its covering
  checkpoint (`seal`: `sealed`, `pending`, `key_unknown`,
  `signature_invalid`, `head_mismatch`; `checkpoint_id`,
  `checkpoint_sequence` replace `epoch_number` and `proof`). A rewrite by
  someone holding the HMAC key is now detected.
- **Fixed: the event HMAC key was random on every start.** No installer set
  `AUDIT_EVENT_SIGNING_KEY_B64`, so each restart made a new key and every
  earlier event became `hmac_key_unknown`. The key is now derived
  (HKDF-SHA256) from the audit master key (`pkg/mek`, keycore), for every
  MEK version, so it survives restarts and matches across a cluster
  (`audit.audit.event_hmac_key_installed`). Events written before the
  master key opens are stored unsigned. The environment variable is read
  only if set, to verify events earlier releases signed with it. HMACs of
  events from before this release that used a lost random key stay
  unverifiable.
- **Keycore anchor preview:** the `merkle_root` field and column are gone
  (keycore migration 027); the default `anchor_type` is `local`.
- **Also:** `pkg/clusterroute` and `pkg/clustercatalog` drop the removed
  routes and tables; the FIPS boundary lists ECDSA-P384.
- Docs: [docs/SECURITY/AUDIT_INTEGRITY.md](docs/SECURITY/AUDIT_INTEGRITY.md)
  (new), AUDIT_EVENTS_2026-09.md, API_REFERENCE.md, CERTIFICATES.md §9,
  GOVERNANCE_AND_COMPLIANCE.md §1.6, DECISIONS.md.

## [2.20.0-beta] — 2026-09-28

### Cluster routing: drop audit routes that no longer exist
- `pkg/clusterroute.Local` still listed `POST /alerts/test-rule` and
  `POST /alerts/channels/test` for `kms-audit`. Both were removed with
  audit's own alert rules (2.14.0-beta) and alert store (2.16.0-beta), so
  `TestLocalRoutesExist` failed and `make test-fips-modes` stopped there.
  No routing behaviour changes: the routes are not served.

## [2.19.0-beta] — 2026-09-28

### The KMS no longer tracks vulnerabilities (breaking)
CVE tracking is the job of a vulnerability-management product, not a key
manager. The SBOM stays and is the hand-off: export it (CycloneDX or SPDX)
to your vulnerability-management tool.
- **Removed from the sbom service:** `GET /svc/sbom/sbom/vulnerabilities`,
  `GET|POST /svc/sbom/sbom/advisories` and
  `DELETE /svc/sbom/sbom/advisories/{id}`, the OSV, Trivy and offline
  advisory matchers, and the `sbom.delete` permission they used. Migration
  003 drops `sbom_manual_advisories`. `audit.sbom.generated` no longer
  carries `vulnerabilities_assessed`/`vulnerability_cnt`, and SBOM diffs no
  longer carry `vulnerability_delta`. Audit subjects
  `audit.sbom.sbom_vulnerabilities_listed`, `sbom_advisories_listed`,
  `sbom_advisory_saved` and `sbom_advisory_deleted` are no longer emitted.
- **Smaller sbom image:** the bundled Trivy binary and its cache are gone,
  and `install.sh` / `deploy-local.sh` no longer pull `aquasec/trivy`.
- **Removed compliance's invented SBOM:** `GET /svc/compliance/compliance/sbom`,
  `/sbom/services`, `/sbom/services/{name}` and `/sbom/vulnerabilities`
  returned hard-coded versions ("dev", "1.x", "postgresql 16"), a fixed
  licence list, and a posture score below 60 presented as the vulnerability
  `CRYPTO-DEPRECATED-ALGO`. The real SBOM is the sbom service's.
- **Dashboard:** the SBOM / CBOM page loses the Vulnerabilities tab, the
  offline-advisory dialog, the "Critical CVEs" and "Clean Deps" tiles and the
  per-component CVE badges. Overview shows dependency categories instead.
- **Kept, because they are key management:** CBOM and PQC readiness,
  quantum-vulnerable algorithm classification, and keycore's
  `POST /compromise/advisories/ingest` (a compromise advisory marks the
  affected keys). The build pipeline still scans our own images and modules
  (`govulncheck`, `infra/security/cve-scan.sh`) as release evidence.
- Tests: `TestSBOMVulnerabilityRoutesRemoved`, `TestComplianceSBOMRoutesRemoved`.

## [2.18.0-beta] — 2026-09-28

### Formatting
- `gofmt` applied to `services/audit/hndl_detector.go`, `merkle.go` and
  `quarantine.go`. Whitespace only; no behaviour change.

## [2.17.0-beta] — 2026-09-28

### Audit and dashboard clean-up after the alert-store removal
- **Audit event catalogue:** dropped the per-event `Category` and
  `classifyCategory`. They only set the category of audit's own alerts,
  removed in 2.16.0-beta; the catalogue now holds severity only. Events keep
  their FIPS 140-3 `category_group`, which is unchanged.
- **Dashboard:** the audit config client read `wal_path`, which the audit
  service deliberately never returns (it masks the path). It now reads the
  real `wal_configured` flag. Nothing displayed the old field.

## [2.16.0-beta] — 2026-09-28

### Audit keeps no alert store; alerts live only in reporting (breaking)
- **Removed audit's own alerts.** For every event it ingested, the audit
  service also wrote a row to its `alerts` table, with dedup, HIGH→CRITICAL
  escalation and a severity-derived title. Reporting raises the real alerts
  from the same events, and the Alert Center, header bell, incidents and
  playbooks all read reporting. No screen has read audit's table since
  2.12.0-beta. Ingest now chains, signs, scores and stores the event only.
- **Removed routes:** `GET /svc/audit/alerts`, `GET /svc/audit/alerts/{id}`,
  `PUT /svc/audit/alerts/{id}/{acknowledge|resolve|suppress}`,
  `GET /svc/audit/alerts/stats`, `GET /svc/audit/alerts/stream` (SSE) and
  `GET /svc/audit/audit/stats`, which despite its name returned only those
  alert counts. Use `/svc/reporting/alerts`, `/alerts/stats`,
  `/alerts/stats/mttr|mttd` and `/alerts/feed`.
- **Removed settings:** `ALERT_DEDUP_WINDOW_SECONDS`,
  `ALERT_ESCALATION_THRESHOLD`, `ALERT_ESCALATION_WINDOW_MINUTES`, and the
  `dedup_window_seconds` / `escalation_*` fields of `GET /svc/audit/audit/config`.
- **Audit migration 012** drops the `alerts` table. Its rows were copies of
  events that remain in `audit_events`; the alerts people triage are in
  reporting and are untouched.
- **Dashboard:** the unused audit-alert client functions and types are gone,
  and the REST explorer's "Audit Statistics" entry, which documented event
  counts the route never returned, is removed.
- **Tests:** `TestAuditAlertStoreRemoved` asserts every former route answers
  404/405 and that ingest still stores the chained, risk-scored event. The
  audit Postgres tests pass with migration 012 on Postgres 17.

## [2.15.0-beta] — 2026-09-28

### Dashboard: dead live feed and its invented audit events removed
- **Removed the header's live WebSocket feed.** It opened `wss://<host>/alerts/stream`
  and `/audit/stream`, which Envoy routes to the dashboard's nginx rather than
  to any service, and audit serves those streams as Server-Sent Events, not
  WebSockets. The sockets always failed. On failure a `simulation` timer
  pushed an invented `audit.dashboard.heartbeat` event ("Live stream heartbeat
  from UI fallback channel") into the live audit list every 20 seconds.
  Nothing displayed the list, so no user saw it, but it was synthetic audit
  data. `lib/liveFeed.ts`, `store/live.ts` and the unused `alerts`/`audit`
  tab props are gone. The Alert Center and the header bell already read
  reporting over authenticated HTTPS.
- **Dashboard CSP:** `connect-src 'self' ws: wss:` becomes `connect-src 'self'`.
  The old value allowed WebSocket connections to any host, including
  plaintext `ws:`, and nothing in the dashboard uses a socket any more.
- **Audit event catalogue:** removed the services this product doesn't have
  (`mpc`, `tfe`, `dam`, `qrng`, `qkd`) from the severity catalogue and from
  `categoryGroupForService`, and dropped the unused `quantum` category.
  Nothing emits those events. An unknown event still gets the default
  severity and the system-administration category, as before.
- **Conformance `real-capability`** now also fails on a variable named
  `simulat*` or `synthetic*` outside tests. The policy dry-run's re-evaluation
  of real past decisions is renamed `replayed`, which is what it does.
- **Still open:** audit's own alert table and routes (`/svc/audit/alerts`,
  `/alerts/stats`, `/alerts/stream`) remain. No screen reads them since
  2.12.0-beta; they should be retired in favour of reporting's alerts.

## [2.14.0-beta] — 2026-09-28

### One alert-rule engine: audit's own rules removed
- **Removed `GET/POST /svc/audit/alerts/rules` and
  `PUT/DELETE /svc/audit/alerts/rules/{id}`**, the matcher behind them, and
  the `alert_rules` table (audit migration 011). They were a second rule
  system: a substring matcher that recognised three phrases
  (`event.action == '…'`, `event.tags contains '…'`,
  `event.source_ip.country …`) and only changed the severity and title of
  audit's own alerts, which no screen shows since 2.12.0-beta. The
  dashboard never used it.
- **Alert rules live only in reporting** (`/svc/reporting/alerts/rules`):
  a real expression parser, thresholds, and the test/replay route from
  2.13.0-beta. The Alert Center reads them.
- **Breaking:** rules created through the audit API are deleted with the
  table. Recreate any you need as reporting rules; test them first with
  **Test rule**. A country condition has no reporting equivalent yet.

## [2.13.0-beta] — 2026-09-28

### Test an alert rule before saving it
- **New `POST /svc/reporting/alerts/rules/test`** and a **Test rule** button
  in System Administration → Alert Rules. It checks a rule without saving
  it, using the same matcher live alerting uses:
  - whether the rule is valid, with the reason if not;
  - for a supplied event, whether it matches and would fire now;
  - a replay over the tenant's real audit events from the last 1 hour to
    7 days: how many matched, how many times it would have fired, and
    sample events.
  If audit events can't be read, the result says the replay wasn't
  assessed; it never shows zero. Audited as `audit.reporting.rule_tested`.
- **Removed `POST /svc/audit/alerts/test-rule`.** It answered `dry-run-ok`
  without evaluating anything. Rules live in reporting, which the dashboard
  uses.
- **Docs:** `docs/GOVERNANCE_AND_COMPLIANCE.md` §4 described CEL
  expressions with `&&`, `count()`, `hour()` and `is_new_source_ip()`, 14
  built-in rule templates, alert snooze, and an `/svc/alerting` service.
  None of them exist. The section now documents the real rule language
  (`AND`, `OR`, `==`, `!=`, `contains`, `startsWith`, `matches` on seven
  fields), threshold rules, the test route and the real alert endpoints.
  The editor's example patterns (`auth.login_failed`) could never match,
  because real actions are `audit.auth.login_failed`; they are corrected.
- **Still open:** audit keeps a second, older rule system
  (`/svc/audit/alerts/rules`, a substring matcher that only sets audit
  alerts' severity and title). The dashboard doesn't use it. It should be
  folded into reporting's rules or removed.

## [2.12.0-beta] — 2026-09-28

### Dashboard: one home per view; Compliance shows only what it assesses
- **Overview → Analytics is the only place for charts.** It now has four
  views: Key inventory, Operations, **Audit activity** and **Alerts**. The
  Audit Log's Analytics sub-tab and the alert charts in Compliance → Reporting
  (severity, daily trend, MTTR, resolution status, top sources) moved there.
  MTTD, which used to appear only inside Compliance, sits next to MTTR.
- **Audit Log is the record and its integrity:** Events · Forensics · Merkle.
  Its Alerts sub-tab is gone. It showed the audit service's own alert table,
  a second list next to the Alert Center (reporting), which is where the
  header bell, playbooks and incidents already point. Alerts are triaged only
  in the Alert Center.
- **Audit activity counts what it read.** The old Audit Log analytics charted
  the current page of 100 events and called it "Total Events". The new view
  pages through up to 2,000 events in the chosen window (24h / 7d / 30d),
  shows "Events analysed", and says so when the window holds more.
- **Compliance → Assessment shows only compliance.** Removed:
  - the MTTD/MTTR charts, which measure alert response (now in Analytics);
  - the Autokey, Workload Identity, SCIM, Certificate Renewal, REST Client,
    Key Access and Artifact Signing "Controls" cards. They repeated Posture's
    cards, and when their API call failed they showed "Disabled" instead of
    the error;
  - the **Threshold Signing / FROST** card (also removed from Posture). There
    is no MPC service, so it always rendered zeros and "No active keys".
- **Compliance → Crypto Inventory removed.** It scored keys and
  certificates with a formula invented in the browser, and a failed fetch
  gave an empty inventory scored 100/100. The cryptographic inventory is
  SBOM / CBOM. Its in-app guide ("KeyInsight") is removed too.
- **PQC Migration Gaps** says "unavailable" with the error when the PQC
  inventory can't be read, instead of 0/100, zero counts and "No gaps". The
  tenant policy reads "not set" rather than the invented `balanced hybrid`.
- **Compliance → Reports** (renamed from Reporting) keeps report generation,
  schedules and downloads.
- **Audit Log badges and footer:** removed "250+ event types". That number
  is a service × verb product in `services/audit/event_catalog.go` that
  includes services this product doesn't have (mpc, tfe, dam, qrng, qkd). The
  footer no longer lists MPC, QRNG, TFE or DAM as audited features.
- **Test:** `tests/smoke-tabs.spec.ts` asserts the Audit Log has only Events,
  Forensics and Merkle, that Analytics → Audit activity and Alerts render,
  and that Compliance has no Crypto Inventory, MTTD or FROST section.

## [2.11.0-beta] — 2026-09-28

### PagerDuty removed completely
- **Audit alerts record only where they really go.** Every audit alert
  used to list email, SMS, PagerDuty, SIEM and webhook as "queued" in
  `dispatched_channels` / `dispatch_status`, and nothing ever sent to any of
  them. Alerts now record `dashboard: recorded`, the one place the audit
  service puts them. To notify people or a SIEM, use Playbooks (connections,
  `send_siem_alert`) or Event streaming.
- **Removed `GET/PUT /svc/audit/alerts/channels` and
  `POST /svc/audit/alerts/channels/test`.** They were a process-wide
  in-memory map, the same for every tenant and lost on restart, that
  nothing read. The PagerDuty "configuration" lived there, and the test
  route answered `test-sent` without sending anything. Reporting's
  `/alerts/channels` (the one the dashboard uses) is unchanged.
- **Reporting migration 004** deletes retired notification-channel rows
  (PagerDuty, email, Slack, Teams, webhook, SIEM). They were already hidden
  and never delivered, but their config could hold a PagerDuty routing key
  or a webhook URL in plaintext. Only `screen` (the dashboard) remains. If
  you ever stored a PagerDuty routing key or Slack URL in a reporting
  channel, revoke it at the provider.
- **Dashboard:** the PagerDuty filters in the Alert Center and System
  Administration are gone, and the alert-rule channel picker offers only
  what reporting delivers (`screen`) instead of email, Slack, Teams and
  webhook options that were never sent.
- **Docs:** PagerDuty examples removed from the governance and certificate
  guides, and the alert-rule examples no longer claim Slack, email or
  PagerDuty delivery from reporting.
- **New conformance rule `no-pagerduty`:** `make conformance` fails if
  PagerDuty appears anywhere in Go, TypeScript or JavaScript code or tests.

## [2.10.0-beta] — 2026-09-28

### Webhooks and SIEM are part of Playbooks; one store of outbound credentials
- **No separate "Webhooks & SIEM" tab.** Playbooks now has an **Event
  streaming** view beside Connections. A stream names the audit actions it
  carries and a **connection**; the connection holds the endpoint and
  credentials, sealed under the compliance master key. Playbook actions,
  event streams and governance approval notices all use the same
  connections, so each credential is entered, rotated and flagged for
  exposure in one place (docs/SECURITY/CONNECTIONS.md).
- **SIEM connection types**, delivered by a rewritten `pkg/siem`: Splunk
  HTTP Event Collector, Datadog Logs, Elasticsearch (Bulk API; a rejected
  document is a failed delivery, not a success), Microsoft Sentinel (Azure
  Monitor Logs Ingestion API with an Entra app; the HTTP Data Collector API
  was retired by Microsoft on 14 September 2026), and syslog over TLS 1.3
  carrying CEF for QRadar, ArcSight and other collectors. `pkg/siem` existed
  before but nothing used it, and it dialled plain UDP/TCP syslog, used a
  client with no address guard and signed Sentinel requests with
  `crypto/hmac` directly. It is now wired into event streams and playbooks,
  and every call is TLS through `pkg/ssrfguard`.
- **New playbook action `send_siem_alert`**: raises one alert in any SIEM
  connection with the playbook, run, authorizing person and triggering
  event, at a chosen severity.
- **Webhook connections can sign**: an optional `signing_secret` (at least
  16 characters) signs each body as `X-KMS-Signature: sha256=<HMAC>`, for
  playbook calls and event streams alike.
- **API changes (breaking):**
  - `POST/PATCH /svc/audit/webhooks` take `connection_id`. `url`, `format`,
    `secret` and `headers` are refused.
  - `GET/PUT /governance/settings` carry `slack_connection_id` /
    `teams_connection_id`. `slack_webhook_url` / `teams_webhook_url` are no
    longer returned or accepted: they were returned in plaintext.
  - `POST /governance/settings/webhook/test` no longer takes a URL; it tests
    the saved connection.
- **New service routes:** `POST /compliance/connections/{id}/resolve` and
  `POST /compliance/connections/import`, callable only by the `kms-audit` and
  `kms-governance` identities, audited as `connection_resolved` /
  `connection_imported`.
- **Deleting a connection** now also checks event streams and governance
  approval notices, and is refused when either service can't answer
  (`connection_usage_unverified`).
- **Migration:** the primary moves each existing audit stream's own URL and
  credentials into a connection (`audit.audit.webhook_migrated`). Open
  exposure-register entries move with them. A stream whose headers don't
  map keeps working and is reported once (`webhook_migration_refused`).
  Governance's plaintext Slack/Teams URLs become connections recorded as
  **exposed** (`audit.governance.notify_connections_migrated`). **Rotate
  those Slack/Teams webhooks**, then replace the URL on the connection.
- **Also fixed:** a failed delivery could put the full Slack/Teams URL (a
  credential) into the delivery log and audit event through Go's
  `*url.Error`; errors now name the host only. Governance accepted `http://`
  notification URLs; notices are `https` only.
- **Docs:** `docs/GOVERNANCE_AND_COMPLIANCE.md` §1.7 described CSV, JSONL,
  CEF and LEEF exports and webhook options (`min_risk_score`,
  `retry_attempts`, `X-Vecta-Signature`) that never existed. It now
  describes event streams as built.
- **Still open:** a SIEM on a private network can't be a destination (the
  outbound guard refuses private addresses); streams send one event per
  request; Sentinel is public Azure cloud only.
- **Left in place:** `WebhooksTab.tsx` now holds the Event streaming panel
  (it is no longer a tab), and the old `pkg/siem` files were rewritten in
  place, not renamed.

## [2.9.0-beta] — 2026-09-28

### The generated route and product map can't drift any more
- `make conformance` (and CI's conformance step) now fails when
  `docs/generated/` doesn't match the source. The generator gained
  `--check`: it regenerates into a temporary directory, compares file by
  file with the generation timestamp masked, and names the stale files and
  the command to fix them (`python3 scripts/generate_product_map.py`).
  It adds about 2.5 s.
- The generator now reads only files a commit would carry (tracked, or
  untracked and not ignored), so local scratch and build output can't make
  a local run differ from CI's. Output is unchanged.

## [2.8.0-beta] — 2026-09-28

### Dashboard: undefined-name check for untyped files; three silent UI bugs fixed; route index regenerated
- **New check: undefined names in `@ts-nocheck` files.** 36 dashboard
  files skip type checking, and that hides the one error that fails at
  runtime: a name that doesn't exist. `scripts/check-nocheck-names.mjs`
  (part of `npm run typecheck`, so it runs in CI and in every build) reads
  those files without the marker and fails only on undefined names,
  shorthand properties with no value, use before declaration, and missing
  imports or exports. It ignores their ~1,300 loose-typing errors. Run
  against earlier versions, it catches both the 2.7.0 Certificates crash
  and the payment policy bug below.
- **Dead, broken payment policy panel removed.** `PaymentCryptoPolicy` in
  `TokenizeTab.tsx` (442 lines) called `getPaymentPolicy` and
  `updatePaymentPolicy` without importing them (import dropped in
  `dbbfa63ad`). Nothing rendered it: the Payment Policy subtab uses
  `PaymentPolicyTab`, which works. Removed rather than repaired.
- **Certificates → Enrollment Protocols showed no engine.** The certs
  service sends each protocol's implementation (engine and SDKs), but the
  dashboard dropped it before rendering, so each card's "Engine: …" line
  never appeared. It is shown now.
- **Invalid CSS on certificate cards.** Two card backgrounds were written as
  `"${C.greenTint3}"` in plain quotes, so the browser received the literal
  text and discarded the gradient. Fixed, along with a reference to a theme
  colour that doesn't exist (`C.surfaceHi`).
- **Dashboard unit tests pass again.** `tests/unit/mekExposure.test.ts`
  (CI `npm run test:unit`) pinned the exposure register to four services
  and had failed since `audit` was added. It now reads the service list
  from `pkg/mek/catalog.go` and requires the dashboard to query every one.
  It fails if a service that records exposures is missing from
  `EXPOSURE_SERVICES`, as compliance was until 2.6.0.
- **Audit log search** no longer matches a `description` field the audit
  service never sends.
- **Generated route and product map refreshed** (`docs/generated/`, via
  `scripts/generate_product_map.py`). The map was last regenerated at
  2.2.0-beta, so it now includes 2.3–2.7: the playbook, connection and
  run routes, the delegated auth and governance notify routes, and each
  service's `/mek/exposure` routes including compliance. The generator is
  deterministic (only timestamps change between runs).

## [2.7.0-beta] — 2026-09-28

### Playbook cooldown survives failover; Certificates tab crash fixed; browser smoke test really runs
- **The 60-second cooldown is stored.** A playbook fires at most once per
  cooldown. The last firing was kept in memory, so right after a restart or
  failover a playbook could fire again inside the window. It is now stored
  on the playbook (`last_fired_ms`, migration 008) and claimed with one
  conditional `UPDATE`, so a new primary sees it and two listeners can't
  both claim the same window. If the claim can't be checked, the playbook
  doesn't fire and the refusal is audited (`playbook_triggered`, `reason:
  cooldown_unavailable`).
- **Certificates / PKI tab crash fixed.** The tab threw `ReferenceError:
  pqc is not defined` on every render and showed "This tab failed to
  render". This has been broken since 1.21.0-beta (commit `b3c87986f`,
  which removed the post-quantum certificate count but not its last use).
- **The dashboard smoke test opens tabs again.** `tests/smoke-tabs.spec.ts`
  (CI `npm run test:smoke`) put its session in `localStorage` after the
  dashboard had moved sessions to `sessionStorage`. The test stayed on the
  sign-in page and skipped every tab, so it passed while testing nothing.
  It now signs in, clicks each sidebar entry (Playbooks added), and fails
  if it opens fewer than 10 tabs or reaches the sign-in page.
- **Browser test for the 2.6.0 exposure flags.**
  `tests/playbook-exposure.spec.ts` renders the Playbooks → Connections
  view and the Administration exposure register in Chromium. It checks that
  the ROTATE badge and banner appear only for an open exposure, and that an
  unreachable register shows "not assessed", never a clean list.

## [2.6.0-beta] — 2026-09-28

### Playbooks: tampering trigger, failover-safe thresholds, a policy that can't be switched off, credentials to rotate
Closes the four follow-ups left open by 2.5.0-beta.

- **Audit tampering starts a playbook.** New trigger `audit_chain_broken`.
  The audit service used to write `audit.audit.chain_broken` straight into
  its own chain, so nothing else on the `AUDIT` stream ever saw it. It now
  publishes the event to the stream, where ingest records it once and
  playbooks (and any other subscriber) see it. If the stream refuses the
  publish, the event is still recorded directly. The event also carries
  `break_count` and `scope` (`chain` or `target`).
- **Threshold counts survive a failover.** Threshold counts ("5 failed
  logins for one account in 5 minutes") were kept in memory and restarted
  from zero on a restart or failover. They are now stored in a new
  replicated table, `compliance_playbook_threshold_hits` (migration 007),
  written only by the primary's trigger listener, so a new primary
  continues the count. Counts reset when a playbook fires, is edited or is
  deleted. If a count can't be stored the playbook doesn't fire, and the
  refusal is audited (`playbook_triggered`, `reason:
  threshold_unavailable`).
- **The built-in "Playbook actions" approval policy can't be switched
  off.** Disabling it, or removing `playbook.*` from its actions, is refused
  with `409 builtin_policy` and audited (`approval_refused`, `reason:
  builtin_policy_required`). Before, disabling it silently stopped every
  playbook step that needs approval. Administrators can still change its
  approvers and quorum. A policy disabled under 2.5.0-beta is switched back
  on at the next approval request, audited as
  `audit.governance.builtin_policy_restored`.
- **Credentials that need rotating are shown.** Playbook webhook URLs and
  tokens stored in plaintext before 2.5.0-beta are still readable in older
  database copies and backups. They were already tracked in the exposure
  register, but the dashboard didn't show them. The Connections view now
  flags each one ROTATE with a banner explaining what to do, and the
  Administration exposure register now includes "Playbook connections" and
  shows how each item was exposed. A flag clears when every field of the
  connection is replaced (or the connection is deleted).

## [2.5.0-beta] — 2026-09-28

### Playbooks become the response layer: incidents, approvals, delegation, sealed connections
Playbooks can now respond to any audited event and to every incident, act on
what triggered them, and pause for dual control. They keep acting only on
the current authority of a named person.

**Triggers**
- **Alerts and incidents.** `alert_raised` (every Alert Center alert, with
  its severity, source actor and target) and `incident_opened`: reporting
  now emits `audit.reporting.incident_opened` when an incident opens.
- **More built-in triggers:** `key_exported`, `key_hsm_refused`,
  `fips_mode_changed`, `backup_restored`, `cluster_member_joined`.
- **Custom triggers:** any audit subject you name (exact or `audit.cert.*`),
  labelled as firing only if a service emits it.
- **Filters** on event fields (`severity`, `result`, `actor_id`,
  `target_id`, `details.<key>`, ...) with `eq`, `neq`, `in`, `not_in`,
  `contains`, `prefix`.
- **Real thresholds:** N matching events within a window, counted per
  `group_by` value (for example five failed logins for one account in five
  minutes). Counted in memory on the cluster primary; a failover starts
  them again.

**Actions**
- **Act on what fired:** parameters take `{{event.target_id}}`,
  `{{event.details.<key>}}`, `{{run.id}}` and more. A value that resolves
  empty fails the step rather than calling with nothing. Per-step
  conditions skip a step when the event doesn't match.
- **New actions:** `send_email` (to the tenant's own users or a role,
  through Governance's SMTP), `acknowledge_alert`, `resolve_alert`,
  `set_incident_status`, `assign_incident`, `generate_report`,
  `run_posture_scan`, `trigger_rotation_policy`, and, back and real,
  `disable_user`, `revoke_api_key` and a new `revoke_client`. These three are
  performed by auth on the authorizing person's behalf: auth re-checks the
  person's permission, and never touches the person themself, the last full
  administrator or a platform service identity.
- **Approval gate:** `deactivate_key`, `revoke_certificate` and the
  delegated actions always pause for a governance approval, and any step can
  opt in. A built-in "Playbook actions" policy lets any tenant administrator
  except the person the playbook acts for approve. A run resumes only after
  compliance reads the request back from Governance: it must be approved,
  name this action and requester, and carry the hash of the action as the
  playbook now defines it. Editing the step while it waits voids the
  approval.

**Authority**
- **Re-checked on every unattended run.** Before an automatic run (and a
  resume) compliance asks auth whether the authorizing user is still active
  and still holds the permissions. If not, or if auth can't answer, the run
  doesn't start (`authority_revoked` / `authority_unverified`, audited).
  This closes the gap 2.4.0-beta left open.
- **A person authorizes.** An API client can no longer enable a playbook
  (`user_required`): only a user's grants can be re-checked.

**Credentials**
- **Connections:** Slack, Teams, webhook, Jira and ServiceNow endpoints and
  tokens are defined once as connections, sealed under the compliance master
  key from keycore (`pkg/mek`). Only the name, type and endpoint host are
  stored in plaintext; values are never returned. Actions name a
  `connection_id`. A real test call is available, and a connection in use
  can't be deleted.
- **Existing inline credentials** are moved into connections at startup by
  the primary, audited, and recorded in the exposure register. **Rotate
  those webhook URLs and tokens:** earlier database copies hold them in
  plaintext.

**Runs**
- **Run records** keep the event they answered, one result per step, the
  incident they belong to, and the approval they're waiting on.
- **Dry run** resolves every step against an event and reads each target
  (key, certificate, alert, incident, connection) from its owning service
  without changing anything.
- **Cancel** stops a running run, or ends a paused one and withdraws its
  approval request.
- **Retry** re-runs from the first step that didn't complete, on the
  caller's authority.
- **No chains:** events caused by a playbook (actor `kms-compliance`, a run
  correlation ID, or an alert raised from such an event) don't fire
  playbooks.

**Dashboard.** The Playbooks tab has Overview (with runs awaiting approval),
Playbooks (dry run, run with an event), Runs (filter by status or incident,
per-step results, cancel and retry), Incidents (every Alert Center incident
with the playbook runs that answered it; incidents weren't shown anywhere
before) and Connections. The editor adds a filter builder, threshold and
grouping, a connection picker, per-step conditions and approval, and
template help.

**Fixes found on the way**
- Reporting's `PUT /incidents/{id}/status` and `/assign` answered 200 for
  incidents that don't exist, and accepted any status. They now return 404
  and accept only `open`, `investigating`, `resolved` and `closed`.
- `alert_created` now names the alert as its target, with severity,
  incident and source fields.
- Migration `006_playbook_response.sql` adds the run columns, connections
  and the compliance master-key tables. `TestPlaybookStorePostgres` runs
  004-006 twice on real Postgres.

**Still open:** a paused run waits up to Governance's approval expiry. An
`audit.audit.chain_broken` trigger isn't possible yet: the audit service
writes that event to its own chain and doesn't publish it on the stream
(closed in 2.6.0-beta).

## [2.4.0-beta] — 2026-09-28

### Playbooks: real triggers, real actions, and no borrowed authority
Security fix. Playbook actions run as the compliance service identity, which
passes every tenant and permission check downstream. Until now:
- **Any signed-in user could use that identity.** The playbook API checked
  only that a JWT was valid (no permission), and took the tenant from the
  request body. A read-only user could create a playbook in another tenant
  that rotated or disabled its keys when a canary tripped, or run one in their
  own tenant with permissions they didn't hold.
- **The routes are now on the `pkg/route` kernel.** The tenant comes from the
  token. `compliance.playbook.read`, `.write`, `.delete` and `.run` are
  required. Saving an enabled playbook, or running one, also needs every
  permission its actions use (`key.rotate`, `key.disable`, `key.deactivate`,
  `key.activate`, `cert.renew`, `cert.revoke`, `compliance.assessment.run`,
  `compliance.posture.refresh`). Refusals are audited with
  `action_permission_denied` and the missing permissions.
- **Automatic runs act on a named person's authority.** `authorized_by`
  records who last saved the playbook holding those permissions; runs,
  records and audit events carry it. **Every playbook saved before 2.4.0-beta
  is inert until someone with the permissions saves it again** (the
  dashboard marks it "Not authorized"; the refusal is audited).
- **`send_webhook` could reach platform services with the compliance mTLS
  certificate.** Outbound actions now need a public `https` URL, refuse
  platform hosts and private or metadata addresses (`url_blocked`), and go
  through `pkg/ssrfguard` (checked at dial time, no redirects, no client
  certificate). Errors name the host, never the URL.
- **Secrets** (Slack/Teams webhook URLs, Jira and ServiceNow tokens, webhook
  headers) are no longer returned by the API or put in audit events.

Honesty fixes (rule 8):
- **Triggers are real.** 38 of the 40 triggers listened for audit subjects no
  service emits (`audit.keycore.key_rotated`, `audit.infra.*`, `audit.ops.*`,
  ...). Only a canary trip could fire a playbook, plus `auth_failure_spike`,
  which fired on every single failed login because its threshold was never
  read. The catalogue now holds
  18 triggers on subjects services really emit, including key rotate, create
  and destroy, key compromise, threat signals and findings, certificate
  revocation and renewal misses, login failures and lockouts, and watchdog
  service incidents (which fire the platform tenant's playbooks).
  `TestTriggerSubjectsAreEmitted` fails if an emitter goes away.
- **Actions call endpoints that exist.** Suspend, revoke and enable key called
  `PUT /keys/{id}/status` and the certificate actions `/certificates/...`,
  none of which exist. They are now `disable_key`, `deactivate_key`,
  `activate_key`, `renew_certificate` and `revoke_certificate` on keycore and
  certs' real routes; saved rows with the old key-action names are read with
  the new ones.
- **Removed:** `send_pagerduty` (owner: no one uses it); `destroy_key` (keycore
  requires a person to acknowledge the irreversible pre-destroy checks, so it
  always failed, and a playbook must not acknowledge them for someone);
  `disable_user` and `revoke_api_key` (auth refuses service identities, so
  they always failed; they return with delegated execution).
- **An approval is not a success.** When keycore opens a governance approval
  instead of acting, the action is recorded as `pending_approval` and the run
  as `pending_approval`, not "OK".
- **The trigger threshold is gone.** The form offered it, and it was stored,
  but never evaluated; the API now rejects it. **Category** was shown but
  never stored; it is now.
- **One execution path.** Manual runs had their own copy of the executor and
  emitted no audit event at all. Every run, manual or triggered, now emits
  `playbook_action_executed` per action and `playbook_run_completed`; every
  trigger match emits `playbook_triggered` (success, or refused as
  `playbook_not_authorized`, `cooldown` or `stale_event`). Every route emits
  its own event (list in `docs/API_REFERENCE.md`).
- **Cluster-safe.** Triggered runs happen only on the primary, which sees
  every node's events through the audit relay. Events more than 15 minutes old
  (a consumer catching up) no longer fire playbooks.
- **Dashboard.** The Playbooks tab renders the catalogue from
  `GET /compliance/playbooks/catalog` (nothing hardcoded), shows who
  authorized each playbook and on whose authority each run acted, the
  permissions a playbook needs, the subjects each trigger fires on, and
  per-action parameter help. Parameters are one `key=value` per line, since
  values may contain commas. Load failures show the error. The overview
  stopped failing for tenants with no playbooks (a `SUM` over zero rows
  returned NULL).
- Migration `005_playbook_authorization.sql` (schema only) adds `category`,
  `authorized_by` and run `actor`; `TestPlaybookStorePostgres` runs it (twice)
  on real Postgres with a pre-2.4 row.

## [2.3.0-beta] — 2026-09-28

### Operations metrics: cluster view on every node, values for batch calls
- **A member now shows the cluster.** `GET /svc/audit/ops-metrics/*` on a
  member is forwarded to the primary (`clusterroute.ForwardReads`) through
  the existing member-to-primary forwarding path, which is authenticated and
  audited. Every node shows the same cluster-wide figures. If the primary is
  unreachable the view says "unavailable"; it never falls back to partial
  local figures.
- **Batch calls count their values.** An operation still counts once per
  request, but the values it processed are summed from the event's `count`
  (tokenize, detokenize; 1 for everything else) into `value_count`
  (migration 009). The overview returns `total_values`, and the Total Ops
  card shows it.

## [2.2.0-beta] — 2026-09-28

### Operations metrics cover the cluster and every service that does crypto
Closes the three items 2.1.0-beta left open.

- **Cluster-wide on the primary.** Each row names the node that ran the
  operations (migration 008). A member counts its own. The primary also
  counts every member's metered operation when its audit relay passes the
  replicated event, in the same transaction as the relay cursor, so each is
  counted exactly once. The overview returns `scope` (`cluster` on the
  primary, `node` on a member, `standalone`) and `by_node`. Analytics >
  Operations shows the scope and the per-node split.
- **Not just keycore.** Any audit event carrying `metered_op`
  (`pkg/audit.MeteredOp`, set with `pkg/audit.Metered`) with its
  `duration_ms` and `result` is counted:
  - **dataprotect:** tokenize, detokenize, FPE, field, envelope and
    searchable encrypt/decrypt.
  - **payment:** PIN translate, PVV, PIN offset, CVV, MAC, LAU, and TR-31
    create/parse/translate/validate.
  - **certs:** certificate issuance and OCSP response signing with a local
    CA key.
  - **keycore:** attested release.
  - **Kernel routes:** any route that declares `route.Spec.Metered`, so new
    routes get metering by construction.

  Operations that only call keycore (ISO 20022, signing, hyok, ekm, kmip,
  HSM-held CAs, generate-data-key, service-derive) are counted once, by
  keycore.
- **New audit events for operations that had none.** payment:
  `tr31_validated`, `mac_computed`, `mac_verified`, `lau_generated`,
  `lau_verified`, `iso20022_verified`, `iso20022_decrypted`. Every payment
  operation now also emits `audit.payment.<op>_refused` or `<op>_failed`.
  dataprotect: `audit.dataprotect.<op>_refused` / `<op>_failed` (an FPE
  algorithm refusal stays `fpe_refused`). certs: `audit.cert.cert_issue_failed`
  and `audit.cert.ocsp_sign_failed`. Before this, a refused or failed
  operation in these services left no specific event.
- **Refusals are recorded as refusals.** payment, dataprotect and certs
  publish the event's `result` at top level. The audit record used to say
  `success` for every event these services sent.
- **When measurement started is shown.** The overview returns
  `recorded_since`, and the dashboard says "Measured since …; earlier
  operations were not recorded". History is not backfilled: pre-2.1.0 events
  recorded a wrap as an encrypt and a MAC as a sign, had no duration, and
  left out refusals, so any backfill would mislabel it (docs/DECISIONS.md).
- The route kernel records `duration_ms` to the microsecond.

## [2.1.0-beta] — 2026-09-28

### Operations metrics are real, and live in Analytics
- **The Operations Metrics tab was always empty.** It read
  `ops_metrics_hourly`, which only `POST /ops-metrics/record` wrote, and
  nothing ever called it. The tab is now the **Operations** section of
  **Analytics** (next to Key inventory). A saved `ops_metrics` tab or
  `#ops_metrics` link opens Analytics.
- **Built from audit events of operations that ran.** Keycore now emits
  `audit.key.<op>` for every key operation (`encrypt`, `decrypt`, `wrap`,
  `unwrap`, `sign`, `verify`, `mac`, `derive`, `kem_encapsulate`,
  `kem_decapsulate`) with its measured `duration_ms` and `result`:
  `success`, `refused` (with `reason`: `ops_limit_reached`, `policy_denied`,
  `fips_mode_violation`, key-access and HSM reasons), `failure` (with
  `error_message`) or `pending_approval`. The audit service adds each
  persisted event to the hour it happened in. Refusals and failures count as
  errors, and pending approvals are not counted.
- **Audit fixes on the way.** Refused and failed key operations used to emit no
  operation event. A wrap was audited as `audit.key.encrypt`, an unwrap as
  `audit.key.decrypt` and a MAC as `audit.key.sign`. Each is now named after
  what ran.
- **Latency percentiles are measured.** p90 and p99 used to be printed as
  2× and 4× the average. Each sample is now counted in a latency histogram
  (bounds 0.1 ms to 1000 ms, migration 007), and p50/p90/p99 are the bucket
  bound each falls in, shown as "≤ X ms", or "> 1000ms" for the overflow
  bucket. Latency is summed in microseconds, because whole milliseconds
  rounded every sub-millisecond operation down to 0.
- **The window selector works.** Overview, latency, by-service and errors all
  take `?window=1h|6h|24h|7d|30d`. Before, only errors did, and the dashboard
  never sent it. A failed load shows "Operations metrics unavailable:
  <error>" instead of zeros.
- **Removed `POST /svc/audit/ops-metrics/record`.** Any authenticated caller
  could write arbitrary numbers into the metrics.
- Analytics > Key inventory shows the error when its call fails, and it no
  longer fetches `/rotation/analytics`, which it ignored.
- Metrics are per node (`ops_metrics_hourly` is node-local): each node counts
  the operations its own keycore ran.

## [2.0.0-beta] — 2026-09-28

### Breaking: the Threat & Exposure tab is removed; its real parts move to Keys, Posture and Reporting
The tab combined three things. Only threat detection did real work, and it
ran only while someone had the tab open. The rest moved or went away
(docs/DECISIONS.md, 2.0.0-beta). The removed code is in the commit that
carries this entry.

- **Threat detection runs on a schedule and reaches someone.** Keycore's
  `ThreatSweeper` evaluates `new_actor`, `volume_spike` and
  `dormant_key_activity` every minute, on every node, over that node's
  key usage trail (`key_usage_events` and `threat_signals` are node-local).
  Before, the rules ran only on `GET /threat/signals`. Each new signal emits
  `audit.keycore.threat_signal_raised` (it was `audit.threat.signal_raised`).
  - **Posture** turns each signal into one finding (`threat_<type>`,
    corrective engine, evidence names the signal and audit event), audited as
    `audit.posture.threat_finding_raised`. Open threat findings add to the
    corrective score. Resolving one is final: the event still in the hot
    window never reopens it.
  - **Reporting** raises critical and high signals as alerts. Reporting now
    syncs alerts from audit every minute on the primary, for every tenant it
    knows and root, so the header's unread count moves without anyone
    opening the Alert Center. Before, alerts were created only when the
    Alert Center was listed. A cluster member no longer creates alerts when
    it serves that list (it wrote a replicated table).
- **Canary keys are in Keys** (**Keys → Canary Key**), on the route kernel
  (`key.canary.read` / `key.canary.write`, events `audit.key.canary_*`
  including refusals). Before, create and deactivate were not audited.
  - A new canary's ID is minted like a real key ID (`key_…`). It was
    `canary_…`, which told the prober it was a decoy.
  - A trip raises a critical threat signal, so it becomes a Posture finding
    and an alert, as well as `audit.keycore.canary_tripped`.
  - Trips are written only to the node-local trip log, and counts are read
    from it. A probe served by a cluster member no longer updates the
    replicated `canary_keys` row.
  - Removed `POST /canary/{id}/trip`. It recorded a trip that never happened
    and audited it as a real `canary_tripped`.
  - Removed the `notify_email`, `algorithm`, `purpose` and `metadata` fields
    from the API: nothing sent email and a decoy has no algorithm. The UI's
    "alert on use" checkbox was never stored.
  - Routes are now `GET|POST /canary/keys`, `GET /canary/keys/{id}/trips` and
    `DELETE /canary/keys/{id}`. `GET|POST /canary`, `GET|DELETE /canary/{id}`,
    `GET /canary/{id}/trips` and `GET /canary/summary` are gone.
- **The leak scanner is removed.** It scanned pasted text or a folder on the
  posture host, which is not a credible place for secret scanning. Removed:
  the `/leaks/*` routes, `posture.leak.*` permissions and events, and its
  tables (posture migration `004_drop_leak_scanner.sql`).
- **The credential → key binding registry is removed.** It existed only to
  correlate leak findings with keys. Removed: the `/credential-bindings`
  routes, `/keys/{id}/credential-bindings`, the `credential_binding` field
  of encrypt and wrap requests, `audit.key.credential_binding_auto_registered`,
  and its table (keycore migration `026_drop_credential_bindings.sql`).
- **Also removed:** `GET /threat/signals`, `POST /threat/signals/{id}/ack`
  and `GET /threat/dashboard` (acknowledge and resolve the Posture finding
  instead), the `threat_protection` feature flag, and three dashboard
  libraries nothing imported.
- **Compliance:** no new screen. `audit.keycore.threat_signal_raised` and
  `audit.posture.threat_finding_raised` are the evidence for controls that
  ask for anomaly monitoring.
- **Open:** each node judges its own traffic, so a volume baseline is
  per node, not cluster-wide. Reporting syncs only tenants it already knows
  (any alert, rule, override, channel or report) plus root. A tenant with
  none of those gets its first threat alerts when someone opens its Alert
  Center. Its Posture findings are raised as usual.

## [1.39.0-beta] — 2026-09-28

### One Health view, in Administration
- **Platform > Health is gone; its content moved to Administration >
  Health.** The two screens showed different things under the same name,
  and the Platform one was always empty: it fetched `/api/watchdog/*` and
  `/api/reconciler/*`, which Envoy never routed, sent no token, and turned
  every failure into "No heartbeats received yet". A saved `health` tab or
  `#health` link now opens Administration.
- Administration > Health keeps the live service list (`/auth/system-health`,
  restart buttons) and adds **Heartbeats & Watchdog** (self-reported liveness
  and recent incidents) and **Reconciler Controllers**. A section whose call
  fails says "Unavailable: <error>"; it never shows an empty list instead.
- **Watchdog and reconciler are on the route kernel.** Their read routes
  were unauthenticated raw muxes. They now need a verified token with the
  new `health.read` permission (administrators hold it through `*`) and emit
  `audit.watchdog.heartbeats_listed`, `audit.watchdog.incidents_listed` and
  `audit.reconciler.status_read`, refusals included. Envoy routes
  `/svc/watchdog/` and `/svc/reconciler/` over mTLS. Both services now
  refuse to start without their audit connection. Their unused `/healthz`
  is removed (compose checks the port).
- **Every `platform.Boot` service publishes a heartbeat** once it is
  serving (hsm-connector, payment, secrets, certs, dataprotect), so they
  appear in the watchdog without per-service wiring.
- The reconciler reports no `last_run_at` for a controller that has not run
  yet; it used to send `0001-01-01T00:00:00Z`.

## [1.38.0-beta] — 2026-09-27

### Key history lives on the key; the fake lineage tamper check is gone
- **Removed: Source Traceability.** The tab, all 14 `/discovery/lineage/*`
  routes and the `lineage_events` table (discovery migration
  `003_drop_lineage.sql`) are deleted. The only writer was the tab's own
  "record event" form, so its graph, provenance and chain-of-custody views
  showed what users typed. Its tamper check (`POST
  /discovery/lineage/tamper-check/{key_id}`) compared a hash with the same
  hash recomputed from the same rows, so it always answered "verified".
  Security & compliance loses the tab. Discovery stays on the route-kernel
  burn-down list: its scan, asset and PII routes still use a raw mux.
- **New: Keys > key detail > History & usage.**
  - *Timeline:* the key's audit events (`GET /audit/timeline/{id}`), with
    **Verify integrity** calling the new `GET
    /audit/targets/{target_id}/integrity`. Every event is recomputed from
    its stored row and checked against its chain links to both neighbours,
    its HMAC and, once sealed, the Merkle root stored with its epoch. A
    tampered trail answers `verdict: tampered` with per-event reasons and
    raises the critical `audit.audit.chain_broken`.
  - *Used by:* the key's callers from keycore's usage trail (new `GET
    /keys/{id}/consumers`): actor, interface, operation counts and last use,
    over the trail's 30 days on this node (each node keeps its own).
  - *Before you rotate or delete:* the callers affected, the version a
    rotation creates and what happens to the current one, and version
    counts by status.
- **Fixed: Merkle proofs verified against themselves.** `GET
  /audit/events/{id}/proof` returned the root of a tree rebuilt from the
  current leaves, so a proof over an altered leaf still verified. It now
  returns the root stored when the epoch was sealed.
- New audit events: `audit.audit.target_integrity_verified`,
  `audit.key.key_consumers_read` (both kernel events, refusals included).
  `audit.audit.chain_broken` is now in the register.

## [1.37.0-beta] — 2026-09-27

### Close the 1.33.0-beta open items for sbom and reporting
- **Reads never write.** `GET /cbom/history` generated and stored a first
  CBOM snapshot when the tenant had none: a write on a read path, which
  also ran on cluster members (they must not write replicated tables). It
  now returns an empty list; `POST /cbom/generate` or the scheduler creates
  snapshots.
- **One audit pipeline for background events.** sbom's snapshot events and
  reporting's `alert_created`, `evidence_pack_requested` and scheduled
  `report_requested` were raw publishes of a private payload shape. They now
  go through `pkg/audit` `Client.Emit` as standard events (actor
  `kms-sbom` / `kms-reporting`, `actor_type: service`, fields in `details`).
  `audit.cbom.generated` from sbom is now `audit.sbom.cbom_generated`
  (compliance's own `audit.cbom.generated` is unchanged).

## [1.36.0-beta] — 2026-09-27

### Every audit register row names the test that proves it
Each table in
[AUDIT_EVENTS_2026-09.md](docs/SECURITY/AUDIT_EVENTS_2026-09.md) now has a
Test column. About 40 events had no test that failed if the event stopped
being emitted. They have one now, and filling the column found five real
gaps:
- **A cluster join audited no publications.** When a member joined, the
  primary created replication publications for it, and none was audited:
  only the once-a-minute loop audited them. The join now audits
  `audit.cluster.publication_changed` too.
- **A refused service derive was not audited.** Keycore refused a
  `POST /keys/{id}/service-derive` from anything other than an internal
  service identity, returning 403 with no specific event. New:
  `audit.key.service_derive_refused`, with the response's error code as
  `reason`.
- **`audit.cert.ocsp_refused` said `result: denied`.** Refusals use
  `result: refused` everywhere else. It now reports `result: refused` and
  `reason: sha1_certid_fips_strict`.
- **`audit.key.create` for an HSM key lacked `hsm_manufacturer`,** although
  the register listed it. The event now carries it, from the same device
  report as the key's labels.
- **Nothing could check the scheduled rotation audit.** The scheduler only
  accepted a NATS client, so no test could see `rotation_policy_run`. It
  now takes the same emitter interface as the route kernel.

New or extended tests: the two-node join (`TestSecureJoinEndToEnd`);
cluster master-key transfer; service derive; the HSM device change, the
destroy failure and the HSM routes (SoftHSM2); a CRL that an HSM CA
cannot sign (SoftHSM2); OCSP in strict mode; internal PKI bootstrap,
Sub CA creation and enrolment; the mTLS inventory read and rotation; PQC
migration steps; MEK exposure listing, acknowledgement and recording;
every webhook management route; a refused credential seal; every posture
engine and leak route; the scheduled audit sync; a disabled leak target;
agility and rotation routes; and dataprotect vault re-protection and
migration abort.


### Posture escalation approvals work with no setup
- **Built-in approval policy.** A posture escalation used to be refused on
  every tenant until an administrator created an approval policy covering
  `posture.escalate_remediation`. Now governance creates **Posture
  escalation (built-in)** in a tenant the first time an escalation needs
  approval and no active policy covers it:
  - approvers are the tenant's administrators (roles `admin`,
    `tenant-admin`, direct or through a group) other than the requester;
  - one approval is enough;
  - it is audited once as `audit.governance.builtin_policy_created`.
- **It is an ordinary policy afterwards.** Edit its approvers or quorum, or
  set it inactive, and it is never recreated. A tenant's own active policy
  for `posture.escalate_remediation` or `posture.*` takes precedence.
  Deleting it is refused (`409 builtin_policy`, audited `approval_refused`,
  `reason: builtin_policy_delete`), because it would be created again.
- **The requester is left out of the approvers when a service opens the
  request.** Posture names the requester by user ID only, and governance
  excluded requesters by email. A requesting admin was therefore sent
  approval links for their own request (their vote was still refused), and
  a sole admin got a request nobody could approve. Governance now looks up
  the email of a requester a service names.
- **No approvers means a clear refusal.** When no policy is active the
  message is "no active approval policy covers <action>". A tenant whose
  only administrator is the requester is refused with "no approvers
  configured for policy".
- **Docs:** the governance policy section of the API reference showed fields
  governance doesn't have (`minApprovers`, `approverGroups`,
  `emergencyBypassAllowed`); it now lists the real ones.

## [1.34.0-beta] — 2026-09-27

### Posture remediation does what it says, after a real approval (breaking)
Closes the two items 1.32.0-beta left open.
- **Approvals are verified with governance.** Before, an approval-required
  action ran when the body held *any* non-empty `approval_request_id`. Now
  it runs only when governance holds an **approved** request bound to this
  action (`target_type` `posture_action`, `target_id`, action
  `posture.<type>`, payload hash over tenant, action, type and finding) and
  **opened by the executor**. The first Execute opens that request as
  posture's service identity, naming the verified caller as requester, so
  governance excludes them from the approvers and refuses their vote. The
  action moves to `awaiting_approval` and the call is refused
  `409 approval_pending`. A supplied ID is checked, never trusted
  (`403 approval_invalid`). Governance unconfigured or unreachable refuses
  (`503 approval_unavailable`). An active approval policy covering
  `posture.escalate_remediation` or `posture.*` is required
  ([OPERATIONS_GUIDE.md](docs/OPERATIONS_GUIDE.md)).
- **Execute runs a real executor or refuses.** "Execute" used to publish
  `audit.posture.runbook.execute`, which no service consumed, and marked the
  action executed. That event is gone. The findings carry only counts (no
  connector, client, credential, HSM profile or certificate), so eight of the
  nine action types had nothing a real executor could act on:
  - `escalate_remediation` now really escalates. It raises the overdue
    finding one severity level, restarts its SLA and resolves the SLA-breach
    finding; the result is in the response and the audit event.
  - The engine no longer creates `restart_degraded_connector`,
    `failover_hsm_profile`, `quarantine_nonapproved_policy`,
    `quarantine_compromised_client_profile`, `rotate_affected_credentials`,
    `rebalance_certificate_renewal_schedule`,
    `execute_emergency_certificate_rotation` or
    `spread_certificate_rotation_window` actions. Their findings still raise
    the corrective score and keep their recommended action as operator
    guidance. Executing one is refused `409 not_executable`.
- **Existing action rows are corrected** on the primary at the next scan, and
  audited once as `audit.posture.actions_corrected`:
  - escalations the old code marked executed go back to `suggested` (nothing
    was escalated);
  - other types it marked executed become `not_performed`;
  - open actions of other types become `withdrawn`.
- **`POSTURE_AUTO_REMEDIATE` is removed.** It "auto-executed" low-impact
  actions, which only published the unconsumed event.
- **Remediation cockpit:** the "Safe Auto-Fix" group is gone (nothing
  auto-fixes). Withdrawn and not-performed actions are left out of the
  cockpit and the scenario simulator. Rollback hints no longer describe
  undoing actions that never ran.
- **Dashboard:** Execute is offered for `suggested`, `awaiting_approval` and
  `failed` actions. The approval request ID is shown in the toast.

## [1.33.0-beta] — 2026-09-27

### sbom and reporting on the route kernel: tenant and identity from the token (breaking)
- **Cross-tenant access closed.** `POST /cbom/generate` took `tenant_id`
  from the body and `POST /reports/generate` from the body or query, with no
  check against the caller's token, so any caller could generate a CBOM or
  queue a report (over another tenant's alerts and posture) for any tenant.
  Every sbom and reporting route is now registered through `pkg/route`: the
  tenant is the verified token's, a `tenant_id` in the query, `X-Tenant-ID`
  or body must match it (403 `tenant_mismatch`), and internal `kms-*`
  service principals still act for the tenant they name.
- **sbom now verifies tokens at all.** It had no JWT middleware: every route,
  including the platform-wide advisory writes, answered unauthenticated
  callers. It now requires a verified token (`SBOM_JWT_PUBLIC_KEY_*` or the
  shared `JWT_PUBLIC_KEY_*`, already in compose) and refuses to start without
  one.
- **Identity from the token only.** `requested_by` (report generation) and
  `actor` (alert acknowledge/resolve/false-positive, bulk acknowledge/resolve)
  body fields are rejected with 400; the `actor` query parameter and
  `X-Actor-ID` header on `DELETE /reports/jobs/{id}` are ignored. The
  recorded requester, acknowledger, resolver and deleting actor is the
  verified caller.
- **Permissions.** `sbom.read` / `sbom.write` / `sbom.delete` and
  `reporting.read` / `reporting.write` / `reporting.delete`. Tenant admins
  (`*`) are unaffected; custom roles that used these screens need the new
  grants. `POST /telemetry/errors` needs only a verified token. The
  platform SBOM and its advisories are shared, so generating it or changing
  advisories also requires the platform tenant (refusal reason
  `platform_tenant_required`).
- **Audit.** Every route emits its own `audit.sbom.<action>` /
  `audit.reporting.<action>`, refusals included (list in
  [docs/API_REFERENCE.md](docs/API_REFERENCE.md), Audit Action Subject
  Reference). The reporting service no longer publishes the request events
  itself; the kernel emits them under the same subjects (`rule_created`,
  `report_deleted`, `mttd_stats_viewed`, ...). `audit.reporting.alert_escalated`
  is replaced by `audit.reporting.alert_updated` with `operation`.
  Scheduled report runs publish `audit.reporting.report_requested` with
  `trigger: scheduled`.
- **Alert operations** are one route, `PUT /alerts/{id}/{op}` (`op` =
  `acknowledge`, `resolve`, `false-positive`, `escalate`), replacing the
  `PUT /alerts/` subtree router. Paths are unchanged for clients.
- **Alert feed streams.** `GET /alerts/feed` (SSE) could never flush:
  neither `pkg/auditmw`'s response wrapper nor the kernel's exposed `Flush`.
  Both now implement `Unwrap`, and the feed subscribes before sending
  `ready`.
- **Dashboard and OpenAPI.** The dashboard no longer sends `tenant_id`,
  `requested_by` or `actor` in these requests. The sbom and reporting
  OpenAPI specs declare bearer auth, list each operation's permission and
  audit subject, drop `tenant_id`/`requested_by` from request bodies and add
  `DELETE /reports/jobs/{id}`. `services/sbom/handler.go` and
  `services/reporting/handler.go` leave the route-kernel burn-down list.
- **Still open:** `GET /cbom/history` generates a first snapshot when none
  exists (a write on a read path, including on cluster members); the
  reporting service's background events (`alert_created`,
  `evidence_pack_requested`, scheduled `report_requested`) and sbom's
  `generated` / `cbom.generated` still use the legacy publisher rather than
  `pkg/audit` `Client.Emit`.

## [1.32.0-beta] — 2026-09-27

### Posture requires a verified token on every route (breaking)
- **Posture is on the `pkg/route` kernel.** All twelve `/posture/*` routes
  moved off the raw `http.ServeMux`; `services/posture/handler.go` is off the
  route-kernel burn-down list. Before this, `optionalJWTMiddleware` let
  requests with no `Authorization` header through and Envoy adds no auth on
  `/svc/posture/`, so:
  - `GET /posture/dashboard`, `/posture/risk` and `/posture/risk/history`
    took the tenant from `tenant_id` / `X-Tenant-ID` unchecked and, with
    none, served `*` (the all-tenant aggregate), to anyone.
  - `POST /posture/scan` scanned any tenant, or every tenant (`*`, `all`
    or empty), without a token.
  - `POST /posture/events` and `/events/batch` stored events under any
    `tenant_id` in the body, without a token.
  - `POST /posture/actions/{id}/execute` recorded the executor from the body
    `actor` or `X-Actor-ID` (CLAUDE.md rule 4).
- **Now:** a missing or forged token is refused with `401`; the tenant is
  the token's, and a query, header, body or batch-item tenant that differs
  is refused (`403 tenant_mismatch`); `*` and `all` are refused
  (`403 tenant_wildcard`) even for tenant-less root tokens and service
  principals; the executor is the verified caller, a body `actor` is
  rejected (`400`) and `X-Actor-ID` is ignored.
- **Permissions:** `posture.read` (dashboard, risk, findings, actions),
  `posture.write` (scan, event ingest, audit sync, finding status),
  `posture.action.execute` (execute an action). `kms.read`/`kms.write` don't
  grant them. Roles with `*` or `posture.*` are unaffected.
- **Audit:** every request emits `audit.posture.<action>` (list in
  [docs/API_REFERENCE.md](docs/API_REFERENCE.md)), refusals included.
  `dashboard_viewed` and `events_ingested` keep their names; the service no
  longer emits them a second time. The scheduled audit sync now emits
  `events_ingested` under the synced tenant (it used `root` for every
  tenant).
- **Execute is honest about outcome:** re-running an executed action returns
  `409 already_executed` (it returned `200` and did nothing), and a runbook
  that can't be published (no event bus, or publish error) returns
  `502 dispatch_failed` with the action marked `failed` (it returned `200`).
- **Posture refuses to start without a JWT public key**
  (`POSTURE_JWT_PUBLIC_KEY_PEM` or the shared `JWT_PUBLIC_KEY_*`); it used
  to log "jwt parser disabled" and serve unauthenticated.
- **Reporting authenticates to posture** with its `kms-reporting` service
  identity (it called `/posture/findings` and `/posture/actions` with no
  token). The dashboard no longer sends `actor`.
- **Posture's audit sync works.** Its calls to audit's `GET /audit/events`
  (the scheduled sync, `POST /posture/ingest/audit`, and the event enrichment
  on dashboard, findings and actions) sent no token, and audit requires one,
  so they got `401` and the engine scored tenants without their audit
  events. They now carry the `kms-posture` service token.
- **Posture OpenAPI spec (2.0.0)** covers all twelve routes (it listed
  seven), with bearer auth, permissions, audit subjects and refusals.
- **Still open:** `approval_request_id` on execute is required but not yet
  verified against governance, and nothing consumes
  `audit.posture.runbook.execute` yet, so "executed" means the runbook event
  was published, not that a remediation ran. Both are tracked as follow-ups.

## [1.31.0-beta] — 2026-09-27

### Signing refusals are proven audited
- `audit.signing.sign_refused` and `audit.signing.request_refused` were
  emitted, but no test showed it. The audit register named a handler function
  instead of a test. New handler tests cover both.
  `TestTenantMismatchRefusedAndAudited` sends a blob, git or verify request
  that names another tenant. It gets 403, emits `request_refused`
  (`reason: tenant_mismatch`, `route`), and nothing else is audited.
  `TestSignRefusalAuditedPostgres` runs against real Postgres. Signing while
  disabled, and signing with a forged OIDC token, each emit `sign_refused`
  with its `code`. A later valid sign is audited as signed, not refused.
- No behaviour change.

## [1.30.0-beta] — 2026-09-27

### Attested key release is real
Until now confidential compute returned a verdict and released nothing
([REAL_CAPABILITY.md](docs/SECURITY/REAL_CAPABILITY.md) listed it as open).
- **`POST /confidential/release`** evaluates the evidence as before and, on an
  `allow`, releases the key to the enclave. The request carries
  `recipient_public_key` (an RSA 2048–8192 key generated in the enclave), and
  the *verified* evidence must commit to it: AWS Nitro signs it into the
  attestation document's `public_key`; Azure MAA and GCP Confidential Space
  commit through their verified nonce = base64url(SHA-256(DER)). Evidence that
  names another key, or any unverified or generic evidence, releases nothing.
- **`POST /keys/{id}/attested-release`** (keycore) returns the key's current
  material sealed to that key: RSA-OAEP-256 wraps a fresh AES-256 key, which
  seals the material with AES-256-GCM (module-generated IV), bound by AAD to
  tenant, key, version and release ID. Only the `kms-confidential` service
  identity may call it, and only for an active, exportable key; HSM-resident
  keys, policy and FIPS refusals apply. Keycore never sees the enclave's
  private key and returns no plaintext. Replaying evidence is harmless: the
  sealed result opens only inside the enclave that holds the key.
- `pkg/crypto`: `SealToRecipient`, `OpenFromRecipient`,
  `ParseRecipientPublicKey`, `RecipientKeyBinding`.
- `kms-confidential` is now a provisioned service identity (auth) and sends
  its service token; the release history records `released` and
  `recipient_key_binding` (migration 003).
- Audit: `audit.confidential.key_released`,
  `audit.confidential.key_release_refused`, `audit.confidential.key_release`
  (kernel), `audit.key.attested_release` (keycore; refusals included).
- The dashboard's confidential tab says what now happens and marks released
  entries.
- README's service table listed `qkd`, `qrng`, `mpc` and `ai` services that do
  not exist; it now lists `ai-gateway`.

## [1.29.0-beta] — 2026-09-27

### OpenAPI specs describe only real services (breaking for anyone using them)
- **The `ai` spec is removed.** `docs/openapi/ai.openapi.*` and the
  dashboard's `/openapi/ai.html` described a `/svc/ai` service
  (`/ai/config`, `/ai/query`, `/ai/analyze/incident`, `/ai/recommend/posture`,
  `/ai/explain/policy`) that does not exist. The only AI service is
  `ai-gateway` (`/svc/ai-gateway/ai-gateway/v1/...`), listed in the route
  index in [docs/API_REFERENCE.md](docs/API_REFERENCE.md). Its generator
  entry, viewer page and validation entries are gone.
- **No plain-HTTP "direct service" servers.** The `sbom`, `posture`,
  `compliance` and `reporting` specs offered `http://localhost:<port>` as a
  second server. Services are reached through the Envoy edge at
  `/svc/<name>`; that is now the only server listed.
- **Checked against the routers.** `scripts/check-doc-routes.py` (run by
  `make conformance`) now reads every `docs/openapi/*.openapi.json`: each
  server must be an edge `/svc/<name>` path routed to a service, and each
  operation must be a route that service registers. All 39 operations in the
  four remaining specs match their routers.
- **Swagger UI assets match the pinned version.** The committed
  `swagger-ui.css` and `swagger-ui-standalone-preset.js` were still 5.32.x
  while the bundle and lockfile were 5.33.0, so "Validate OpenAPI artifacts"
  failed on a clean `npm ci`. Both are now the 5.33.0 files.
- **Still open:** request and response schemas and tenant parameters are not
  yet checked against the handlers (see
  [REAL_CAPABILITY.md](docs/SECURITY/REAL_CAPABILITY.md)).

## [1.28.0-beta] — 2026-09-27

Closes the items 1.27.0-beta left open in
[REAL_CAPABILITY.md](docs/SECURITY/REAL_CAPABILITY.md), and the fakes found
while doing it. [learning.md](learning.md) records how each slipped through.

### Microsoft DKE works with Office and Entra ID tokens (breaking)
- **Entra ID tokens.** hyok verified only Vecta JWTs, so a DKE endpoint whose
  `valid_issuers` named Entra could never be satisfied. A decrypt call may now
  carry an Entra ID access token. It is verified with `pkg/oidc` against the
  Entra tenant's signing keys (`login.microsoftonline.com/{tid}/discovery/v2.0/keys`).
  The token's issuer must be one of the endpoint's `valid_issuers`, its
  audience one of `jwt_audiences`, and its `tid` must match the issuer. The
  user must be listed by user name (`upn` or `preferred_username`; the mutable `email` claim is not used) in the
  new `authorized_emails` metadata, or hold an app role (`roles`) in the new
  `authorized_roles`. An endpoint with no audiences or no authorized users
  refuses every Entra token. The Vecta tenant is the one whose DKE endpoint
  trusts the token's issuer, or `tenant_id` when the key URI names it. For
  Entra callers, `authorized_tenants` lists Entra tenant IDs.
- **The Office wire format.** The adapter did not speak DKE as Office does
  (checked against Microsoft's reference service). `GET /api/v1/keys/{id}`
  now returns `{"key": {kty, n, e (number), alg, kid}, "cache": {"exp"}}`. The
  `kid` is the key's public URL plus its current version, including the
  `/svc/hyok` prefix (from `x-envoy-original-path`). Decrypt moved to
  `POST /api/v1/keys/{id}/{version}/decrypt` (the `kid` plus `/decrypt`).
  Values are standard base64; base64url input is still accepted. The old
  `POST /api/v1/keys/{id}/decrypt` is removed. Only the key's current version
  decrypts: a `kid` naming another version gets `409 key_version_not_current`,
  because keycore decrypts with the current version.
- **The public key without a token.** Office fetches the public key
  anonymously. hyok now serves it without a token, but only on the host an
  enabled endpoint's `key_uri_hostname` names. Decrypt always needs a token.
- **Every DKE refusal is audited:** `audit.hyok.dke_refused` (`reason`,
  `result: refused`, status), including Vecta-token refusals that were not
  audited before.
- Dashboard: HYOK > DKE has Authorized User Emails and Authorized App Roles
  fields, and explains when Entra tokens are accepted.

### Google CSE checks the authentication token's audience (breaking)
- A CSE config now has `authentication_client_ids`: the OAuth client IDs of
  the customer's CSE identity provider. The authentication token's `aud`
  (string or list) must be one of them. Creating a config requires at least
  one. **Existing configs have none and refuse every request until an
  administrator sets them** (dashboard: EKM > Google CSE > Client IDs).
  Migration `006_google_cse_client_ids.sql`.
- Fixed: `UpdateGoogleCSEConfig` and `UpdateAzureEKMConfig` failed on every
  call on Postgres (`CASE types text and timestamp without time zone cannot be
  matched`). Updating a CSE or Azure EKM config, and the CSE key count, never
  worked. Both now use `COALESCE`, verified on Postgres 17.
- Creating a CSE key without a `kacls_endpoint` is refused. It used to fall
  back to the placeholder host `kacls.vecta-kms.example.com`.

### Governance approver roles decide who may vote
- `approver_roles` was stored but ignored. When a request opens, every active
  user of the tenant who holds one of the policy's roles, directly or through
  a group role binding (key-access groups, and SCIM groups when group role
  mapping is on), becomes an approver alongside `approver_users`. The
  requester is never an approver, so an all-approvers quorum stays reachable.
  A policy whose roles nobody holds opens no request.
- Dashboard: the policy editor has an Approver Roles field. Saving a policy
  used to wipe its stored roles.
- Vote refusals (not an approver, requester voting, bad challenge code) are
  now audited as `audit.governance.approval_refused` with
  `reason: vote_refused`. Before, they only returned 400.

### Java JCA provider rebuilt for real (breaking)
- The provider could not work. It called ekm routes that do not exist
  (`/sign`, `/verify`, a key list). Its `AES/GCM/NoPadding` cipher discarded
  data passed to `update()` and ignored its IV on the remote path. Its key
  cache was never filled, its keystore invented creation dates, and its
  mTLS/API-key settings were never read. The SDK download shipped a second,
  hand-written Java client embedded in Go strings.
- It now registers one service, `Cipher.VectaKeyWrap`
  (`WRAP_MODE`/`UNWRAP_MODE`), over the real ekm wrap/unwrap API, with TLS 1.3,
  `VECTA_CA_CERT` trust, and a bearer token that is never logged. Signature,
  KeyStore, the AES-GCM cipher and the cache are removed. The SDK download is
  the provider source itself (`go:embed`).
- `services/ekm/jca_consumer_test.go` drives it through `javax.crypto.Cipher`
  against the ekm API over TLS: a round trip, plus refusals for a forged
  token, an untrusted server certificate and plain HTTP. CI runs it on
  Temurin 17. **Oracle JDK** loads a `Cipher` provider only from a jar signed
  with an Oracle JCE code-signing certificate, so the provider runs on
  OpenJDK builds.

### Docs name only APIs that exist
- API_REFERENCE.md described 151 endpoints that no service registers,
  including whole MPC, QKD, QRNG and `/svc/ai` services (MPC, QKD and QRNG
  moved to KMSExtension). They are removed. Paths that missed the service's
  own prefix are corrected, and a route index generated from the code lists
  every real route.
- KEYS.md, DATA_PROTECTION.md, IDENTITY_AND_PQC.md, INFRASTRUCTURE.md,
  REST_API_ADDITIONS.md, FEATURE_REFERENCE.md, ADMINISTRATION.md,
  CERTIFICATES.md, CLOUD_INTEGRATION.md, GOVERNANCE_AND_COMPLIANCE.md and
  AUTOMATION_ALKM_PQC.md now point at real routes, or no longer describe what
  does not exist. That includes the "Vecta PKCS#11 library" walkthrough.
- `scripts/check-doc-routes.py`, in `make conformance`, fails when a doc
  names a `METHOD /path` that no service registers. `--write-index`
  regenerates the route index. The dashboard REST catalog and
  `docs/generated/` are regenerated.

### Removed
- 11 packages in `pkg/` that nothing imported: `keyrisk`, `sprawlscanner`,
  `analytics`, `multicloudsync`, `keylineage`, `geofence`, `classification`,
  `cicd`, `imagesign`, `dynamicsecrets`, `breakglass` (about 7,600 lines).
  `go mod tidy` dropped the AWS IAM and S3 SDKs they alone used. They are
  recoverable from git history before this release.

### Fixed
- The ekm-agent Windows build: `pkg/svctls` called `syscall.Kill`, which does
  not exist on Windows. A graceful restart on Windows exits for the service
  manager to restart (`restart_windows.go`). CI now cross-builds the agent for
  Windows.
- A racy posture test (`TestLeakScanFindsSecretsAndResolverIsTheCaller`)
  read the last audit event while the background scan could already have
  emitted `leak_scan_completed`. It now looks for the start event.

## [1.27.0-beta] — 2026-09-27

The second sweep for fake capability (CLAUDE.md rule 8), covering the
services the first sweep only skimmed: auth, governance, hyok, signing,
reporting, secrets, kmip, autokey, ekm, ekm-agent, the PKCS#11 provider and
`pkg/tsa`. Several were security holes, not just labels. Each item was made
real, or removed where no real path exists.
[learning.md](learning.md) records how each slipped through;
[docs/SECURITY/REAL_CAPABILITY.md](docs/SECURITY/REAL_CAPABILITY.md) lists them.

### Security: SAML and OIDC SSO verify what they accept (breaking)
- **SAML** accepted any SAMLResponse: no XML signature check, no issuer,
  audience, recipient or request binding, so anyone could log in as any user.
  The `idp_certificate` the admin entered was never read. Now the Assertion
  (or Response) signature is verified with goxmldsig v1.6.1 against that
  certificate (SHA-2 only), and issuer (`idp_entity_id`, now required),
  audience, recipient, `InResponseTo` (bound to a one-time RelayState), validity
  window and single use are enforced. Values are read only from the signed
  element, so signature wrapping is refused.
- **OIDC** read ID-token claims without checking the signature. `pkg/oidc`
  now verifies the token against the issuer's JWKS with `iss`, `aud`, `exp`,
  `nonce` and `azp`; the userinfo fallback is gone.
- Unused settings removed: `idp_metadata_url`, `sign_requests`,
  `sp_private_key` (SAML), `response_type` (OIDC). Existing SAML providers
  must set `idp_entity_id` and `idp_certificate` before logins work.
- Refusals are audited: `audit.auth.sso_login_refused`.

### Security: governance approvals are enforced (breaking)
- The approval API (policies, requests, votes, key approvals) needed no
  authentication, and a dashboard vote counted as whatever `approver_email`
  the body named, so one user could meet any quorum. Now every route needs a
  verified token for the tenant, policy changes need a tenant administrator,
  and a dashboard vote is cast as the logged-in user (email from their
  account). Only approvers the request was sent to may vote, never the
  requester; a challenge code must be the voter's. Users cannot pick their own
  approvers or set a completion callback. The email-link page needs a live
  token. `approver_roles` was never enforced and is documented as such.
  Refusals: `audit.governance.approval_refused`, `audit.governance.link_refused`.
- Auth client activation stored the placeholder `TODO-GOVERNANCE-HOOK` as its
  approval; it now requires an approved `client.activate` request
  (`audit.auth.client_activation_refused`) and no longer accepts another
  tenant in the body.
- hyok, autokey, keyaccess and keycore now send their service token to
  governance.

### Security: HYOK authentication (breaking)
- Every request arrives through Envoy over internal mTLS, so the TLS peer
  certificate hyok treated as the client's identity was Envoy's: any caller
  was "mtls"-authenticated for whatever `tenant_id` it named. `X-Client-CN`
  headers were trusted too. Now only a verified JWT authenticates.
  `auth_mode` `mtls` is refused (the edge does not verify client
  certificates); `mtls_or_jwt` reads as `jwt`.
- Endpoint administration had no authentication; it now needs a tenant
  administrator (`audit.hyok.admin_refused`).
- Governance-gated operations could never complete (each retry opened a new
  approval; the callback named no reachable method). A retry carrying
  `approval_request_id` now runs once the approval is approved for that key,
  operation and payload, and only once (`audit.hyok.approval_refused`).
- A down key-access service allowed the request; with the default
  `HYOK_POLICY_FAIL_CLOSED=true` it now refuses.

### Security: EKM is authenticated, and reachable
- EKM treated the TLS peer as a `tenant:role` client certificate; behind Envoy
  that is `vecta-envoy`, so every edge request failed with 401 (confirmed on
  a running stack), and dropping the check would have left EKM with no
  authentication at all. EKM now requires a verified auth-service token for
  the tenant on every tenant route (`audit.ekm.request_refused`); BitLocker
  agents use their bitlocker-role JWT. Deploy scripts read `EKM_TOKEN` from the
  environment and never write it to disk.
- Google CSE KACLS decoded Google's authorization token without verifying it
  and fell back to "the first active key". It now verifies the token
  (`gsuitecse-tokenissuer-*` issuer, audience `cse-authorization`), requires
  the same user as the authentication token, requires `exp` and an allowed
  hosted domain, and uses only the key the token names.

### Security: signing identity is verified
- OIDC issuer/subject and workload identity came from the request body and
  were signed into the envelope as if proven. Now OIDC mode takes
  `oidc_token`, verified against the issuer's JWKS (issuer must be listed
  exactly; audience `SIGNING_OIDC_AUDIENCE`), and workload mode signs as the
  caller token's `workload_identity`.
- `/signing/blob|git|verify` accepted another tenant's `tenant_id` in the
  body; it is now enforced (`audit.signing.request_refused`,
  `audit.signing.sign_refused`).
- The `require_transparency` toggles gated nothing (an empty `if`) and are
  removed; the record index is described as the tenant signing log, not a
  transparency log.

### Removed or corrected fakes
- **Governance FDE** (status, integrity check, key rotation, recovery test,
  recovery shares) returned hard-coded LUKS data and "passed" for anything;
  **network apply** changed nothing. Both removed, API and UI.
- **Governance system state**: network, DNS/NTP, proxy, license, backup
  schedule, TLS mode and PEMs, HSM/cluster labels and QRNG were stored but
  never read. They are no longer exposed, a migration clears the unused TLS
  private key and license key, and the integrity check reports only measured
  items (SMTP, runtime FIPS mode, a completed backup, SNMP reachability).
  The RNG shown is the one in use (module CTR_DRBG in FIPS mode, else the OS
  CSPRNG); the "hsm-trng" label on software bytes and the bits-per-byte
  statistic over DRBG output are gone. The System Admin save sent fields the
  server rejects and now sends only accepted ones.
- **Reporting** marked alerts "sent" to email, Slack, Teams and SIEM without
  sending anything, and stored schedule recipients nobody emailed. Channels
  are now `screen` only and `recipients` is gone.
- **PKCS#11 provider** (`services/pkcs11-provider`) could not be loaded by any
  PKCS#11 application (no `C_GetFunctionList`), ignored mechanism and PIN, and
  always signed as RSA. Removed, with its SDK download, the "PKCS#11 C
  Provider v2.40/v3.0 active" card and the mechanism "telemetry" that
  relabelled EKM agent activity. The dashboard view is now "Java SDK".
- **EKM TDE guides** told customers to load a Vecta EKM DLL in SQL Server and
  a PKCS#11 library in Oracle, pg_tde and MySQL; none exists. Guides now
  describe KMIP for MySQL (`keyring_okv`), pg_tde and Db2 and say SQL Server,
  Oracle and MariaDB are not supported. The agent's PKCS#11 "readiness" (a
  file-exists check that also marked agents degraded) is gone, and heartbeats
  report the real OS instead of always "windows".
- **BitLocker jobs**: the agent polled with GET (the route is POST), read the
  wrong response shape, reported status `completed` and a string result, so no
  remote operation or recovery-key escrow ever completed. Aligned with the
  service contract; rotated recovery passwords are sent as `recovery_key`.
  Installers wrote `mode` (the agent reads `agent_mode`) and offered
  pkcs11/azure-ekm/google-cse modes the agent does not have.
- **JCA** `SecureRandom.VectaQRNG` called a non-existent endpoint and silently
  used the JVM generator; removed.
- **KMIP** Query advertised 32 operations while 15 are routed; the other
  handlers sat in a build-tagged file that no longer compiled. The file is
  deleted and Query lists the routed operations (tested against the router).
- **Secrets** "PPK" export was not a PuTTY file (removed); PGP armor wrapped
  already-armored keys again (fixed); Vault seal status invented Shamir,
  cluster and build fields (removed).
- **Autokey** template versioning and drift detection were never called, had
  no table, and `version`/`policy_drifted` were always zero; removed.
- **EKM health** said "all checks within threshold" for agents that reported
  no metrics, and new BitLocker clients were "healthy" before any heartbeat.
- **Dead code**: `pkg/tsa` (unused, invented policy OID under PEN 99999),
  `pkg/compliance` and `pkg/evidence` (hard-coded "pass" with invented
  evidence such as "external TLS scan confirms").
- Docs: DATA_PROTECTION.md's PKCS#11 section (invented RPM/DEB/Homebrew
  packages) and JCA section (invented Maven coordinates and config builder),
  CLOUD_INTEGRATION.md's SQL Server/Oracle EKM walkthroughs, and the network
  apply guide are corrected.

### Upgrade notes
- SAML: set `idp_entity_id` and the IdP signing certificate, and start logins
  from Vecta (IdP-initiated SAML is refused).
- Signing clients in OIDC mode send `oidc_token`.
- HYOK callers use bearer JWTs; `mtls` endpoints must be reconfigured.
- EKM agents and scripts need an auth-service token (`EKM_TOKEN`).
- Anything that voted or managed governance policies without a token must
  authenticate.

## [1.26.0-beta] — 2026-09-27

A code-wide sweep for fake, simulated, mock or fabricated capability (CLAUDE.md
rule 8, owner directive of 2026-09-27: "no mock, synthetic, fake simulation
data or feature, no fake audit"). Each item below was either made real or
removed. [learning.md](learning.md) records how each one slipped through.
[docs/SECURITY/REAL_CAPABILITY.md](docs/SECURITY/REAL_CAPABILITY.md) lists the
items and what replaced them.

### Security: format-preserving encryption is real FF1 (breaking)
- **What was wrong.** "FF1" and "FF3-1" were an additive keystream: the round
  keys never depended on the data, so a single known plaintext/ciphertext pair
  decrypted every other value of that length under the same key and tweak.
- **Now.** FF1 follows NIST SP 800-38G (`pkg/crypto.FF1Encrypt`) on the
  certified module's AES, and passes all nine NIST sample vectors.
  **FF3-1 is refused**, because NIST's SP 800-38G Rev. 1 draft withdraws it.
  The FF1 minimum domain applies (radix^length >= 1,000,000; for example, at
  least 6 digits).
- **Existing ciphertext.** Ciphertext produced before 1.26.0-beta does not
  decrypt as FF1. Decrypt it with `algorithm: LEGACY-FF1` or `LEGACY-FF3-1`
  (decrypt only, audited as `audit.dataprotect.fpe_legacy_decrypted`), then
  re-encrypt with FF1. See [docs/DATA_PROTECTION.md](docs/DATA_PROTECTION.md).
- Refusals are audited as `audit.dataprotect.fpe_refused`.

### Security: masking
- The non-consistent `shuffle` mask did nothing: it returned the value
  unmasked. It now shuffles with the CSPRNG.

### Security: keys are the algorithm they name (breaking)
- **What was wrong.**
  - Key creation stored 32 random bytes for any algorithm without its own
    branch: XMSS, HSS/LMS, DSA, DH, ML-DSA-44, hybrid pairs, and every SLH-DSA
    set except 256f.
  - Brainpool and secp256k1 keys were made on P-256, and RSA-1024 keys at
    2048 bits.
  - Every SLH-DSA key was SHAKE-256f, and SLH-DSA sign and verify panicked
    because the parameter set was never supplied.
- **Now.**
  - keycore generates exactly the named key or refuses with
    `400 algorithm_unsupported`, audited as `audit.key.create_refused`.
  - All twelve FIPS 205 SLH-DSA parameter sets are generated, sign and verify.
  - XOR key components (`/keys/form`) form symmetric keys only.
- **Existing records.** On the primary, keycore relabels every key whose
  material is not what its label says: the real algorithm, or
  `INVALID-MATERIAL` when the bytes are not a key (every operation then
  refuses it). Each correction is audited as
  `audit.key.algorithm_label_corrected`.
- **Dashboard.** The Keys tab offers only what keycore generates. Removed:
  Camellia, ChaCha20, DSA, Brainpool, Ed448, X448, ML-DSA-44, HSS/LMS, XMSS,
  hybrid pairs, CMAC and HMAC-SHA3. Also removed: the unwired "New algorithm"
  and "PQC migration (coming soon)" rotate options, the always-checked
  BYOK/HYOK notify boxes, and the PQC "hybrid mode" label that the PQC
  inventory then counted as a hybrid key.

### Security: random sources are what they say
- **What was wrong.** `hsm-trng`, `qkd-seeded-csprng` and
  `qrng-seeded-csprng` returned the OS CSPRNG under their own label, and were
  audited that way.
- **Now.**
  - `hsm-trng` draws from the tenant HSM's `C_GenerateRandom` through the new
    connector route `POST /hsm/random` (audited as
    `audit.hsm.random_generated`). With no tenant HSM it is refused.
  - QKD and QRNG are refused (no such source is integrated), and the unused
    QRNG client is removed.
  - Refusals return `409 random_source_unavailable` and are audited as
    `audit.crypto.random_refused`.

### Removed: invented values in the dashboard
- (The Leak Scanner, Rotation Scheduler and Webhooks `MOCK_*` fallbacks were
  removed in 1.20.0-beta, e3edda730.)
- System Administration showed guessed values when the service reported
  nothing (entropy sample of 4096 bytes, CTR_DRBG, TLS 1.2+ FIPS, and entropy
  "ok"). It now shows "not reported".
- The home dashboard showed "0/0 nodes" when the cluster service didn't
  answer. It now shows "unavailable".
- The Crypto tab's hard-coded "FIPS-approved" algorithm list marked Poly1305,
  3DES encryption and DSA as approved, and offered algorithms keycore doesn't
  implement. It now lists only implemented algorithms, with correct approval
  status.

### Discovery scans observe instead of inventing (breaking)
- **Network.** The scan never connected: each endpoint's "algorithm" was the
  sum of its hostname's bytes mod 5, and the default endpoints were
  `*.vecta.local`. It now performs a TLS handshake with each endpoint in
  `DISCOVERY_TLS_ENDPOINTS` (no default), and records the negotiated key
  exchange (including X25519MLKEM768), the protocol, the cipher, the leaf key
  and whether the chain is trusted.
- **Cloud.** The scan made up AWS, Azure and GCP keys. It now reads each
  registered account's live KMS inventory through the cloud service
  (`CLOUD_URL`).
- **Certificates.** When there were none, the scan invented two certificates
  (one "ML-DSA-65"). It now reports the certs service's list or its error.
- **Code.** The scan walked the container's own filesystem, gave secrets an
  arbitrary algorithm and **stored the matched secret** (rule 9). It now needs
  `WORKSPACE_ROOT`, records file:line and a fingerprint, never the secret,
  and names a private key by the key it parses to.
- A scan type that fails or isn't configured is recorded in `stats.errors`,
  with status `completed_with_errors` or `failed`.
- The unused `pkg/caim` library is deleted; its TLS probe now lives in
  discovery.

### SBOM vulnerabilities
- When OSV or Trivy failed, the SBOM silently returned a built-in two-entry CVE
  list with wrong facts (CVE-2024-24784 listed against gRPC). That list is
  gone:
  - A failed source now returns `503 vulnerability_source_unavailable`.
  - Partial results from a composite with a failed source are refused.
  - `audit.sbom.generated` records `vulnerabilities_assessed: false` instead
    of counting zero.
- New setting: `OSV_ENABLED=false` for air-gapped installs.

### PQC migration does what it records (breaking)
- **What was wrong.** "Execute" marked every step `completed`: key steps
  after a same-algorithm rotate, and other steps after nothing at all.
- **Now.**
  - Key steps create a real successor key of the target algorithm (ML-DSA-65,
    ML-KEM-768 or AES-256), recorded as `successor_created` with the new key
    id.
  - A key already at the target algorithm is rotated (`rotated`).
  - Certificates, TLS endpoints and code become `manual_required`, and the
    plan ends as `manual_steps_remaining`.
  - Rollback deactivates the successor keys. Rotations are reported as not
    reversible.
- New audit event: `audit.pqc.migration_step_executed`.

### Removed: Feature Forge
- It had no staging or production environment ("deployed to prod" changed a
  status field). Its "sandbox dry-run" was two parameter checks, and its
  policy guardrail read HTTP 200 as "permitted" even when the policy service
  denied. Its apply body was also rejected by the policy service, so nothing
  was ever applied.
- Removed: the `featureforge` service, the Compose profile, the Envoy routes,
  the dashboard tab, the installer module, the cluster component and its
  docs.
- Last present at a71088391; the 1.26.0-beta commit removes it.

### Compliance playbooks
- `send_alert`, `notify_soc` and `disable_access` only logged, yet reported
  OK. `send_email`, `generate_evidence_report` and `create_backup` called
  endpoints that don't exist. The dashboard also offered ten actions with no
  executor.
- A playbook now accepts only the actions the executor performs.
- `trigger_assessment` and `snapshot_posture` now run in-process.

### Other corrections
- **Watchdog.** Incidents claimed actions ("page-oncall", "freeze-mutations")
  that nothing performed. They now record `action: alert` and a labelled
  `recommendation`.
- **Confidential compute.** Evaluations return an `allow` / `review` / `deny`
  *verdict*, not a "release": no key material is released. Self-asserted
  `generic` evidence is never allowed.
- **AI gateway.** `/ai-gateway/v1/health` hard-coded every check as "ok". It
  now pings the database and runs the DLP and injection detectors, and
  returns `503 degraded` on failure.
- **Keycore scores.**
  - The cost-optimisation dollar figure came from an invented unit price and
    is removed.
  - The compliance dashboard no longer scores controls as 50 when there are
    none; preview records don't count.
  - The key-health "entropy score" was the algorithm's strength again and is
    removed.
- **Compliance.** PQC readiness is "not assessed" (0 evaluated) instead of
  100% with no keys.
- **Posture.** The what-if no longer claims at least 4 points (12 with
  approval) for every action.
- **Keycore KDF.** scrypt and Argon2id move to `pkg/crypto` and are refused in
  FIPS strict mode (`audit.key.kdf_refused`; impact catalogue entry).
  HKDF-SHA256 and PBKDF2-SHA256 use the certified module.
- **Dead code deleted:** `pkg/hwtoken` (a fabricated fallback token, and the
  PIN on the command line), and keycore's unwired `HBSTracker`,
  `PQCAttestation`, `RotationForecaster` and composite-key types. The cloud
  test double moves to a `_test` file.

### Enforcement
- `make conformance` (`real-capability`) now also fails on `newMock…` /
  `newFake…` constructors outside tests (sample-data constants have been
  checked since 1.20.0-beta).

## [1.25.0-beta] — 2026-09-27

### Webhook credentials encrypted at rest under an audit service master key
- **Closes the item left open in 1.20.0-beta.** Webhook signing secrets and
  custom header values (Splunk HEC tokens, Datadog API keys) were hidden in
  the API but stored in plaintext in the audit database.
- **How they are stored now:**
  - Each webhook's credentials are sealed together as one envelope: a random
    DEK encrypts them, and the audit service's master key wraps the DEK.
  - The master key comes from keycore through `pkg/mek` (a protected system
    key, derived for the `kms-audit` identity). There is no environment
    variable and no fallback.
  - The sealed payload names its tenant and webhook, so a copied blob doesn't
    open elsewhere.
  - The database keeps header names only. The store refuses to write
    plaintext credentials at all.
- **Existing plaintext rows** are sealed on the primary at startup and every
  15 minutes (which catches restored rows). Each one is recorded in the
  exposure register as `plaintext_storage` and shown under Webhook
  credentials on the master-key exposure page.
  - **Action:** a database copy made before this still holds those values.
    Rotate each secret and token at the receiver and enter the new values.
    The entry closes when every credential has been replaced, or when the
    webhook is deleted.
- **A keycore key rotation** re-wraps every envelope onto the new version, as
  for the other `pkg/mek` services.
- **The audit service does not wait for keycore.**
  - It is the audit sink, so the key opens in the background.
  - Until then, credential writes return `503 credentials_key_unavailable`,
    and deliveries that need credentials fail with that reason.
  - A mismatched key keeps credentials unavailable (fail closed) without
    stopping the audit pipeline.
- **New audit events:**
  - `audit.audit.webhook_credentials_sealed` and
    `audit.audit.webhook_credentials_seal_refused`;
  - `audit.audit.mek_exposure_recorded` (new `mek.Keyring.RecordExposure`);
  - the standard `audit.audit.mek_*` events from `pkg/mek`.
- **Operators:** the audit container authenticates to keycore with its
  service identity (`kms-audit`, from `INTERNAL_SERVICE_BOOTSTRAP_SECRET`,
  already in the common environment). Migration 006 adds the envelope
  columns and the `audit_mek_state` / `audit_mek_exposure` tables. Both
  tables are replicated under the `audit` component.
- **Tests:** see docs/SECURITY/SERVICE_MASTER_KEYS.md. They include real
  Postgres, a keycore rotation and a key mismatch.
## [1.24.0-beta] — 2026-09-27

### Fix: system backups held partitioned tables twice, and restores failed
- **What was wrong:** the backup engine listed tables from
  `information_schema`, which reports a partitioned parent and each of its
  partitions as `BASE TABLE`. Every system backup therefore held every row
  of keycore's `keys` (64 hash partitions) and audit's `audit_events`
  (monthly partitions) twice, once through the parent and once through the
  partition. A restore then failed with a duplicate key on `keys_pNN`, or
  would have doubled `audit_events` rows, which have no unique key to stop
  it.
- **Fixed:**
  - Backups capture plain tables and partitioned parents only (`pg_class`,
    `NOT relispartition`). Postgres routes restored rows into their
    partitions.
  - A restore skips a table that is a partition in the current database
    and reports it as skipped. Backups taken before this fix, which contain
    the partitions, restore every row exactly once.
- **Test:** `TestBackupPartitionedTablesPostgres` covers a hash-partitioned
  table through a full backup and restore, and an old-format backup. It
  fails on the previous code. The full suite passes in FIPS `off`, `on` and
  `only` on a shared database that holds keycore's partitioned `keys` table,
  which is where governance's backup tests used to fail.

## [1.23.0-beta] — 2026-09-27

### Fix: 1.22.0-beta was pushed with a failing test
- `TestCorrectKeyLabelsPostgres` failed in the full certs suite, though it
  passed alone. `TestCertsEnrolsItselfLocally` calls `svctls.Init`, which
  sets a process-wide identity. `pkg/db` then dialled every later Postgres
  connection over internal mTLS, and the plain test database refused it. The
  push went ahead because the command didn't stop on the failure.
- **Fixed:** `svctls.ResetForTests` clears that identity when the test
  ends. The full certs suite passes in FIPS `off`, `on` and `only`, with
  all three Postgres tests running. A new conformance check
  (`test-hooks-in-tests`) fails if `ResetForTests` is used outside a test.

## [1.22.0-beta] — 2026-09-27

### Tests: key-label correction proven on real Postgres
- `TestCorrectKeyLabelsPostgres` runs the relabelling of PQC-labelled and
  mis-sized certificate and CA records (`algorithm` with `cert_class` or
  `ca_type`) and the deletion of PQC profiles against real Postgres with the
  certs migrations. Until now only SQLite had run those statements. It
  passes in FIPS `off`, `on` and `only`.
- The certs Postgres tests share one helper, `postgresTestDB`: a schema of
  their own, dropped afterwards. That way governance's backup test, which
  restores every public table, can't interfere.

## [1.21.0-beta] — 2026-09-27

### Landed: the post-quantum certificate removal documented under 1.19.0-beta
- The 1.19.0-beta notes, learning and audit-event docs reached main early,
  in commit `a71088391` (another session committed a shared working tree).
  The code they describe lands here: PQC and hybrid certificate, CA and
  profile requests are refused (`audit.cert.pqc_issuance_refused`), the four
  PQC routes and their RPCs, the stateful-signature counters and the seeded
  PQC profiles are removed, existing PQC-labelled records are relabelled to
  their real key (`audit.certs.certificate_key_label_corrected`,
  `reason: pqc_label_removed`) and PQC profiles deleted
  (`audit.certs.pqc_profile_removed`), and the dashboard's PQC issue flow
  and menus are gone. See 1.19.0-beta for the details.
- Also here: the dashboard API catalog generator reads every service file
  and route-kernel registrations, and `key_label_correction_test.go`
  (`TestGeneratedKeyMatchesRequestedAlgorithm`, `TestCorrectKeyLabels`).

## [1.20.0-beta] — 2026-09-27

### Rotation policies, webhooks and the leak scanner: real, with no sample data
- **Removed invented dashboard data.** Three tabs showed built-in rows as the
  customer's own whenever a call failed, the same pattern removed from
  Crypto Agility in 1.18.0-beta:
  - Webhooks: `MOCK_WEBHOOKS` and `MOCK_DELIVERIES`;
  - Leak Scanner: `MOCK_TARGETS`, `MOCK_FINDINGS` and `MOCK_JOBS`;
  - Rotation Scheduler: `MOCK_POLICIES`, `MOCK_UPCOMING` and `MOCK_RUNS`.

  Failed creates, edits, toggles, deletes and resolves also updated the page
  as if they had succeeded. Each tab now shows **"Not assessed: … is
  unavailable"** with the error, and every action shows its real result or
  error.
- **Rotation policies actually rotate keys** (owner decision: build it).
  - Before, "Run" wrote a run marked `running` and rotated nothing, and
    nothing ever ran a policy on schedule.
  - Now a trigger rotates every active key matching `target_filter` (`*`,
    `tag:`, `id:` or a name glob) through `RotateKey`, *as the caller*.
  - A primary-only scheduler runs due `auto_rotate` policies every minute,
    under keycore's in-process service identity.
  - Each key gets a run row with the real outcome. The policy records its
    totals and next date, and shows `error` with the reason when a key fails.
  - Migration 025 marks the old fake `running` rows as failed ("not
    executed").
  - Only key policies are accepted. `cron_expr` and `notify_days_before`
    (stored, never used) are refused.
  - The routes moved to the `pkg/route` kernel (`key.rotation.read` /
    `key.rotation.write`).
- **Webhooks deliver real events** (owner decision: wire it).
  - Before, only the Test button sent anything.
  - Now the audit service delivers every persisted audit event whose action
    matches a subscription (`*`, `audit.key.*` or an exact action) to the
    tenant's enabled webhooks.
  - Supported formats: JSON, Splunk HEC, Datadog Logs or Slack. PagerDuty
    and "Generic SIEM" were never produced and are refused.
  - Each delivery is recorded and audited (`audit.audit.webhook_delivered`).
  - **Security fixes:**
    - `GET /webhooks` returned signing secrets and header values (Splunk
      tokens, Datadog keys) in plaintext. Both are now write-only.
    - Webhook URLs must be `https`. Delivery dials only the address the SSRF
      guard checked (no DNS rebinding), with no redirects, no proxy and TLS
      1.3 (`ssrfguard.NewHTTPSClient`).
    - HMAC signing uses `pkg/crypto`, with secrets of at least 16
      characters.
  - Routes are on the kernel (`audit.webhook.read` / `audit.webhook.write`).
  - **Breaking:** existing webhooks with the old event names (`key.created`
    and so on) or an `http://` URL deliver nothing until they are edited.
    They never delivered anything before.
- **Leak scanner hardening.**
  - Routes moved to the kernel (`posture.leak.read` / `posture.leak.write`).
    Before, none was audited beyond the request log.
  - A scan's outcome is audited (`audit.posture.leak_scan_completed`, with
    the finding count).
  - `resolved_by` is the verified caller. Before, the client could set any
    name.
  - The tab can scan pasted content, and says plainly that remote URLs are
    not fetched.
- **Breaking:** non-admin roles need the new permissions:
  - `key.rotation.read` / `key.rotation.write`;
  - `audit.webhook.read` / `audit.webhook.write`;
  - `posture.leak.read` / `posture.leak.write`.

  Admin's `*` covers them all.
- **Conformance:** `real-capability` now also fails on built-in sample data:
  `MOCK_*`, `DEMO_*`, `SAMPLE_*`, `FAKE_*` and `DUMMY_*` identifiers, and
  `mock*`/`demo*`/`fake*`/`dummy*` data variables, outside tests. It would
  have caught all four tabs.
- **Tests:**
  - `services/keycore/rotation_engine_test.go`, plus
    `rotation_postgres_test.go` on real Postgres;
  - `services/audit/webhook_test.go`: real TLS delivery, signature, write-only
    secrets and member mode;
  - `services/posture/handler_leak_test.go`;
  - `pkg/ssrfguard` dialer.
- **Still open:** webhook signing secrets and header values are stored in
  plaintext in the audit database. Encrypting them at rest needs a `pkg/mek`
  master key for the audit service (see learning.md).

## [1.19.0-beta] — 2026-09-27

### Removed: post-quantum and hybrid certificates (they were never real)
- **What was fake.** Certificates and CAs requested as ML-DSA, SLH-DSA,
  HSS/LMS, XMSS or hybrid (`ECDSA-P384+ML-DSA-65`) got a classical ECDSA key.
  They were recorded as class `pqc`/`hybrid` and audited as
  `audit.cert.pqc_cert_issued` (rule 8). Real ML-DSA isn't possible here: the
  certified FIPS 140-3 Go Cryptographic Module v1.0.0 has no ML-DSA. Owner
  decision: remove.
- **Now refused and audited.** Issuance, CA creation and profile creation
  with a PQC or hybrid algorithm or class return an error and emit
  `audit.cert.pqc_issuance_refused`.
- **Removed:**
  - the routes `POST /certs/validate-pqc`, `POST /certs/pqc/migrate/{id}`,
    `GET /certs/pqc-readiness` and `GET /certs/ots-status/{ca_id}`, and their
    RPCs in `proto/certs.proto`;
  - the stateful-signature (XMSS/LMS) counters and their certificate
    extension;
  - the four seeded PQC profiles (`pqc-tls-server`, `hybrid-tls`,
    `quantum-safe-smime`, `pqc-code-signing`);
  - in the dashboard: the PQC Issue button and modal, the PQC and hybrid
    algorithm menus (CA, issue, sign CSR) and the PQC stat card.
- **Existing data.** On the primary, certs relabels every PQC- or
  hybrid-labelled certificate and CA with the key it actually carries and the
  `classical` class (`audit.certs.certificate_key_label_corrected`,
  `reason: pqc_label_removed`), and deletes PQC profiles
  (`audit.certs.pqc_profile_removed`).
- **Post-quantum protection that is real** stays: hybrid ML-KEM key
  exchange on internal mTLS (Certificates / PKI > Service mTLS), and the
  CBOM/compliance PQC readiness reports, which inventory algorithms.
- **Fix: the dashboard's API catalog** (`generate-rest-catalog.mjs`) read
  only `handler.go`/`http_api.go` and only `mux.HandleFunc`. It now reads
  every service file and route-kernel `Handle` registrations: 28 routes it
  was missing are listed (Service mTLS, secrets, keycore HSM,
  `generate-data-key`).
- **Correction to 1.16.0-beta.** Its notes cited
  `TestGeneratedKeyMatchesRequestedAlgorithm` and `TestCorrectKeyLabels` as
  proof, but the test file was never written (the command that should have
  created it didn't run). Both tests exist now and pass.

## [1.18.0-beta] — 2026-09-27

### Crypto Agility: real data only; plan progress measured from keys
- **Removed invented data from the dashboard.** When keycore failed to answer,
  the Crypto Agility tab showed built-in numbers as the customer's own: an
  agility score of 78, an inventory (for example "AES-256-GCM 1,842 keys",
  "RSA-2048 634 keys", "ML-KEM-768 94 keys") and three migration plans with
  progress. A failed plan creation also added a made-up plan to the list.
  Those constants and fallbacks are gone. On failure, the tab now says **"Not
  assessed: crypto agility data is unavailable"**, shows the error and offers
  Retry. A failed create shows its error in the dialog.
- **The tab now reads what keycore really returns.** It had expected fields
  keycore never sent (NIST status, ops over 30 days, urgency, replacement,
  family). Against a live keycore it showed a 0 score and blank columns. It
  now shows score and grade, quantum-safe share, legacy-algorithm key count,
  keycore's recommendations, and an inventory of live keys (share,
  quantum-safe, legacy).
- **No perfect score for an empty tenant.** With no live keys, keycore scored
  100/A. `GET /agility/score` now returns `assessed: false` (score 0, empty
  grade), and the tab shows "Not assessed".
- **Deleted and destroyed keys no longer count** toward the inventory or the
  score.
- **Migration plan progress is measured, not typed in.**
  - `affected_keys` is counted by keycore at creation: the live keys on the
    source algorithm.
  - `completed_keys` and the new `remaining_keys` are derived on every read
    from the keys table.
  - Before, both counts came from the client (the dashboard always sent 0),
    and `PATCH` let anyone set `completed_keys` to any number.
  - `PATCH` now changes `status` only.
  - The plans table gets a status selector wired to it.
- **Security fix: cross-tenant plan creation.** `POST
  /agility/migration-plans` trusted a `tenant_id` in the body without checking
  it against the caller's token. An authenticated user could write plans into
  another tenant. All six `/agility/*` routes now go through the `pkg/route`
  kernel:
  - the tenant is enforced;
  - permissions are required: new `key.agility.read` and
    `key.agility.write`, both included in admin's `*`;
  - each call emits its own `audit.key.agility_*` event, refusals
    included. Before, none were audited beyond the request log.
  - **Breaking:** non-admin roles need `key.agility.read` to open the tab,
    and `key.agility.write` to manage plans.
- The dashboard's target-date input sends `YYYY-MM-DD`, which the old handler
  rejected (RFC3339 only), so plan creation always failed and fell through to
  the invented plan. Both formats are accepted now.
- Tests: `services/keycore/handler_agility_test.go`
  - figures derive from keys;
  - client-supplied counts are rejected;
  - the empty tenant is not assessed;
  - body-tenant smuggling is refused and audited;
  - `routetest.RefusalsAudited` passes for all agility routes.
- Still open: the Webhooks, Leak Scanner and Rotation Scheduler tabs have the
  same `MOCK_*` fallback pattern (see learning.md, 2026-09-27).

## [1.17.0-beta] — 2026-09-27

### Product map: dashboard calls to a service chosen at runtime
- The dashboard's MEK exposure page calls the same `/mek/exposure` routes on
  each of several services in a loop. The generator recorded those calls
  under `$dynamic-service` and reported them as unmatched.
- They now match any service's route with the same method and path, in the
  unmatched-call count, the unused-route list and the request flows. The
  kernel-route parsing itself came in 1.14.0-beta.
- Result: unmatched dashboard calls 52 → 50; `/mek/exposure` and its
  acknowledge call now match, as do the Service mTLS calls (1.16.0-beta).

## [1.16.0-beta] — 2026-09-27

### Internal mTLS, slice 3: Service mTLS page
- **Certificates / PKI > Service mTLS** lists every internal identity: the
  services, Envoy and the dashboard, and Postgres, NATS, Valkey and Consul.
  For each it shows:
  - its policy and its active certificate from `vecta-internal-services`;
  - what each running instance reports it uses: serial, key, key-exchange
    profile, and the group and time of its last handshake;
  - whether a change has been applied.
- **Per identity, one click each:**
  - **Certificate key:** ECDSA P-256, ECDSA P-384 or RSA-3072.
  - **Key exchange:**
    - **PQC required:** the server accepts only hybrid ML-KEM
      (`X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`), and
      classical-only peers are refused in the handshake;
    - **PQC preferred:** the default;
    - **Classical:** no ML-KEM.
  - **Rotate:** the certificate is revoked, then a graceful restart drains
    in-flight requests.
  - **Force restart:** the certificate is revoked as `keyCompromise`, then
    the service exits at once.
  - The restarted service generates a fresh key and enrols.
- **Daemons** get a reissued certificate that they reload within 30 s.
- **Rotate every certificate** restarts services one every 20 s, certs last,
  and needs a typed confirmation.
- **How it works:**
  - certs publishes the policy as `/run/vecta/trust/mtls-policy.json`;
  - every service reads it before enrolling and restarts itself when its
    entry changes;
  - every service reports what it runs (`platform_mtls_observed`).
  Root tenant only.
- **Audit:**
  - `audit.certs.internal_mtls_policy_updated`, `internal_mtls_rotated`,
    `internal_mtls_rotated_all` and `internal_mtls_inventory_read`, with
    their refusals;
  - `internal_mtls_applied` once a change is running on every instance.
- **Breaking:** `VECTA_MTLS_KEY_ALGORITHM` is removed; the key comes from the
  policy.

### Security fix: requested key sizes were ignored
- **What was wrong:** key generation ignored the size in the algorithm name.
  - Every RSA certificate got a 2048-bit key and every ECDSA certificate
    P-256.
  - Every CA got RSA-3072 or P-384.
  - The records kept the requested name. The edge and KMIP certificates,
    labelled RSA-3072, were RSA-2048.
- **Fixed:**
  - Keys are generated as named, and never weaker than the old defaults.
  - On the primary, certs corrects every certificate and CA record to the
    key its certificate actually carries
    (`audit.certs.certificate_key_label_corrected`).
  - The edge and KMIP certificates are reissued at RSA-3072.
- **Open for the owner:** a certificate requested as PQC (ML-DSA) or hybrid
  without a CSR also got an ECDSA key while it was recorded and audited as
  PQC. The certified Go module v1.0.0 has no ML-DSA, so this can't be made
  real on the certified module. Those records are left unchanged until the
  owner decides to remove it or make it a labelled preview
  (docs/DECISIONS.md).

### Docs correction
- INTERNAL_TLS.md said Go's TLS can't use ML-DSA certificates. Go's TLS can
  (from module v1.26.0). The accurate reason signatures stay classical here
  is that the certified module v1.0.0 has no ML-DSA.

## [1.15.0-beta] — 2026-09-27

### Removed: the CRWK "TPM sealing" option, which did nothing
- **The problem.** `install.sh` offered "Use TPM sealing for CRWK blob". It
  fed `CERTS_CRWK_USE_TPM_SEAL`, `cert_security.use_tpm_seal` in
  `deployment.yaml`, and `use_tpm_seal: true` in
  `GET /certs/security/status`. No TPM was ever used: the certs root
  wrapping key is sealed with Argon2id(passphrase) + AES-GCM either way. The
  status presented a recorded flag as protection (rule 8).
- **Removed everywhere:**
  - the installer prompt;
  - the `.env` and compose variable;
  - the `deployment.yaml` field and its schema;
  - the start scripts;
  - the certs config field, the status field and the sealed-blob field;
  - the dashboard type.
- **Old configs and blobs:**
  - A sealed blob written by an earlier release still unseals; its
    `use_tpm_seal` field is ignored.
  - `start-kms.sh`, `start-kms.ps1` and `deploy-local.sh` warn when an old
    `deployment.yaml` or `.env` still turns the option on, instead of
    silently implying TPM protection.
- **Test:** `TestCRWKStatusMakesNoTPMClaim` shows that neither status
  reports TPM sealing and a new blob doesn't record it, and that an old
  blob with the flag still unseals.

## [1.14.0-beta] — 2026-09-27

### Fixed: the product map missed every `pkg/route` kernel route
- `scripts/generate_product_map.py` found routes only by `mux.HandleFunc(`.
  The 52 routes registered through the route kernel
  (`r.Handle("METHOD /path", route.Spec{...}, h)`) were missing from
  `docs/generated/` (backend routes, request flows, product map JSON and
  graph). Examples: keycore `POST /keys/{id}/generate-data-key` and
  `GET /hsm/settings`, all of secrets, and hsm-connector.
- The generator now parses kernel registrations and records each route's
  `permission`, audit `action` and `resource` from its `route.Spec`.
  `backend-routes.csv` has new `registration` (`kernel` | `mux`),
  `permission`, `action` and `resource` columns. Public routes show
  `public`.
  - It resolves literal specs, local spec helpers (`secret("read",
    permRead)`), spec variables with later field assignments, and patterns
    built from constants (`"POST "+svctls.EnrollPath`).
  - Route sets defined in `pkg/` are attributed to each service that
    mounts them, with that service's arguments: `pkg/mek` exposure routes
    appear under certs, cloud, ekm and secrets, each with its own
    permission domain; `pkg/hsmconnector` appears under hsm-connector.
- Result: 898 → 950 backend routes; dashboard calls with no matching
  backend route drop from 67 to 52.
- Test files are no longer scanned for routes, and inline handler funcs
  show as `<inline func>` instead of their whole body.

## [1.13.0-beta] — 2026-09-27

### Removed: keycore "Envelope Encryption" hierarchy (it held no keys)
- **Removed the Envelope Encryption tab and keycore's `/envelope/*`
  endpoints** (`keks`, `keks/{id}/rotate`, `deks`, `hierarchy`, `rewrap`,
  `rewrap-jobs`).
- **Why:**
  - A "KEK" was a name and version row with no key material.
  - "Rotate KEK" only incremented the version number.
  - Nothing ever created a DEK, so the DEK list and hierarchy were always
    empty.
  - A "rewrap job" was a row that no worker ever processed.
  - The routes were on the raw mux, with no permission check and no audit
    event.
- Keycore migration 024 drops `envelope_keks`, `envelope_deks` and
  `envelope_rewrap_jobs`. The code is recoverable from `a238c2782`, the last
  commit that has it.

### Added: `POST /keys/{id}/generate-data-key` (real envelope encryption)
- Returns a fresh 128/192/256-bit DEK from the FIPS module's DRBG and the
  same DEK wrapped under the named keycore key. `include_plaintext: false`
  returns only the wrapped copy (for a producer that stores it for later).
- The caller encrypts locally and keeps the wrapped DEK beside the data.
  `POST /keys/{id}/unwrap` recovers it. Rotating the key wraps new DEKs under
  the new version; old versions still unwrap.
- Wrapping runs through the same path as `/wrap`: key access, policy, FIPS
  mode, approval, metering and ops limits all apply.
- Registered through the `pkg/route` kernel: permission `key.wrap`, audit
  `audit.key.data_key_generated`, refusals included (`ops_limit_reached`,
  `policy_denied`, `fips_mode_violation`, access refusals and the kernel's
  own). It runs locally on a cluster member, like `/wrap`.
- Dashboard: Data Encryption → Envelope → Mode "Generate data key".
- dataprotect's `/app/envelope-encrypt|decrypt` is unchanged.

### Fixed: the Secret Vault "Envelope Encryption" switch did nothing
- The switch only changed labels and a metadata field. Every secret is always
  encrypted (a MEK-wrapped DEK per secret, AES-256-GCM), but turning it off
  claimed "secret will be stored as-is". It is now a read-only indicator.

## [1.12.0-beta] — not released

This number was held by uncommitted work while 1.13.0-beta landed. That
work shipped as 1.15.0–1.17.0-beta.

## [1.11.0-beta] — 2026-09-26

### Security fix: hsm-integration SSH access
- **Published password.** The README published `VectaCLI@2026` as the SSH
  "default credentials". No code used it any more. But the SSH password is
  the KMS CLI user's password, and a CLI user seeded before the 2026-09-25 fix could still
  hold it, with port 2222 published on every interface.
  - Auth now refuses to start with it as `AUTH_BOOTSTRAP_CLI_PASSWORD`.
  - On every start it replaces it on any CLI user still holding it
    (`audit.auth.cli_password_revoked`) and locks the SSH copy.
  - It refuses a CLI session using it
    (`audit.auth.cli_session_refused`).
  - The README lists no password.
- **Password on a command line (rule 9).** Opening a CLI session copied
  the password into the container through a `docker exec` command line,
  base64-encoded, where `docker inspect` and the host's process list show
  it. Now it goes through the exec's environment to `chpasswd` via a shell
  builtin, and the copy is audited (`audit.auth.cli_ssh_password_synced`).
- **Key-based SSH.** `HSM_INTEGRATION_SSH_AUTHORIZED_KEYS` holds SSH public
  keys, and setting it turns password login off. The keys file is
  root-owned, so a session can't add its own. Without keys, the account is
  locked at every start until auth sets the password.
- **No sudo.** The SSH user had `NOPASSWD:ALL` sudo. It's removed with the
  package: uploading a library and running the helper scripts need no
  privilege.
- **Hardened sshd:**
  - no root login, TCP/agent/X11 forwarding, tunnels or user environment;
  - `MaxAuthTries 3`;
  - `LogLevel VERBOSE`, which logs key fingerprints.
- **Port 2222 binds to loopback** (`HSM_INTEGRATION_SSH_BIND` to open it
  deliberately).
- **Fix: the container could not start.** The Dockerfile's `USER hsm` made
  the root-only entrypoint fail at `useradd`.
- **Fix: the connector couldn't read uploads.** Uploaded libraries were
  readable only by the SSH user, so `hsm-connector` (another uid) couldn't
  load them. The workspace is now setgid, group `hsm-providers` (gid
  10430), and the connector joins it.
- **Uploads are audited.** `hsm-connector` records an inventory at start,
  then every file added, changed or removed in the provider workspace, with
  its SHA-256 (`audit.hsm.provider_library_*`).
- **New `make conformance` checks:**
  - `no-retired-public-secret` now covers this password and READMEs;
  - `no-sudo-in-images` fails on sudo or `NOPASSWD` in a service image or
    entrypoint.
- **Tests:**
  - refusal, revocation and audit of the public password;
  - the password copy carries the password only in the environment (against
    a fake Docker API);
  - the library watcher.

  Checked on the real container:
  - key login works;
  - password login is off when keys are set;
  - root login, forwarding, sudo and self-added keys are refused;
  - SFTP uploads get the shared group;
  - the account starts locked, the environment-only copy sets it, and a
    restart locks it again.

## [1.10.0-beta] — 2026-09-26

### Security fix: the certs CRWK passphrase was a public default
- **The problem.** `start-kms.sh` and `start-kms.ps1` wrote the passphrase
  sealing the certs root wrapping key (CRWK) as the literal
  `vecta-dev-passphrase` whenever none was set. That covered every
  `deploy-local.sh` and `start-kms` install. The CRWK wraps every CA
  signing key, so a copy of the certs volume plus the database opened all
  of them.
- **Now generated.** The passphrase is 32 random bytes, generated inside the
  certs key volume by `infra/scripts/crwk-passphrase.sh`. `start-kms.sh`,
  `start-kms.ps1` and `install.sh` share that script. An operator-supplied
  value (`CERTS_CRWK_BOOTSTRAP_PASSPHRASE`) is passed to the container by
  variable name. Before, `start-kms.sh` and `install.sh` put the passphrase
  on the `docker run` command line.
- **Validated.** Certs refuses to start on the retired public value, or on a
  passphrase shorter than 32 characters or with fewer than 8 distinct
  characters. `install.sh` and `deploy-local.sh` refuse a short one first.
- **Existing installs migrate automatically.**
  1. The next `start-kms` moves the public passphrase aside and generates a
     new one.
  2. Certs re-keys the CRWK to a new random key, rewraps every CA signer
     (all tenants) and the internal PKI cache, then deletes the old key and
     passphrase.
  3. It emits `audit.certs.crwk_rotated` with
     `reason: public_default_passphrase`.

  If a copy of the old certs volume may exist elsewhere, rotate the CAs too
  (docs/SECURITY/SECRET_ROTATION.md).
- **New: `scripts/rotate-crwk-passphrase.sh`.** It rotates the passphrase at
  any time through the same re-key. The rewrap resumes after a crash, a
  failure is audited (`result: failure`), and nothing is deleted until
  every signer is rewrapped. `GET /certs/security/status` shows
  `rotation_pending` meanwhile.
- **New `make conformance` checks:**
  - `no-secret-fallback-scripts`: a literal `${SECRET:-...}` in the
    installers and start scripts;
  - `no-retired-public-secret`: a value that once shipped, such as this
    passphrase or `vecta-valkey-secret`, appearing again in code.
- **Dashboard fix:** System Administration → Runtime Crypto now shows the
  certs root wrapping key's real state (storage, mode, state, key version,
  a pending rotation, last error). The summary used to read fields the API
  doesn't return, fell back to "ready", and was never shown.
- **Tests:** refusal of public and weak passphrases; the full migration on
  SQLite and on real Postgres; crash-resume and failure audit; the script
  run in the busybox, alpine and postgres images.

## [1.9.0-beta] — 2026-09-26

### Internal mTLS, slice 2: Postgres, NATS, Valkey and Consul
- **Postgres** accepts only TLS 1.3 with a client certificate chaining to
  the internal CA **and** the SCRAM password. Plaintext is rejected by
  `pg_hba`, which is now actually used (`hba_file`); the mounted file was
  previously ignored.
  - Verified: all 61 service connections are TLS 1.3, each with its own
    `kms-<service>` client certificate.
- **NATS** requires TLS 1.3 and a Sub CA client certificate, plus the
  token. Its plain-HTTP monitoring port (8222) is gone.
  - Services keep retrying a NATS connection that isn't up yet, instead of
    silently running without audit publishing.
- **Valkey** is TLS 1.3 only, with a client certificate and a password
  (`VALKEY_PASSWORD`, generated by every installer).
  - Security fix: `valkey.conf` shipped `requirepass vecta-valkey-secret`, a
    password in the repo.
  - The metadata cache was never actually in use: keycore connected without
    the password and fell back to memory. It is in use now.
- **Consul** serves its API only over HTTPS on 8501, with mTLS. Plain HTTP
  (8500), gRPC (8502), DNS (8600) and Connect are off.
  - `bootstrap-mesh.sh` is removed. It wrote allow-all Connect intentions
    that no service used, over plain HTTP, and failed with 405.
- **How the daemons get certificates.**
  - The certs service issues each daemon a Sub CA server certificate into
    its own subdirectory of the `infra-tls` volume.
  - `infra/tls/tls-entry.sh` installs it for the daemon's user and reloads
    the daemon when the certificate is renewed.
- **Certs starts before the database.**
  - It loads the internal root and Sub CA from a sealed cache on its key
    volume (keys still wrapped by the certs root wrapping key). On a fresh
    install it creates them.
  - It issues its own and the daemons' certificates, then connects to
    Postgres over mTLS and records the CAs and those certificates.
  - Existing installs get the cache from a one-time export of the two CA
    rows over Postgres' Unix socket.
- **The FIPS mode is known before any cryptography.**
  - Governance writes the platform mode to
    `/run/vecta/platform/fips-mode`, and services read it at start.
  - Before, the mode was read from Postgres, which now needs mTLS: a TLS
    handshake in the seed mode.
  - Until a service's database connection is attached, it doesn't run
    primary-only cluster jobs.
- **Removed:**
  - **etcd**, which nothing used; it served plain HTTP.
  - **pgbouncer**, an opt-in profile no DSN pointed at.

### Fixed: audit ingestion had stalled
- **Since 12:10 UTC every audit event was stuck in NATS.**
  - Platform events without a tenant were rejected and redelivered
    forever, until the consumer's in-flight limit blocked everything
    behind them.
  - Now they are recorded under the platform tenant
    (`details.tenant_scope = platform`), and a message that can never be
    ingested is terminated instead of redelivered.
  - The backlog, about 9,100 events, was ingested after the fix.
- **Corrected a documented subject:** the kernel's enrolment event is
  `audit.certs.internal_enroll`, not `audit.cert.internal_enroll`.

### Enforcement
- **`make conformance` `no-password-in-infra-config`** fails on a literal
  `requirepass` or `masterauth` in any `infra/*.conf`.
- **The `tls-only` rule now also covers the infrastructure hosts:**
  postgres, nats, valkey and consul.

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
