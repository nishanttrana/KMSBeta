# Changelog

All notable changes to Vecta KMS are recorded here. Versions follow the
`MAJOR.MINOR.PATCH[-beta]` scheme; the canonical version lives in the
[`VERSION`](VERSION) file and is published as a git tag (`vX.Y.Z`).

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
