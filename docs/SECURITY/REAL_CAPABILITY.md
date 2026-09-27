# Real capability only

**Standing rule** (owner directive, 2026-09-26; CLAUDE.md rule 8): every
feature in the KMS is 100% real capability. It does what its UI and API say,
end to end. Nothing is mimicked, simulated or faked, and a screen with no
working backend behind it doesn't count as a feature.

## What counts as fake

- Results the code invents: synthetic certificates, "passed" steps that
  never ran, made-up RTO/RPO, fixed "10/10 keys restored".
- A workflow that stores records but never touches the thing it claims to
  protect, such as "escrowing" a key without the key material.
- Demo or sample data shown as if it came from the customer's system.
- UI controls that change nothing in the backend.
- Security values from non-cryptographic randomness (`Math.random` nonces,
  timestamp fallbacks).
- **Mock or sample data used as a fallback** (owner directive, 2026-09-27):
  `MOCK_*` constants rendered when an API call fails, built-in "local
  catalogue" results when the real source is unreachable, invented defaults
  shown as reported values.
- **Invented numbers:** scores for things never measured, dollar costs from
  a made-up unit price, a readiness of 100% with nothing assessed. Show
  "not assessed" instead.
- **False labels:** recording the algorithm, key size, RNG source or
  provider that was requested rather than what was produced or called.
- **Fake audit:** an audit event or `result: "success"` for work that didn't
  happen (a no-op, a log-only action, a same-algorithm rotate audited as a
  migration). The audit trail is evidence; fake audit fabricates evidence
  (CLAUDE.md rule 7).
- Mocks outside `_test` files.

## What to do instead

1. Build it for real. Test it against its real dependency (Postgres, the
   real protocol client, SoftHSM2 for PKCS#11), audit every action and
   refusal, and take the tenant and actor from verified claims.
2. If that isn't possible yet, remove it (preferred). Otherwise label it a
   preview: list it in `pkg/features.Preview`, label its responses, and have
   operations it can't perform return `409 feature_preview`. A preview
   stores settings; it never produces results.

## How it's enforced

- `make conformance`, rule `real-capability`, fails on:
  - `simulate*`, `synthetic*`, `fabricate*`, `fake*` and `mock*` functions
    outside tests (Go and dashboard TypeScript);
  - `Math.random()*256` byte generation and `nonce-${Date.now…}` fallbacks
    in the dashboard;
  - built-in sample data outside tests: `MOCK_*`, `DEMO_*`, `SAMPLE_*`,
    `FAKE_*` or `DUMMY_*` identifiers, and `mock*`/`demo*`/`fake*`/`dummy*`
    data variables (added 2026-09-27). A failed fetch renders "not assessed /
    unavailable" with the error.
- Review: follow the data. If no code path touches the secret, calls the
  network or runs the check, the feature is a record-keeper, whatever the
  UI shows.

## Removed for faking (2026-09-26)

| Feature | What it faked | Replaced by |
|---|---|---|
| Key escrow workflow (keycore) | Stored key names only; approvals released nothing; votes forgeable | M-of-N guardian shares for the backup key ([BACKUP_KEYS.md](BACKUP_KEYS.md)) |
| CT log monitor (certs) | `simulateCTFetch` invented certificates and "unknown CA" alerts | Nothing yet; certificate discovery and scanning may come later |
| DR drill (keycore) | Every step "passed", synthetic RTO/RPO | Verify Backup (`POST /governance/backups/verify`) |
| mTLS Mesh (certs) | "Renew" discarded the cert and key; topology claimed mTLS on plain-HTTP links | Internal mTLS from the internal-services Sub CA ([INTERNAL_TLS.md](INTERNAL_TLS.md)) |
| "TLS 1.3 + Hybrid PQC (KMS internal)" mode (governance) | Minted ML-DSA certificates for every service, then discarded them; audited `internal_hybrid_tls_applied` | Real hybrid ML-KEM key exchange on every internal mTLS link, asserted by `TestMutualTLSBetweenServices` |
| Envelope Encryption hierarchy (keycore, 2026-09-27) | KEKs without key material, "rotate" bumped a counter, DEK list always empty, rewrap jobs never ran | `POST /keys/{id}/generate-data-key` + `/unwrap` on real keycore keys |
| Sample-data fallbacks (dashboard, 2026-09-27) | Crypto Agility, Webhooks, Leak Scanner and Rotation Scheduler tabs showed built-in `MOCK_*` rows as the customer's data when a call failed, and "succeeded" at failed creates | An explicit "not assessed / unavailable" state with the error |
| Rotation policy trigger (keycore, 2026-09-27) | Wrote a run marked "running" and rotated nothing; no scheduler existed | Trigger and a primary-only scheduler rotate the matching keys through `RotateKey` |
| Webhook event delivery (audit, 2026-09-27) | Only the Test button sent anything; the dispatcher was never wired | Every matching persisted audit event is delivered, signed and recorded |
| Secret Vault envelope switch (dashboard, 2026-09-27) | "Off" claimed secrets were stored as-is; the backend always encrypts | Read-only indicator |
| PQC and hybrid certificates (certs, 2026-09-27) | ML-DSA/SLH-DSA/XMSS/hybrid certificates and CAs got ECDSA keys, recorded and audited as PQC; `pqc/migrate` issued the same | Refused (`audit.cert.pqc_issuance_refused`); existing records relabelled to their real key; PQ protection is internal mTLS's hybrid ML-KEM key exchange |
| Tokenize nonce fallback (dashboard) | `Math.random` / timestamp nonces | The browser CSPRNG only; fails closed |

## Fixed or removed (sweep of 2026-09-27, 1.26.0-beta)

Found by reading the code, fixed in 1.26.0-beta. Details and the lessons
learned: CHANGELOG 1.26.0-beta, [learning.md](../../learning.md).

| Area | What was fake | Now |
|---|---|---|
| FPE (dataprotect) | "FF1"/"FF3-1" were an additive keystream | NIST SP 800-38G FF1 in `pkg/crypto` (NIST vectors); FF3-1 refused; `LEGACY-*` decrypt-only for migration |
| Masking (dataprotect) | Non-consistent `shuffle` was a no-op | CSPRNG Fisher-Yates |
| Key generation (keycore) | Unimplemented algorithms stored as random bytes; Brainpool/secp256k1 made on P-256; RSA-1024 at 2048; all SLH-DSA as SHAKE-256f; SLH-DSA sign panicked | `planKeyGeneration` generates the named key or refuses (`audit.key.create_refused`); existing records relabelled (`audit.key.algorithm_label_corrected`) |
| Random sources (keycore) | HSM/QKD/QRNG labels on OS CSPRNG bytes | `hsm-trng` from the tenant HSM (`POST /hsm/random`); QKD/QRNG refused (`audit.crypto.random_refused`) |
| Dashboard fallbacks | `MOCK_*` data on API failure; Webhooks faked failed writes | The error is shown (1.20.0-beta, e3edda730) |
| Discovery | Hostname byte-sum "scan", invented cloud keys and certificates, secret stored | TLS handshake, cloud service inventory, certs list, code scan with fingerprints only |
| SBOM | Built-in CVE list on source failure | 503 "not assessed"; composite partial failure is an error |
| PQC migration | Steps "completed" without migrating | Successor keys, `rotated`, `manual_required`; rollback deactivates successors |
| Feature Forge | No environments; guardrail read 200 as permit; nothing applied | Removed |
| Compliance playbooks | Log-only "OK" actions; dead endpoints; UI actions with no executor | Only executable actions are accepted; compliance actions run in-process |
| Watchdog | Published actions nothing performed | `action: alert` + labelled `recommendation` |
| Confidential compute | "Attested key release" released nothing; generic evidence trusted | Verdict (`allow`/`review`/`deny`) labelled as such; generic evidence never allowed |
| AI gateway | Hard-coded "ok" health | Database ping and detector self-checks |
| Scores and costs | Invented USD; 50 with no controls; 100% PQC with no keys; name-based "entropy"; minimum what-if reduction | Removed or "not assessed" |
| FIPS flags (dashboard) | Wrong "approved" flags; unimplemented algorithms | Implemented algorithms with correct status |
| System Administration | Guessed runtime values | "not reported" |
| Dashboard cluster status | A failed cluster call showed "0/0 nodes" | "unavailable" |
| Dead code | `pkg/hwtoken`, `pkg/caim`, unwired keycore types, cloud mock outside tests | Deleted / moved to `_test` |
| Conformance gate | Missed `MOCK_*` and `newMock…` | Checked (`MOCK_*` since 1.20.0-beta; constructors in 1.26.0-beta) |

## Fixed or removed (second sweep, 1.27.0-beta)

The services the first sweep only skimmed. Details: CHANGELOG 1.27.0-beta,
[learning.md](../../learning.md).

| Area | What was fake | Now |
|---|---|---|
| SAML SSO (auth) | No signature, issuer, audience or request check; `idp_certificate` never read | goxmldsig verification against the IdP certificate (SHA-2), issuer/audience/recipient/InResponseTo/window/single use (`audit.auth.sso_login_refused`) |
| OIDC SSO (auth) | ID token claims read unverified | `pkg/oidc`: JWKS signature, `iss`, `aud`, `exp`, `nonce`, `azp` |
| Client activation (auth) | Approval ID `TODO-GOVERNANCE-HOOK` | Approved `client.activate` governance request required |
| Governance approvals | No authentication; vote identity from the body; users picked approvers and callbacks | Verified token per tenant, vote as the logged-in user, requester excluded, approvers fixed by the request (`audit.governance.approval_refused`) |
| Governance FDE / network apply | Hard-coded LUKS data, "passed" for anything, "applied" with no effect | Removed |
| Governance system state | License, network, backup schedule, TLS mode/PEMs, HSM/cluster labels, QRNG stored, never read; "hsm-trng" on software bytes; bits/byte over DRBG output | Not exposed; unused TLS key cleared; runtime RNG/TLS reported; integrity checks measured |
| HYOK | Envoy's peer cert or `X-Client-CN` taken as the client; admin routes open; approvals never released; key-access fail-open | JWT only, admin needs tenant admin, approval releases once, fail closed |
| EKM | Peer-cert identity (every edge call 401) with no other auth; KACLS authorization token unverified with first-key fallback | Verified tenant token (`audit.ekm.request_refused`); KACLS verifies Google's token and binds user and key |
| Signing | OIDC/workload identity from the body; cross-tenant body tenant; no-op transparency toggles | Verified `oidc_token` or token workload identity; tenant enforced; toggles removed |
| Reporting | Alerts "sent" to email/Slack/Teams/SIEM; schedule recipients never mailed | Screen channel only; recipients removed |
| PKCS#11 provider | Not loadable (no `C_GetFunctionList`); mechanism/PIN ignored; invented packages in docs; EKM "active v2.40" card and CKM telemetry | Removed; Java SDK view only |
| EKM TDE guides | Vecta EKM DLL / PKCS#11 library recipes for SQL Server, Oracle, pg_tde, MySQL | KMIP for MySQL, pg_tde, Db2; others stated unsupported |
| BitLocker agent | GET poll on a POST route, wrong shapes: no job or escrow ever completed; installer `mode` ignored | Service contract, tested; `agent_mode` |
| ekm-agent PKCS#11 readiness | File-exists check reported "ready" and marked agents degraded; OS always "windows" | Removed; real OS |
| JCA SecureRandom | `VectaQRNG` hit a missing endpoint, used the JVM RNG | Removed |
| KMIP Query | Advertised 32 operations, 15 routed; extension file did not compile | Routed list only; file deleted |
| Secrets | Invalid PPK; double PGP armor; invented Vault seal fields | PPK removed; RFC 4880 armor; fields removed |
| Autokey | Template versioning/drift never called, no table | Removed |
| EKM health | "Within threshold" with no metrics; "healthy" before any heartbeat | "unknown" until reported |
| Dead code | `pkg/tsa` (invented OID), `pkg/compliance` + `pkg/evidence` (hard-coded pass) | Deleted |

## Still open

- **Attested key release** is not built: releasing key material to a verified
  enclave (wrapped to the attestation's public key) would need keycore
  support. Until then, confidential compute returns a verdict only and says
  so.
- **Microsoft DKE with Entra ID tokens**: hyok verifies only Vecta-issued
  JWTs, so a DKE endpoint whose `valid_issuers` names Entra cannot be
  satisfied. Verifying Entra tokens (`pkg/oidc` against the tenant's issuer)
  is not built.
- **Google CSE authentication audience**: the authentication token's `aud`
  is not checked (no client ID is configured); the verified authorization
  token and the email match carry the binding.
- **Governance `approver_roles`** are stored and shown but do not decide who
  may vote; approvers are the emails a request is sent to.
- **Docs describing APIs that do not exist**: for example
  CLOUD_INTEGRATION.md's signing `/policies` with `branch_policy`, and
  report schedules with frequency/day/time fields. A docs accuracy pass
  against the routers is needed.
- **Unused packages** still in `pkg/`, imported by nothing: `keyrisk`,
  `sprawlscanner`, `analytics`, `multicloudsync`, `keylineage`, `geofence`,
  `classification`, `cicd`, `imagesign`, `dynamicsecrets`, `breakglass`. They
  are not capability; review each and delete or wire it.
- **JCA provider** has no test with a real JCA consumer.
- **ekm-agent Windows build** fails in `pkg/svctls` (`syscall.Kill`), which
  predates this sweep.
