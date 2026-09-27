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
| Compliance playbooks (2.4.0-beta) | 38 of 40 triggers listened for subjects nothing emits; 5 key/cert actions called routes that don't exist; `destroy_key` and `disable_user`/`revoke_api_key` always refused; trigger threshold and category shown but never used or stored; approvals reported as success | Trigger catalogue of emitted subjects (`TestTriggerSubjectsAreEmitted`); actions call real endpoints or are removed; `pending_approval` is its own outcome; catalogue served to the UI |
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
| Microsoft DKE (1.28) | Only Vecta tokens; flat JWK, wrong decrypt URL and encoding for Office | Entra ID tokens verified (`pkg/oidc`), Office wire format, anonymous public key on the DKE host |
| Google CSE (1.28) | Authentication token `aud` unchecked; config updates failed on Postgres | `authentication_client_ids` enforced; update SQL fixed |
| Governance (1.28) | `approver_roles` stored, never used | Role holders become approvers when a request opens |
| JCA provider (1.28) | Cipher/Signature/KeyStore over missing routes; SDK zip of hand-written Java | `Cipher.VectaKeyWrap` over the real API, tested by a JCA consumer; SDK is the embedded source |
| Docs (1.28) | 151 API_REFERENCE endpoints and whole services that do not exist | Removed; `check-doc-routes.py` in conformance |
| OpenAPI (1.29) | `ai` spec for a `/svc/ai` service that does not exist; `http://localhost` servers | Removed; specs checked by `check-doc-routes.py` |
| Unused packages (1.28) | 11 `pkg/` packages imported by nothing | Deleted |

## Built (1.30.0-beta)

| Area | Was | Now |
|---|---|---|
| Attested key release | Verdict only; no key could reach an enclave | `POST /confidential/release`: verified evidence must commit to the enclave's RSA key (Nitro `public_key`, or OIDC nonce = base64url(SHA-256(DER))); keycore (`POST /keys/{id}/attested-release`, kms-confidential only) seals the active exportable key to it with RSA-OAEP-256 + AES-256-GCM |

## Still open

- **DKE key rotation**: DKE decrypts only with the key's current version
  (keycore decrypts with the current version), so a document wrapped under an
  older version cannot be opened after the key rotates. Decrypting with a
  named version needs keycore support.
- **DKE and CSE on sovereign clouds**: Entra verification covers the public
  cloud issuers only (`sts.windows.net`, `login.microsoftonline.com`), and CSE
  authentication tokens must be Google ID tokens (no third-party IdP yet).
- **JCA provider on Oracle JDK**: it runs on OpenJDK builds; Oracle JDK needs
  the jar signed with an Oracle JCE code-signing certificate, which Vecta does
  not have.
- **Doc request bodies**: `scripts/check-doc-routes.py` proves every
  documented route exists, not that every documented request or response
  field matches the handler. Tables that give paths relative to a base
  (without `/svc/`) are not checked either.
- **OpenAPI schemas**: `check-doc-routes.py` checks that every operation in
  `docs/openapi/` is a registered route, not that its parameters, request
  body or response schema match the handler.
- **Tenant and actor from the request** (found while checking the specs):
  legacy posture routes accept tokenless requests and default the tenant to
  all tenants on the dashboard, risk and scan routes; `POST /cbom/generate`
  and `POST /reports/generate` take `tenant_id` from the body without the
  tenant check; posture action execution and report deletion take the actor
  from the body, a query parameter or `X-Actor-ID`. These routes are on the
  route-kernel burn-down list and are fixed by moving them onto `pkg/route`.
