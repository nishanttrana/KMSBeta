# Identity, Confidential Computing, and Post-Quantum Cryptography

**Vecta KMS Technical Reference**

This guide covers four capability areas and what each one actually does:

1. **Workload identity** (`workload`): SPIFFE SVIDs issued by a per-tenant
   CA, and the exchange of an SVID for a scoped KMS access token.
2. **Attested key release** (`confidential`): a key is released, sealed to
   an enclave's key, only on cryptographically verified TEE evidence.
3. **Key access justifications** (`keyaccess`): a reason code gate on EKM,
   cloud BYOK and HYOK key operations.
4. **Post-quantum cryptography** (`keycore`, `pqc`): ML-KEM, ML-DSA and
   SLH-DSA keys, hybrid TLS key exchange, and the readiness and migration
   tooling.

Section 5 points to the AI gateway, and Section 6 walks through use cases
built only from the routes below.

Every claim was checked against the code in 6.6.0-beta, following each one
to the route that serves it. What this page used to describe that doesn't
exist is listed under [Removed claims](#removed-claims-660-beta). What is
real but has a known gap is under [Open items](#open-items).

All examples go through the gateway (`https://localhost`) with a bearer
token. `$TOKEN` holds it; never paste a token into a command line.

---

## Table of Contents

- [Section 1: Workload identity](#section-1-workload-identity)
- [Section 2: Attested key release](#section-2-attested-key-release)
- [Section 3: Key access justifications](#section-3-key-access-justifications)
- [Section 4: Post-quantum cryptography](#section-4-post-quantum-cryptography)
- [Section 5: AI gateway](#section-5-ai-gateway)
- [Section 6: Use cases](#section-6-use-cases)
- [Open items](#open-items)
- [Removed claims (6.6.0-beta)](#removed-claims-660-beta)

---

## Section 1: Workload identity

### Background: SPIFFE

A SPIFFE ID names a workload as a URI, `spiffe://{trust-domain}/{path}`. The
ID isn't a secret; the proof is a SPIFFE Verifiable Identity Document (SVID),
either an X.509 certificate carrying the ID as a URI SAN or a signed JWT
whose `sub` is the ID. SVIDs are short-lived, so a leaked one expires on its
own.

### What the workload service does

The `workload` service (`/svc/workload/workload-identity/...`) is a SPIFFE
issuer and verifier for one trust domain per tenant. It:

1. **Creates the tenant's signing material** the first time the tenant's
   settings are read: an RSA-2048 root CA certificate (10-year validity) for
   X.509 SVIDs and a separate RSA-2048 key for JWT SVIDs, with its JWKS.
   Both come from `pkg/crypto`. The two private keys are sealed together,
   one envelope per tenant, under the workload service master key from
   keycore (`pkg/mek`, 6.11.0-beta); see
   [Signing keys at rest](#signing-keys-at-rest).
2. **Keeps registrations**: a SPIFFE ID in the tenant's trust domain, with
   the interfaces, key IDs and permissions that ID may be granted.
3. **Issues SVIDs** for a registration, to a caller whose KMS token holds
   `workload.issue`. **The service does not attest the workload.**
   `selectors` on a registration are stored and shown, never checked.
4. **Verifies SVIDs**, its own or those of a federated trust domain whose
   bundle you added, and **exchanges** a verified SVID for a KMS access
   token scoped to the registration's permissions and key IDs.
5. **Reports** issuances, key usage by workload, and an authorization graph.

There is no agent, no Workload API socket, and no Kubernetes, cloud, Docker,
Unix or TPM attestor. A workload gets its SVID from whatever deploys it,
using a token that holds `workload.issue`.

**Access (6.9.0-beta).** Every route goes through the `pkg/route` kernel.
The tenant is the verified token's, and each call emits
`audit.workload.<action>`, refusals included. `workload.read` covers the
reads, `workload.write` settings, registrations and federation, and
`workload.issue` issuance. The token exchange is the one route without a
bearer token: the workload's SVID is its credential (see
[Token exchange](#token-exchange)).

### Tenant settings

`GET` / `PUT /svc/workload/workload-identity/settings` (response key
`settings`):

| Field | Default | Effect |
|---|---|---|
| `enabled` | `false` | Token exchange is refused (`409`) while false. Issuance doesn't check it. |
| `trust_domain` | the tenant ID | Every registration's SPIFFE ID must be in this domain. |
| `token_exchange_enabled` | `true` | Token exchange is refused (`409`) while false. |
| `federation_enabled` | `false` | Federated bundles verify SVIDs only while it is on (6.9.0-beta; before, they were used either way). |
| `default_x509_ttl_seconds` | 43200 (12 h) | Lifetime of an X.509 SVID when the request names none. Values under 300 fall back to the default. |
| `default_jwt_ttl_seconds` | 1800 (30 min) | Lifetime of a JWT SVID when the request names none, and the upper bound of an exchanged KMS token. Values under 120 fall back to the default. |
| `rotation_window_seconds` | 1800 | `rotation_due_at` = expiry minus this window. |
| `allowed_audiences` | `kms`, `kms-workload`, `kms-rest` | Audiences put in a JWT SVID when the request names none, and the only audiences a JWT-SVID exchange accepts. An empty list accepts none. |

`disable_static_api_keys` and the `rotation_alert_*` settings were removed
in 6.9.0-beta: nothing acted on them.

The response also carries `local_ca_certificate_pem`, `local_bundle_jwks`
and `jwt_signer_key_id`. The private keys are never returned.

### Signing keys at rest

The root CA private key and the JWT-SVID signer private key are stored as
one AES-256-GCM envelope per tenant (`signing_*` columns of
`workload_identity_settings`): a random data key per row, wrapped by the
workload service master key, which keycore derives for the verified
`kms-workload-identity` identity
([SERVICE_MASTER_KEYS.md](SECURITY/SERVICE_MASTER_KEYS.md)). The sealed
payload names its tenant, so an envelope copied onto another tenant's row
doesn't open. The service doesn't start without the key.

Before 6.11.0-beta both keys were plaintext PEM (`local_ca_key_pem`,
`jwt_signer_private_pem`). On start, and every 15 minutes, the primary seals
each such row, records the tenant in the exposure register
(`source: plaintext_storage`, `audit.workload.mek_exposure_recorded`), empties
the plaintext columns and emits `audit.workload.mek_signing_keys_sealed`. A
row it can't seal is left as it was and reported as
`mek_signing_keys_seal_refused`; the first pass failing stops the start.
Cluster members only read. Governance won't capture a backup while a
plaintext row remains.

A database copy or backup made before the upgrade still holds the old keys,
so rotate them:

```bash
curl -sk -X POST https://localhost/svc/workload/workload-identity/settings/rotate-signing-keys \
  -H "Authorization: Bearer $TOKEN"
```

This needs `workload.write`. It replaces both keys in the same trust domain
(`audit.workload.signing_keys_rotated`) and closes the tenant's exposure
entry. SVIDs issued under the old keys stop verifying, so workloads fetch
new ones and federated trust domains need the new JWKS. Changing
`trust_domain` also replaces both keys. The dashboard has the same action
(Workload Identity → Rotate Signing Keys).

### Registrations

`GET` / `POST /svc/workload/workload-identity/registrations`,
`PUT` / `DELETE .../registrations/{id}` (response key `registration`):

| Field | Default | Meaning |
|---|---|---|
| `name` | | Display name |
| `spiffe_id` | `spiffe://{trust_domain}/workloads/{slug of name}` | Must start with `spiffe://` and be in the tenant's trust domain |
| `selectors` | | Free-form labels. Recorded only |
| `allowed_interfaces` | `["rest"]` | Interfaces the exchanged token may be used on (`*` for any) |
| `allowed_key_ids` | none | Keys the exchanged token may use. Empty means the token isn't key-scoped (flagged as over-privileged in the graph) |
| `permissions` | `key.encrypt`, `key.decrypt` | `encrypt`, `decrypt`, `wrap`, `unwrap`, `sign`, `verify`, `mac`, `derive`, `export` (stored as `key.<op>`), or `key.*` |
| `issue_x509_svid`, `issue_jwt_svid` | JWT only | Which SVID types may be issued |
| `default_ttl_seconds` | tenant JWT TTL | Stored with the registration |
| `enabled` | | A disabled registration can't be issued or exchanged |

```bash
curl -sk -X POST https://localhost/svc/workload/workload-identity/registrations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "orders-service",
    "spiffe_id": "spiffe://root/ns/prod/sa/orders-service",
    "allowed_interfaces": ["rest"],
    "allowed_key_ids": ["<key-id>"],
    "permissions": ["encrypt", "decrypt"],
    "issue_jwt_svid": true,
    "enabled": true
  }'
```

### Issuing an SVID

`POST /svc/workload/workload-identity/issue` with `registration_id` (or
`spiffe_id`), `svid_type` (`x509` or `jwt`), and optionally `audiences` and
`ttl_seconds`. The response key is `issued`.

- **X.509:** the service generates the workload's RSA-2048 key pair, signs a
  certificate with the SPIFFE ID as URI SAN, key usage `digitalSignature` and
  `keyEncipherment`, and extended key usage `clientAuth` only, and returns
  `certificate_pem`, **`private_key_pem`** and `bundle_pem`. The private key
  is created by the KMS and travels in the response; protect that response
  like any other secret.
- **JWT:** an RS256 token with `iss` = `spiffe://{trust_domain}`, `sub` and
  `spiffe_id` = the SPIFFE ID, `aud`, `iat`, `nbf`, `exp` and
  `trust_domain`, plus the tenant `jwks_json`.

Each issuance is recorded (`GET .../issuances`) with a hash of the document,
and audited as `audit.workload.svid_issued`.

### Federation bundles

`GET` / `POST .../federation`, `PUT` / `DELETE .../federation/{id}` hold
another trust domain's `jwks_json` and/or `ca_bundle_pem`. While
`federation_enabled` is on, they verify that domain's SVIDs during token
exchange. `bundle_endpoint` is stored; the service doesn't fetch it.

### Token exchange

`POST /svc/workload/workload-identity/token/exchange` takes `tenant_id`, one
SVID, `interface_name`, and optionally `registration_id`,
`requested_permissions` and `requested_key_ids`. It is **not** an OAuth 2.0
RFC 8693 endpoint and takes no `grant_type` / `subject_token`.

**How it authenticates (6.9.0-beta).** The route needs no bearer token: a
workload holding only an SVID must be able to call it, so the SVID is the
credential ([DECISIONS.md](DECISIONS.md), 2026-09-29). `tenant_id` only
selects whose trust anchors verify it. A request that does carry a bearer
token must name the token's tenant.

- **JWT-SVID** (`jwt_svid`): RS256 signature against the tenant's JWT
  signer, or a federated JWKS while federation is on; expiry; and an
  audience the tenant allows. An `audience` sent with the request must be
  in `allowed_audiences`; without one, the SVID's `aud` must include an
  allowed audience. A JWT-SVID minted for another relying party can't buy a
  KMS token by naming its audience.
- **X.509-SVID** (`x509_svid_chain_pem`): the chain must verify to the
  tenant CA (or a federated bundle) with `clientAuth`. A certificate chain
  is public, so it also needs `x509_svid_proof`: `signed_at` (RFC 3339 UTC)
  and `signature`, made with the SVID's private key over

  ```
  vecta-kms/workload-token-exchange/v1
  tenant=<tenant_id>
  leaf-sha256=<lowercase hex SHA-256 of the leaf certificate DER>
  signed-at=<signed_at as sent>
  ```

  with RSA PKCS#1 v1.5 or PSS / SHA-256, ECDSA / SHA-256, or Ed25519.
  `signed_at` must be within two minutes of the server's clock, and each
  signature is accepted once (cluster members forward the exchange to the
  primary, which remembers accepted proofs in memory). The dashboard signs it in the
  browser for an SVID it has just issued. For example, with OpenSSL:

  ```bash
  AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  LEAF=$(openssl x509 -in svid.pem -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1)
  printf 'vecta-kms/workload-token-exchange/v1\ntenant=%s\nleaf-sha256=%s\nsigned-at=%s' root "$LEAF" "$AT" \
    | openssl dgst -sha256 -sign svid-key.pem | base64 | tr -d '\n'
  ```

The service then finds the registration for the verified SPIFFE ID. A
`registration_id` may name only that SVID's own registration (403
`svid_registration_mismatch` otherwise). It checks the interface and
intersects the requested permissions and keys with the registration's. It
then asks auth (`POST /auth/workload-token`) for a KMS access token whose
client is the registration and which carries those permissions,
`allowed_key_ids` and the trust domain. The token lives no longer than the
SVID or the tenant JWT TTL, whichever is shorter. The response key is
`exchange`. The exchange, and every refusal with its reason, is audited as
`audit.workload.token_exchanged`, with the verified SPIFFE ID as the actor.

Keycore enforces the token's `allowed_key_ids`: a key outside the list is
refused and hidden from listings.

### Reporting routes

| Route | Returns |
|---|---|
| `GET .../summary` | Registration, issuance, exchange and key-use counts over 24 h; expiring and expired SVIDs; over-privileged registrations. `key_usage_unavailable` says why the key-use counts are missing |
| `GET .../graph` | Nodes (`workload:`, `key:`) and edges: `policy` from a registration's `allowed_key_ids`, `usage` from recorded key use. Audited as `audit.workload.graph_viewed` |
| `GET .../usage` | Key operations performed with workload tokens, read from the audit log with the caller's own token (502 `audit_unavailable` if it can't be read) |
| `GET .../issuances` | Issuance history |

Using a JWT SVID with AWS STS, GCP STS or Azure AD federation is **not
supported**. Those services require an HTTPS issuer with OIDC discovery,
and the SVID's issuer is `spiffe://...` with no discovery document.

---

## Section 2: Attested key release

### Background

A trusted execution environment (TEE) runs code in hardware-isolated,
encrypted memory and can produce signed evidence of what it is running. An
attested key release gives a key only to a TEE whose evidence verifies and
matches policy, sealed so that only that TEE can open it.

### What the confidential service verifies

`confidential` (`/svc/confidential/confidential/...`) verifies evidence from
three providers. Anything else is `generic`: it is recorded, and never
allowed.

| `provider` | Evidence (`attestation_document`) | Verification |
|---|---|---|
| `aws_nitro_enclaves`, `aws_nitro_tpm` | Base64 CBOR COSE_Sign1 attestation document | COSE ECDSA signature by the document's certificate; the certificate chain to the AWS Nitro root pinned in the service (more roots: `CONFIDENTIAL_AWS_ROOT_PEM_PATH`). PCRs become measurements `pcr0`, `pcr1`, …; `nonce`, `public_key` and a JSON `user_data` (claims, measurements, workload identity, image) are read from the verified document. |
| `azure_secure_key_release` | Microsoft Azure Attestation (MAA) JWT | Issuer host must be under `attest.azure.net`; OIDC discovery, then the RS256 signature against the issuer's JWKS; `nonce` / `eat_nonce`, `x-ms-sevsnpvm-launchmeasurement` and similar claims become measurements. |
| `gcp_confidential_space` | Confidential Space JWT | Issuer must be `https://confidentialcomputing.googleapis.com`; OIDC discovery and JWKS, RS256. |

Raw Intel TDX quotes, raw AMD SEV-SNP reports (VCEK, AMD KDS) and SGX quotes
are **not verified**. Azure Confidential VMs are supported only through
their MAA token.

### The tenant policy

One attestation policy per tenant: `GET` / `PUT
/svc/confidential/confidential/policy` (response key `policy`).

| Field | Default | Effect |
|---|---|---|
| `enabled` | `false` | Every evaluation is refused while false |
| `provider` | `aws_nitro_enclaves` | Evidence from another provider is refused. A `generic` policy accepts any provider, but generic evidence itself is never allowed |
| `mode` | `enforce` | `monitor` turns a failing evaluation into `review` instead of the fallback action. Neither releases a key |
| `fallback_action` | `deny` | `deny` or `review` for a failing evaluation in `enforce` mode |
| `key_scopes` | any | Key IDs or scopes that may be released |
| `approved_images` | any | Image refs or digests the evidence must name |
| `approved_subjects` | any | Workload identities the evidence must name |
| `allowed_attesters` | any | Evidence issuers accepted |
| `required_measurements` | `pcr0`, `pcr8` (empty values are ignored) | Each named measurement must equal the value |
| `required_claims` | none | Each named claim must equal the value |
| `require_secure_boot`, `require_debug_disabled` | `true` | Evidence must show secure boot / debug disabled (Nitro always does) |
| `max_evidence_age_sec` | 300 (max 86400) | Evidence older than this, or more than 5 minutes in the future, is refused |
| `cluster_scope`, `allowed_cluster_nodes` | `cluster_wide` | `node_allowlist` limits evaluation to named nodes |

### Freshness and nonces

The service doesn't issue nonces. Freshness is the evidence's own timestamp
against `max_evidence_age_sec`. If the request carries a `nonce`, the nonce
inside the verified evidence must equal it. For a release, the nonce is how
OIDC evidence binds the recipient key (below).

### Evaluate and release

- `POST /svc/confidential/confidential/evaluate` returns the verdict
  (`result`: `decision` `allow` / `deny` / `review`, `reasons`, matched and
  missing claims and measurements, `cryptographically_verified`,
  `attestation_document_hash`) and records it unless `dry_run`. No key
  material moves. Needs `confidential.evaluate`; the recorded requester is
  the verified caller. Audited as `audit.confidential.key_release_evaluated`.
- `POST /svc/confidential/confidential/release` (permission
  `confidential.release`, through the `pkg/route` kernel) evaluates the
  same way. On `allow` it has keycore release the key. It needs
  `recipient_public_key`, the enclave's RSA key (2048 to 8192 bits) as base64
  DER SubjectPublicKeyInfo, which the verified evidence must commit to:
  - **Nitro:** the document's signed `public_key` must equal it.
  - **MAA / Confidential Space:** the token's `nonce` must equal
    base64url(SHA-256(DER)).

  Keycore (`POST /keys/{id}/attested-release`, callable only by the
  confidential service) then requires the key to be active and
  `export_allowed`, applies the FIPS algorithm check and the policy engine,
  and seals the current version to the recipient key with
  **`RSA-OAEP-256+A256GCM`**: a fresh AES-256 key wrapped with RSA-OAEP-256,
  and the key material encrypted under it with AES-256-GCM. The AAD
  `vecta-attested-release|{tenant}|{key}|{version}|{release_id}` binds the
  result to that release. The response (`decision.release`) holds
  `wrapped_key`, `nonce`, `ciphertext`, `aad`, `seal_algorithm`, `version`
  and `kcv`. A refusal is `403 release_refused` with the reasons.
  Outcomes are audited as `audit.confidential.key_released` or
  `audit.confidential.key_release_refused`, and by the kernel as
  `audit.confidential.key_release`.

The enclave opens the release with its private key: RSA-OAEP (SHA-256,
label `vecta-kms recipient seal v1`) to recover the AES key, then
AES-256-GCM with the given nonce and AAD.

### History

`GET .../releases?limit=` (default 100) and `GET .../releases/{id}` return
recorded evaluations and releases. `GET .../summary` returns 24 h counts.
These and `GET .../policy` need `confidential.read`; `PUT .../policy` needs
`confidential.write`. Since 6.9.0-beta every confidential route is on the
`pkg/route` kernel, with the tenant from the verified token.

---

## Section 3: Key access justifications

### What it does

The `keyaccess` service decides whether a key operation performed **by
another service on a caller's behalf** may proceed, based on a justification
code the caller supplies. It is consulted by exactly these operations:

| Service | Operations | Caller supplies |
|---|---|---|
| `ekm` (TDE) | `wrap`, `unwrap`, `rotate` | `justification_code`, `justification_text` in the EKM request |
| `cloud` (BYOK) | `import`, `rotate`, `sync` | same fields in the cloud request |
| `hyok` | each proxied operation (connector = protocol) | same fields in the HYOK request; skipped when a governance approval already covers the request |

**Keycore's own routes (`/keys/{id}/encrypt`, `decrypt`, `wrap`, `unwrap`,
`sign`, `export`, …) don't consult it**, and no header carries a
justification. To require a reason for direct keycore use, use key access
grants (a grant's `justification` and `ticket_id` are recorded) and
governance approvals ([KEY_ACCESS_MODEL.md](SECURITY/KEY_ACCESS_MODEL.md)).

### Settings

`GET` / `PUT /svc/keyaccess/key-access/settings` (response key `settings`):

| Field | Default | Effect |
|---|---|---|
| `enabled` | `false` | While false every evaluation is allowed and recorded |
| `mode` | `enforce` | `audit` allows a violating request and records `bypass_detected` |
| `default_action` | `deny` | `allow`, `deny` or `approval`, for a request that matches no rule |
| `require_justification_code` | `true` | A request without a code is a violation |
| `require_justification_text` | `false` | A request without text is a violation |
| `approval_policy_id` | | Governance approval policy for the `approval` action |

### Rules ("codes")

A rule is one justification code and what it permits.
`GET` / `POST /svc/keyaccess/key-access/codes`,
`PUT` / `DELETE .../codes/{id}` (response key `rule`):

| Field | Meaning |
|---|---|
| `code` | The code callers send (upper-cased). There are no built-in codes: the tenant defines every one |
| `label`, `description` | Display |
| `action` | `allow`, `deny` or `approval` when this code is presented |
| `services` | Services the code is valid for (`ekm`, `cloud`, `hyok`); empty = any |
| `operations` | Operations the code is valid for; empty = any |
| `require_text` | Justification text required with this code |
| `approval_policy_id` | Overrides the tenant approval policy |
| `enabled` | Disabled rules don't match |

### Evaluation

For each request: a missing code (when required), an unknown code, a code
used outside its `services` / `operations`, or missing required text is a
violation. In `enforce` mode the result is the matched rule's `action` (or
`default_action` when no rule matched), with the violation as the reason; in
`audit` mode a violation is allowed with `bypass_detected`. `approval`
creates a governance approval request (`external_key_access`); with no
approval policy or governance unavailable, the request is denied.

Every decision is stored (`GET .../decisions?service=&action=&limit=`) and
audited as `audit.keyaccess.decision_evaluated`, with `approval_required`
and `approval_request_id` when an approval is opened.
`GET .../summary` returns 24 h counts per service.

**Who may ask (6.9.0-beta).** `POST /key-access/evaluate` answers only the
`kms-ekm`, `kms-cloud` and `kms-hyok-proxy` service identities, each for its
own service name; a tenant administrator, another service, or an evaluator
naming another service is refused (`evaluator_identity_required`,
`service_mismatch`) and audited. The tenant comes from the request, which a
service identity may name. The other routes need `keyaccess.read` or
`keyaccess.write` and a token for the tenant. Before 6.9.0-beta
`pkg/keyaccess` sent no token, so every evaluation got 401 and ekm and cloud
treated it as "service unavailable".

**When keyaccess isn't there (6.10.0-beta).** ekm, cloud and hyok read the
deployment's profiles from `VECTA_DEPLOYED_PROFILES`, which
`docker-compose.yml` sets from `COMPOSE_PROFILES` (derived from
`infra/deployment/deployment.yaml` by the installers and `start-kms`):

| Deployment | Result |
|---|---|
| `key_access_justifications` profile off | The operation runs; its success event carries `key_access_reason: key_access_not_deployed` |
| Profile on, or the profile list unset or empty (unknown) | keyaccess decides. If it can't be reached, answers an error, or returns no action, the operation is refused with `424 key_access_unavailable` and audited with `result: refused` and `reason: key_access_unavailable` (`audit.ekm.key_access_denied`, `audit.cloud.key_access_denied`, `audit.hyok.request_denied`) |

A failure is never turned into an allow. HYOK's policy-engine check fails
closed too (`424 policy_unavailable`); `HYOK_POLICY_FAIL_CLOSED` was removed in
6.20.0-beta. Each
service logs `key access justifications deployed=<bool>` at start. Adding the
profile only with `docker compose --profile` on the command line, not in
`COMPOSE_PROFILES`, leaves the callers treating it as not deployed: enable
features in `deployment.yaml`.

---

## Section 4: Post-quantum cryptography

### Background

Shor's algorithm, on a large enough quantum computer, breaks RSA and
elliptic-curve cryptography (RSA, DSA, ECDSA, ECDH, EdDSA, X25519). Grover's
algorithm gives a square-root speedup against symmetric ciphers and hashes,
so AES-256 keeps about 128 bits of security against it. Data encrypted today
under a quantum-vulnerable key exchange can be recorded and decrypted later
("harvest now, decrypt later").

The product states these properties per algorithm (strength, post-quantum
category, quantum-vulnerable, weak) from `pkg/cryptocatalog`. When and what
to migrate is the customer's decision, set in their own Crypto Agility
policy ([ALGORITHM_TRANSITIONS.md](SECURITY/ALGORITHM_TRANSITIONS.md)).

### Sizes

ML-KEM (FIPS 203), in bytes:

| Parameter set | Category | Encapsulation key | Decapsulation key | Ciphertext | Keycore generates |
|---|---|---|---|---|---|
| ML-KEM-512 | 1 | 800 | 1632 | 768 | no |
| ML-KEM-768 | 3 | 1184 | 2400 | 1088 | yes |
| ML-KEM-1024 | 5 | 1568 | 3168 | 1568 | yes |

ML-DSA (FIPS 204), in bytes:

| Parameter set | Category | Public key | Private key | Signature | Keycore generates |
|---|---|---|---|---|---|
| ML-DSA-44 | 2 | 1312 | 2560 | 2420 | no |
| ML-DSA-65 | 3 | 1952 | 4032 | 3309 | yes |
| ML-DSA-87 | 5 | 2592 | 4896 | 4627 | yes |

SLH-DSA (FIPS 205), SHA2 and SHAKE variants alike, in bytes. `s` sets have
smaller signatures and slower signing; `f` sets are the reverse:

| Parameter set | Category | Public key | Signature |
|---|---|---|---|
| SLH-DSA-*-128s | 1 | 32 | 7856 |
| SLH-DSA-*-128f | 1 | 32 | 17088 |
| SLH-DSA-*-192s | 3 | 48 | 16224 |
| SLH-DSA-*-192f | 3 | 48 | 35664 |
| SLH-DSA-*-256s | 5 | 64 | 29792 |
| SLH-DSA-*-256f | 5 | 64 | 49856 |

Keycore generates all twelve SLH-DSA parameter sets.

### PQC keys in keycore

`POST /svc/keycore/keys` creates:

- **ML-KEM-768, ML-KEM-1024** with Go's `crypto/mlkem`, inside the certified
  FIPS 140-3 module.
- **ML-DSA-65, ML-DSA-87** and **SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}**
  with `github.com/cloudflare/circl`, **outside** the certified module. They
  are listed in the FIPS impact catalogue, and in FIPS mode `only` keycore
  refuses them with `fips_mode_violation`
  ([FIPS.md](SECURITY/FIPS.md)).

Keycore refuses, with `400 algorithm_unsupported` and
`audit.key.create_refused`:

- any name containing `+` (hybrid or composite keys, for example
  `X25519+ML-KEM-768`). Create each component key instead;
- XMSS, LMS and HSS (stateful hash-based signatures);
- Ed448 and X448.

The operations on them:

| Key | Route | Request | Response |
|---|---|---|---|
| ML-KEM | `POST /svc/keycore/keys/{id}/kem/encapsulate` | `algorithm` (optional, must match), `aad`, `reference_id` | `shared_secret`, `encapsulated_key` (base64) |
| ML-KEM | `POST /svc/keycore/keys/{id}/kem/decapsulate` | `encapsulated_key`, `algorithm`, `aad` | `shared_secret` |
| ML-DSA, SLH-DSA | `POST /svc/keycore/keys/{id}/sign` | `data` (base64) | signature |
| ML-DSA, SLH-DSA | `POST /svc/keycore/keys/{id}/verify` | `data`, `signature` | result |

`/keys/{id}/wrap` wraps with a key whose purpose includes `wrap`. It doesn't
use an ML-KEM key; to protect a data key under ML-KEM, encapsulate, derive a
key from the shared secret (HKDF-SHA256), and encrypt under that
([Use case 5](#use-case-5-protecting-a-data-key-under-ml-kem)).

A PQC key's check value is the `sha256-material` KCV keycore gives every
non-symmetric key.

### Hybrid: where it exists

- **TLS key exchange is hybrid.** Internal mTLS offers `X25519MLKEM768`,
  `SecP256r1MLKEM768` and `SecP384r1MLKEM1024`, with a per-service profile
  set in the dashboard: `pqc-required`, `pqc-preferred` (default) or
  `classical` ([INTERNAL_TLS.md](SECURITY/INTERNAL_TLS.md)). External
  listeners follow `VECTA_TLS_PQ_PROFILE` (hybrid groups first by default).
- **Keys aren't.** There are no composite keys, as above.
- **Certificates aren't.** `certs` refuses ML-DSA, SLH-DSA, LMS/XMSS and
  hybrid certificates: the certified Go module has no ML-DSA, and Go's TLS
  can't present an ML-DSA certificate. Certificate signatures are classical.

### Readiness and migration (`pqc`)

All routes go through the `pkg/route` kernel (read: `pqc.read`, write:
`pqc.write`):

| Route | What it does |
|---|---|
| `GET /svc/pqc/pqc/inventory` | Counts the tenant's keys (from keycore) and certificates (from certs) as classical, hybrid or PQC-only by their algorithm, and lists the classical ones. `interfaces` is always `not_assessed`. No score |
| `POST /svc/pqc/pqc/scan` | Takes a readiness scan: collects keys, certificates and discovered assets, classifies each algorithm from `pkg/cryptocatalog`, and records risk items with a migration target |
| `GET /svc/pqc/pqc/scans`, `.../scans/{id}`, `.../readiness` | Scan history and the latest scan: `total_assets`, `pqc_ready_assets`, `hybrid_assets`, `classical_assets`, `algorithm_summary`, `risk_items` |
| `POST /svc/pqc/pqc/migration/plans` | Builds a plan from the latest scan's risk items. Body: `name`, `target_profile`, and your own `deadline` (optional; the product sets none) |
| `GET .../migration/plans`, `.../plans/{id}`, `.../plans/{id}/runs` | Plans and their runs |
| `POST .../plans/{id}/execute` | For each key step, keycore creates a successor key in the target algorithm (labelled `pqc_successor_of`), or rotates the key when the target is its own algorithm. The old key isn't changed; move data to the successor, then retire the old key. Certificate, TLS and other non-key steps are manual and marked so. `dry_run` records without acting |
| `POST .../plans/{id}/rollback` | Deactivates the successor keys the plan created and marks its steps and the plan rolled back (`partially_rolled_back` if a deactivation fails) |
| `GET .../migration/report` | Inventory, latest scan, your plans' deadlines, and top risk items |
| `GET .../timeline` | Your plans with a deadline, and how many steps of each are open |
| `GET .../cbom/export` | The cryptographic bill of materials |

A migration target is always something keycore can generate: ML-KEM-768
for key establishment, ML-DSA-65 for signatures and for RSA/EC keys whose use
isn't recorded, AES-256 for weak symmetric keys. TLS endpoints get
`X25519MLKEM768` as a manual step.

To stop new quantum-vulnerable protection from a date you choose, add a
Crypto Agility migration rule. Keycore enforces it on every key operation
and audits refusals as `audit.key.crypto_policy_refused`:

```bash
curl -sk -X POST https://localhost/svc/keycore/agility/policy/rules \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name": "No new quantum-vulnerable protection",
       "match_kind": "quantum_vulnerable", "action": "decrypt_only",
       "effective_date": "2027-01-01"}'
```

---

## Section 5: AI gateway

There is no `/svc/ai` service. AI traffic goes through the AI gateway
(`/svc/ai-gateway/ai-gateway/v1/...`): chat and completion proxying with DLP
scanning, redaction and guardrails (`POST .../v1/chat/completions`,
`.../v1/scan`, `.../v1/redact`, `.../v1/evaluate`), plus model, policy,
guardrail, access-rule and budget administration. See the route index in
[API_REFERENCE.md](API_REFERENCE.md#appendix-route-index-generated).

---

## Section 6: Use cases

Each use case uses only the routes above.

### Use case 1: A workload uses a scoped token instead of a static credential

1. Enable workload identity and set the trust domain (`PUT .../settings`
   with `"enabled": true, "trust_domain": "root"`).
2. Register the workload with the keys and operations it needs (the
   registration example in Section 1).
3. Your deployment tooling, holding an operator token, issues a JWT SVID
   for the registration and hands it to the workload:

   ```bash
   curl -sk -X POST https://localhost/svc/workload/workload-identity/issue \
     -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" \
     -H "Content-Type: application/json" \
     -d '{"tenant_id": "root", "registration_id": "<registration-id>",
          "svid_type": "jwt", "audiences": ["kms"]}'
   ```

4. The workload exchanges the SVID for a KMS token. It holds no long-lived
   KMS credential; the SVID and the token both expire (30 minutes by
   default). Pass the SVID from a file, not the command line:

   ```bash
   jq -n --rawfile svid /run/secrets/svid.jwt \
     '{tenant_id: "root", jwt_svid: ($svid | rtrimstr("\n")), audience: "kms",
       interface_name: "rest", requested_permissions: ["decrypt"]}' |
   curl -sk -X POST https://localhost/svc/workload/workload-identity/token/exchange \
     -H "X-Tenant-ID: root" -H "Content-Type: application/json" --data-binary @-
   ```

5. The workload calls keycore with `exchange.kms_access_token`. Keycore
   refuses any key outside the registration's `allowed_key_ids`. The graph
   (`GET .../graph`) shows the workload, its authorized keys and its actual
   use.

Re-issuing the SVID before `rotation_due_at` is up to your tooling; there's
no agent to do it.

### Use case 2: Release a model key only to a verified Nitro enclave

1. Create the key with `"export_allowed": true` (release needs it).
2. Set the tenant policy to the enclave image:

   ```bash
   curl -sk -X PUT https://localhost/svc/confidential/confidential/policy \
     -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" \
     -H "Content-Type: application/json" \
     -d '{"tenant_id": "root", "enabled": true, "provider": "aws_nitro_enclaves",
          "mode": "enforce", "key_scopes": ["<key-id>"],
          "required_measurements": {"pcr0": "<expected PCR0 hex>"},
          "max_evidence_age_sec": 300}'
   ```

3. Inside the enclave: generate an RSA-3072 key pair, request an attestation
   document from the NSM with `public_key` = the public key's DER, and send
   it with the same DER:

   ```json
   POST /svc/confidential/confidential/release
   {"key_id": "<key-id>", "provider": "aws_nitro_enclaves",
    "attestation_document": "<base64 COSE_Sign1>",
    "recipient_public_key": "<base64 DER SubjectPublicKeyInfo>",
    "release_reason": "model load"}
   ```

4. Open `decision.release`: RSA-OAEP-SHA256-decrypt `wrapped_key` (label
   `vecta-kms recipient seal v1`) to get the AES-256 key, then
   AES-256-GCM-decrypt `ciphertext` with `nonce` and `aad`.
5. Review `GET .../releases`. Evidence from another image fails the `pcr0`
   check. A document whose `public_key` isn't the recipient key fails the
   binding. Both are recorded and audited as refusals.

For Azure (MAA) or GCP Confidential Space, set `provider` accordingly and
put base64url(SHA-256(DER of the recipient key)) in the token's nonce when
requesting it from the attestation service.

### Use case 3: Require a reason for TDE key unwrap and HYOK operations

1. Define the codes your organisation uses, for example:

   ```bash
   curl -sk -X POST https://localhost/svc/keyaccess/key-access/codes \
     -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" \
     -H "Content-Type: application/json" \
     -d '{"tenant_id": "root", "code": "DB_STARTUP", "label": "Database start",
          "action": "allow", "services": ["ekm"], "operations": ["unwrap"],
          "enabled": true}'
   ```

   Add an `approval` code (with an `approval_policy_id`) for emergency access.
2. Enable enforcement: `PUT .../settings` with `"enabled": true,
   "mode": "enforce", "default_action": "deny",
   "require_justification_code": true`.
3. EKM, cloud and HYOK callers send `justification_code` (and
   `justification_text` where required) in their requests. Requests without
   an accepted code are refused.
4. Review `GET .../decisions?service=ekm` and the
   `audit.keyaccess.decision_evaluated` events. An evidence pack
   (`POST /svc/reporting/reports/generate` with
   `"template_id": "evidence_pack"`) collects approvals, alerts and actions
   for a period.

This gate doesn't cover direct keycore calls (Section 3).

### Use case 4: A post-quantum signing key

1. Create it:

   ```bash
   curl -sk -X POST https://localhost/svc/keycore/keys \
     -H "Authorization: Bearer $TOKEN" -H "X-Tenant-ID: root" \
     -H "Content-Type: application/json" \
     -d '{"name": "release-signing-mldsa87", "algorithm": "ML-DSA-87",
          "key_type": "asymmetric-private", "purpose": "sign-verify"}'
   ```

2. Sign with `POST /svc/keycore/keys/{id}/sign` (`{"data": "<base64>"}`),
   verify with `.../verify`.
3. In FIPS mode `only` keycore refuses to create or use ML-DSA and SLH-DSA
   keys. They run outside the certified module.

An ML-DSA or hybrid **CA certificate** can't be issued: `certs` refuses
them. To keep a classical CA and add PQC signatures, sign artifacts with
both a classical key and an ML-DSA key and have verifiers check both. That
is two keys and two signatures, not a composite key.

### Use case 5: Protecting a data key under ML-KEM

1. Create an ML-KEM-1024 key (`"algorithm": "ML-KEM-1024",
   "key_type": "asymmetric-private", "purpose": "key-encapsulation"`).
2. Encapsulate: `POST /svc/keycore/keys/{id}/kem/encapsulate` returns
   `shared_secret` and `encapsulated_key`.
3. Derive a key-encryption key from `shared_secret` with HKDF-SHA256, wrap
   your data key with AES-256-GCM, and store `encapsulated_key` with the
   ciphertext. Discard the shared secret.
4. To recover it, `POST .../kem/decapsulate` with `encapsulated_key` returns
   the same `shared_secret`.

For a hybrid construction, also run an X25519 or ECDH exchange with a
separate keycore key and feed both shared secrets into the HKDF. Your
application does the combining; keycore has no hybrid key type.

**Platform backups** (System Administration → Backups) are AES-256-GCM. The
backup key is either wrapped inside the tenant's HSM under its tenant key or
handed to the operator as a key file. Backups are not wrapped under ML-KEM.

### Use case 6: Measure readiness and plan migration

1. `POST /svc/pqc/pqc/scan`, then `GET /svc/pqc/pqc/readiness` for counts
   and risk items.
2. `POST /svc/pqc/pqc/migration/plans` with your own `deadline`.
3. `POST .../plans/{id}/execute` with `"dry_run": true`, review, then run it:
   key steps create PQC successor keys; do the manual steps yourself.
4. Add a Crypto Agility migration rule for the date you choose (Section 4).
5. `GET .../migration/report` and `GET .../timeline` show progress against
   your deadlines. `GET .../cbom/export` exports the inventory.

---

## Open items

- **X.509 SVID private keys are generated by the KMS** and returned in the
  issue response. Issuance from a workload-supplied public key (CSR) isn't
  implemented.
- **X.509-SVID proof replay is remembered in memory.** The exchange is a
  write, so a cluster member forwards it to the primary, which checks every
  proof. The primary keeps accepted proofs for two minutes in memory: a
  restart or failover inside that window forgets them. JWT-SVIDs are bearer
  credentials by design, reusable until they expire.

---

## Removed claims (6.6.0-beta)

Until 6.6.0-beta this page described the following. None of it existed, so
it was removed:

- **Workload identity:** a `vecta-agent` (DaemonSet, sidecar or service), a
  SPIFFE Workload API socket, `svid-tool`, SVID files on disk, automatic
  renewal at 50% of lifetime, pod annotations for SPIFFE IDs, Kubernetes
  TokenReview attestation, AWS IID, GCP IIT, Docker, Unix-process, TPM 2.0
  and Azure MSI attestors, an attestation-policy schema (`attestorType`,
  `spiffeIdTemplate`, `conditions`, `maxSvidTtl`, `priority`), a CA "stored
  in the KMS key store" with an intermediate, RFC 8693 token exchange
  (`grant_type`, `subject_token`), exchange of a Kubernetes SA token, and
  federation into AWS STS, GCP STS and Azure AD. The settings and
  registration fields shown (`default_svid_ttl_secs`, `enable_x509`,
  `ca_key_id`, `oidc_issuer`, `jwks_uri`, `attestor_type`,
  `attestation_policy_id`, `public_key_pem`) weren't the API's.
- **Attested key release:** Intel TDX quote, AMD SEV-SNP report / VCEK /
  AMD KDS verification, a `get_nonce` action and server-issued nonces with
  `REPORT_DATA` binding, `action` / `key_release` / `verify` sub-actions on
  `/evaluate`, named per-workload policies (`teeType`, `measurements`,
  `allowedKeyIds`, `allowedOperations`, `keyWrappingAlgorithm` with
  RSA-OAEP-512 / ECDH-ES, `maaEndpoint`), `wrapped_key_material` wrapped
  directly with RSA-OAEP, and a release that restricts the operations of the
  released key.
- **Key access justifications:** 17 built-in reason codes, an
  `X-Key-Access-Justification` header and a `justification` body on keycore
  decrypt, per-key rules (`applyToKeyIds`, `applyToOperations`,
  `requiredCodes`, `requireTicketId`, `managerApprovalCodes`,
  `managerApprovalGroups`), `log_only` mode, and a summary with top codes and
  keys.
- **PQC:** hybrid and composite keys (`HYBRID_X25519_MLKEM768`,
  `HYBRID_RSA4096_MLDSA87`, `hybridMode`, `componentKeyIds`), a hybrid KEM
  `wrap` (`HYBRID_X25519_MLKEM768_HKDF`), backups wrapped under a hybrid
  X25519 + ML-KEM-768 KEK, a self-signed hybrid root CA certificate,
  `nist_security_level` / `public_key_size_bytes` in the create response,
  scan findings with CRITICAL/HIGH ratings and remediation text, a readiness
  score with "framework alignment", a migration report with blocked reasons,
  and a "CNSA 2.0 gap analysis". Also removed: agency deadlines and
  "Recommendation" lines (the customer decides what and when to migrate),
  SLH-DSA sign and verify timings nobody measured, and ML-DSA sizes from the
  pre-standard Dilithium submission (now the FIPS 204 values).
- **Use cases** built on the above: Kubernetes zero-trust via the agent,
  multi-cloud attestor federation, Azure CVM policies, a SOX gate on keycore
  decrypt, the hybrid root CA, hybrid backup KEKs, and an AI-generated board
  report.

How this happened is recorded in [learning.md](../learning.md) (2026-09-29).

---

## Related references

- [API_REFERENCE.md](API_REFERENCE.md): routes and request fields
- [AUTOMATION_ALKM_PQC.md](AUTOMATION_ALKM_PQC.md): lifecycle automation and PQC keys
- [SECURITY/KEY_ACCESS_MODEL.md](SECURITY/KEY_ACCESS_MODEL.md): key access grants and approvals
- [SECURITY/INTERNAL_TLS.md](SECURITY/INTERNAL_TLS.md): hybrid TLS key exchange profiles
- [SECURITY/ALGORITHM_TRANSITIONS.md](SECURITY/ALGORITHM_TRANSITIONS.md): migration policy rules
- [SECURITY/FIPS.md](SECURITY/FIPS.md): FIPS modes and the impact catalogue
