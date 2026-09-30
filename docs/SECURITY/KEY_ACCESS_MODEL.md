# Key access model and key management overhaul

Status: **binding design** (owner directive, 2026-09-29: "add all of this so
it is implemented properly and strictly"). Phase 0 started in 4.0.0-beta;
the phase table at the end tracks what is done. Every change to key access,
key metadata or the key management UI follows this document. A change that
departs from it updates this document, and `docs/DECISIONS.md`, in the same
commit.

Vecta is not a copy of CipherTrust Manager. The owner's screenshots of
CipherTrust (keys list, per-key access matrix, key policies with label
selectors, KMIP properties, key usage, dates, links) set the **floor** for
granularity. The model below goes further where CipherTrust stores something
without enforcing it.

## 1. What existed before the overhaul (kept, not re-built)

| Capability | Where |
|---|---|
| Per-key grants to users and groups: operations, `not_before`/`expires_at`, justification, ticket | `key_access_grants`, `services/keycore/access_control.go` |
| Keycore access groups | `key_access_groups` (migration 003) |
| Deny-by-default, grant TTLs, approval for grant changes, signed requests, interface subject policies, interface ports and TLS | `services/keycore/access_hardening.go` |
| Justification-code rules with time windows and approval | `services/keyaccess` |
| Workload tokens bound to key IDs | `AllowedKeyIDs` in `evaluateKeyAccess` |
| Every key-use refusal audited with a reason | `audit.key.access_refused` |
| Usage limits, export policy, IV mode, versions, labels, tags | `Key` in `services/keycore/store.go` |
| Who used a key, through which interface, for which operation | `services/keycore/key_consumers.go` |
| Tenant guardrails (deny, warn, require approval, algorithm floor) | `services/policy` |

Nothing in this list is removed by the overhaul. Anything replaced (keycore's
own groups, the free-form `purpose`) is migrated per record first.

## 2. Gaps found (2026-09-29)

1. **Management routes had no permission check and accepted tokenless
   requests.** Fixed in 4.0.0-beta (section 9). Found by a probe test: with
   no token, `PUT /keys/{id}/export-policy`, `PUT /keys/{id}/access-policy`,
   `PUT /access/settings` and `PUT /keys/{id}/approval` returned 200.
2. **A body field named the actor** (`updated_by`, `created_by`). Fixed in
   4.0.0-beta for the access routes.
3. **The key's purpose is not enforced.** `ensureKeySupportsOperation` checks
   only that the algorithm can do an operation, so an AES key created for
   `encrypt-decrypt` still wraps and MACs. KMIP's usage mask is flattened
   into the `purpose` string (`purposeFromUsageMask`), losing bits.
4. **Service principals skip per-key grants.** dataprotect (FPE), payment
   (TR-31 / PIN translate) and certs (CA signing) call keycore as themselves,
   so keycore never sees the end user or the intended usage. Anyone who can
   reach dataprotect can FPE with any key in the tenant.
5. **Step-up MFA is read from a request header** (`X-Step-Up-Auth`), which
   any caller can set. Tokens carry no MFA claim.
6. **No key visibility control.** `GET /keys` lists every key in the tenant.
7. **Two group systems.** Keycore's `key_access_groups` duplicate auth's
   groups (IdP/SCIM-synced). Registered API clients can't be grant subjects.
8. **Missing:** label-selector policies, explicit deny, an owner distinct
   from the creator, aliases, KMIP links, enforced protect-stop /
   process-start dates, and the KMIP metadata fields in section 6.

## 3. The decision

One function decides every key use, for every interface (REST, KMIP, EKM,
HYOK, cloud BYOK, PKCS#11, and services acting for a user):

```
allow = usage_mask(key) ∋ usage                      what the key may ever do
      ∧ lifecycle_phase(key, now) permits usage      when
      ∧ (direct grant ∨ label-policy grant) ∋ usage  who
      ∧ conditions hold                              interface, network, justification, approval, quota
      ∧ no explicit deny matches                     deny always wins
```

Each layer refuses with its own `reason` (`usage_mask`,
`protect_stop_passed`, `not_yet_processable`, `explicit_deny`,
`no_matching_grant`, `condition:<name>`, ...) on `audit.key.access_refused`.
There is no second decision path: a protocol service that decides on its own
is a bug.

`services/policy` stays the tenant **guardrail** layer (algorithm floors,
require-approval, deny rules over the whole tenant). Grants and label
policies live in keycore, next to the key, because the decision runs on every
crypto operation.

## 4. Operations and usages

A grant names **operations**; a key's usage mask names **usages**. A grant can
never exceed the mask: the UI offers only operations the mask allows, and the
decision checks both.

### Operation groups (grants)

| Group | Operations |
|---|---|
| Manage | `read`, `update`, `manage-access`, `lifecycle`, `destroy` |
| Use | `encrypt`, `decrypt`, `wrap`, `unwrap`, `sign`, `verify`, `mac`, `mac-verify`, `derive`, `kem`, `agree`, and the delegated usages below |
| Material | `export`, `wrapped-export` |

### Usage mask, and where each usage is enforced

A usage appears in the UI **only** if an operation that enforces it exists.
Adding a checkbox without its enforcement point is a fake capability
(CLAUDE.md rule 8).

| Usage | Performed by | Enforcement |
|---|---|---|
| Encrypt, Decrypt, Wrap, Unwrap, Sign, Verify, Generate MAC, Verify MAC, Derive, Key agreement | keycore | the decision, directly |
| Export | keycore `/keys/{id}/export` | the decision, directly |
| FPE encrypt / decrypt, tokenize / detokenize | dataprotect (FF1, vaults) | delegated (section 5), 6.0.0-beta |
| Certificate sign, CRL sign | certs (CA keys held in keycore) | delegated, 6.0.0-beta |
| Content commitment | not an operation: the X.509 non-repudiation bit | certs sets the bit on an issued certificate only if the CA key's mask has it |
| Translate (TR-31, PIN), generate / validate cryptogram (EMV) | **nothing in the core**: payment moved to KMS Extension in 7.0.0-beta (5a) | not offered |

Mask rules:
- Set at creation from presets (Data encryption, Key wrapping, Signing CA,
  TR-31 / PIN) or explicit usages, filtered by what the algorithm can do.
- **Narrowing** is allowed and audited (`audit.key.usage_narrowed`).
  **Widening** needs a governance approval (`audit.key.usage_widen_requested`),
  because one key serves one purpose (NIST SP 800-57).
- KMIP `Cryptographic Usage Mask` is stored as-is, never flattened.
- Existing keys are migrated per key from `purpose`, with the mapping and
  each migrated key recorded; nothing switches silently.

## 5. Delegated usage (service acting for a user)

Built in 6.0.0-beta (`pkg/delegation`). A service performing a user's
request forwards, on its keycore call:
1. the user's own bearer token (`X-Vecta-Delegated-Token`), which keycore
   verifies itself with its JWT key (never a header or body claim, CLAUDE.md
   rule 4), and
2. the usage it performs (`X-Vecta-Key-Usage`, for example `fpe-encrypt`).

`pkg/auth`'s middleware keeps the verified token in the request context, and
`delegation.Attach` adds both headers only when the caller is a user (not a
service token, not a request with no token). Keycore accepts a delegation
only from a verified service identity; the forwarded token must verify, must
not be a service token, and must belong to the tenant of the request and of
the key; the usage must be known. Anything else is refused before any
handler (`audit.key.delegation_refused` with a reason). The access actor
becomes the user: the user's grants must allow the **usage** (an `encrypt`
grant does not allow `fpe-encrypt`), visibility is the user's, and every
event keycore emits carries `on_behalf_of`, `via` and `usage`. The route
permission is still checked against the calling service. The edge (Envoy)
strips both headers from outside requests.

**Correction (7.2.0-beta).** In dataprotect this engaged only from
7.2.0-beta: until then dataprotect booted without JWT verification
(`SkipJWT`) and no route checked a token, so no verified user token was
ever in its context and every call reached keycore as the bare service,
while tokenless callers could use any key. `NewAuthenticatedHandler` now
requires a verified platform token on every route except the wrapper
runtime routes (wrapper token), and `TestVerifiedTokenReachesTheService`
proves the token reaches the keycore call.

A workload token forwarded this way names key operations only
(`key.encrypt`, ...), so its permission check accepts the usage's base
operation (`fpe-encrypt` → encrypt); its key binding still applies.

| Service | Keycore call (decision point) | Usages |
|---|---|---|
| dataprotect | `POST /keys/{id}/usage/meter`, made before every key operation and before `service-derive` | `fpe-encrypt`, `fpe-decrypt`, `tokenize`, `detokenize`, `encrypt`/`decrypt` (field, searchable, mask), `wrap`/`unwrap` (envelope) |
| certs | `POST /keys/{id}/sign` (HSM CA keys and the `keycore` backend) | `certificate-sign` (issuance, sub-CA), `crl-sign` |
| ekm | `GET /keys/{id}/public-key` (TDE public key, on every request and at key creation and rotation) | `read` (6.18.0-beta) |

`read` is the one usage that is not a key operation: it is a per-key read
(section 8), decided by the user's view of the key, not by
`evaluateKeyAccess`. Because a delegated usage replaces the operation keycore
checks, a delegated `read` on any key operation is refused
(`delegation_usage_mismatch`); otherwise a `read` grant forwarded by a
service would allow a use (`TestDelegatedReadCannotPerformAKeyOperation`).

Not delegated, and why:
- `service-derive` stays service-only; dataprotect's metering call before it
  is the decision.
- certs signs as itself for OCSP responses, SCEP, the internal bootstrap and
  a new HSM CA's own self-signature (the user was authorized to create the
  CA and holds no grant on the key made a moment before).
- dataprotect lease receipts meter operations already authorized when the
  lease was issued.
- EKM has no export: a TDE key's material never goes to an agent. The
  agent sends each DEK wrap and unwrap to `POST /ekm/tde/keys/{id}/wrap` /
  `/unwrap`, and keycore decides every use (6.15.0-beta,
  `TestAgentHasNoKeyExportPath`).

Open:
- **Bare service identities are not yet limited to their usages.** A
  request with no user behind it (scheduler, ACME/EST client, reconciler)
  still acts with the service's tenant-wide trust. The allowlist per
  identity in `pkg/svctls.Services` is the next step.
- **Field-encryption leases** hand wrapped key material to a registered
  wrapper without a keycore decision for the user who asked
  (`IssueFieldEncryptionLease`).

### 5a. Payment (moved out, 7.0.0-beta)

The payment service (TR-31, PIN translation, PVV/CVV, MAC, ISO 20022, AP2)
moved to the KMS Extension repository as a seed (owner decision,
2026-09-29; `seeds/services/payment`, last in KMSBeta at `4146dc70c`). Its
delegated usages (`translate-*`, `mac`, `export`, `sign`, `verify`) went with
it. Its key-by-ID path never worked against the real keycore (keycore exports
only under a `wrapping_key_id`; payment read a plaintext field its test fake
supplied). Promoting it back needs a design where keycore performs the
payment cryptography or releases material only to a verified payment
identity for a delegated user. Keycore still imports TR-31 key blocks with
`pkg/payment`.

## 6. Key properties and KMIP metadata

First-class key fields in keycore. The KMIP service reads and writes the
**same** fields; there is no KMIP-only copy and no "cannot be updated for this
key type" split.

| Field | KMIP attribute | Rules |
|---|---|---|
| Owner | (Vecta) | a user, group or client ID; change-owner is its own audited route |
| Contact information | Contact Information | length-limited; audit records that it changed, not the text (may be PII) |
| App namespaces | Application Specific Information (namespace + data) | indexed so KMIP `Locate` can filter on it |
| Custom attributes | `x-` custom attributes | returned to clients, **never** read by an access decision; size and count limits |
| Alternative names | Alternative Name (string, URI, email, DNS, IP, X.500, serial) | validated per type |
| Aliases | additional Name values | unique per tenant; accepted wherever a key ID is |
| Links | Link (previous, replacement, next, parent, child) | written by rotation and derivation, not free text |
| Dates | Activation, Process Start, Protect Stop, Deactivation, Destroy, Compromise, Compromise Occurrence, Archive | Process Start and Protect Stop are **enforced** (section 7) |

**Labels and custom attributes stay separate.** Labels select keys for label
policies (restricted charset, indexed). Custom attributes are opaque
application data. An application attribute must never change who can use a
key. Tags merge into labels.

KMIP needs `AddAttribute`, `ModifyAttribute` and `DeleteAttribute` (only
`GetAttributes` exists today), tested with the real KMIP TLS client.

## 7. Lifecycle phases are enforced

| Phase | Protect usages (encrypt, sign, wrap, MAC, FPE encrypt, translate encrypt) | Process usages (decrypt, verify, unwrap, MAC verify, FPE decrypt) |
|---|---|---|
| before Activation | refused `not_yet_active` | refused |
| before Process Start | allowed | refused `not_yet_processable` |
| after Protect Stop | refused `protect_stop_passed` | allowed until Deactivation |
| after Deactivation, Compromised, Destroyed | refused | refused (decrypt of compromised data only with approval) |

## 8. Who, and separation of duties

- **Subjects:** auth users, auth groups (including IdP/SCIM groups),
  registered clients, workload identities. Keycore's own groups are migrated
  into auth groups and then dropped.
- **Grants** carry `effect: allow|deny`, operations, validity window,
  conditions, justification and ticket.
- **Label policies** (`key_policies`): a label selector, subjects with
  operations and conditions, and whether a change needs approval. Every
  policy change runs a dry run that lists the keys the selector matches.
- **Visibility** (owner decision 2026-09-29, option A; built in
  5.0.0-beta, `services/keycore/key_visibility.go`): a key is listed and
  readable only by its creator, holders of an active grant on it (any
  operation, including the view-only `read`), directly or through a group,
  workloads bound to it, tenant admins, service identities and holders of
  `key.inventory.read` (auditors). The filter runs in the database query.
  A hidden key answers exactly like a missing one (`404`), audited as
  `audit.key.access_refused` (`operation: read`, `reason: not_visible`), and
  the tenant is checked before the key is looked up. Tenant-wide inventory
  and analytics views need `key.inventory.read`. When owners and label
  policies land (phases 1-2), they join the same view.
- **Separation of duties:** `manage-access` is distinct from using the key.
  An owner can't grant `export` to themselves. Grant changes on keys whose
  labels mark them high-value go through governance approval, which the
  requester can't give.
- **Explainers:** "who can do X with this key, and through which grant or
  policy", and "what can this subject do", served from the decision function
  itself so they can't drift from enforcement.

## 9. Route permissions (4.0.0-beta)

Keycore requires a verified token on every route except the reconciler
route that authenticates with the internal token
(`GET /keys/due-for-lifecycle`; the no-op `POST /tenants/onboard` and the
`POST /keys/{id}/archive` stub were removed in 5.3.0-beta). A tokenless request is refused `401` and audited
as `audit.key.request_refused` (`reason: unauthenticated`).

| Routes | Permission | Extra check |
|---|---|---|
| `GET /keys/{id}/access-policy` and the `GET` routes under `/access/` | `key.access.read` | |
| `PUT /keys/{id}/access-policy` | `key.access.manage` | caller created the key, or is a tenant admin (`not_key_owner`) |
| groups, access settings, interface policies, ports, TLS config (writes) | `key.access.admin` | |
| `POST /keys`, `/keys/import`, `/keys/form`, `/keys/bulk-import` | `key.create`, `key.import`, `key.form` | tenant in the body must match the token |
| rotate, activate, deactivate, disable, destroy, versions, bulk rotate/delete | `key.rotate`, `key.activate`, `key.deactivate`, `key.disable`, `key.destroy` | |
| `PUT /keys/{id}`, `PUT /keys/{id}/iv-mode` | `key.update` | |
| export policy, approval, usage limit and reset | `key.export_policy_update`, `key.approval_update`, `key.usage_limit_update` | |
| tag writes | `key.tags.write` | |
| crypto operations | any verified identity | the per-key decision (section 3) |
| `GET /keys` and per-key reads | any verified identity | the key must be visible (section 8) |
| tenant-wide inventory and analytics views | `key.inventory.read` | |
| ceremonies, compromise, enterprise controls, scheduling, inventory/analytics writes, attestation, integrity checks, FIPS self-test (5.0.0-beta) | `key.ceremony.*`, `key.compromise`, `key.enterprise.*`, `key.scheduling.*`, `key.inventory.write`, `key.analytics.write`, `key.health.write`, `key.rotation.write`, `key.usage.meter`, `key.attest`, `key.integrity.verify`, `key.fips.selftest`; orchestration runs `key.rotate` | per-key routes: the key must be visible |

Built-in `admin` / `tenant-admin` hold `*`. Other roles get these permissions
explicitly. Service principals pass the permission check and act for the
request's tenant.

## 10. Implementation rules (strict)

Every slice of this work meets all of these, or it isn't done:

1. **One decision path.** New interfaces and services call the keycore
   decision; they never decide key access themselves.
2. **Every usage has an enforcement point and a test** that proves the
   refusal. No checkbox, mask bit, date or field is stored without the code
   that acts on it; otherwise it isn't offered (CLAUDE.md rule 8).
3. **Identity only from a verified credential.** No actor, owner, group or
   usage claim from a body field or header. A body field that names an actor
   is rejected, not ignored (4.0.0-beta: `Decode` rejects unknown fields).
4. **Every route through `pkg/route`** with a permission; per-key checks
   return `c.Refuse` with a reason. `routetest.RefusalsAudited` covers each
   router.
5. **Every change and every refusal is audited** under its own subject, with
   a test named in `docs/SECURITY/AUDIT_EVENTS_2026-09.md`.
6. **Deny wins, default closed.** No grant means no access and no
   visibility (only the creator, tenant admins, service identities and
   `key.inventory.read` holders see an ungranted key). Explicit deny beats
   any allow.
7. **Migrations are per record** and recorded (purpose to usage mask, keycore
   groups to auth groups, tags to labels). No silent switch.
8. **Clustering.** New tables are classified in
   `pkg/clustercatalog/tables.go` (grants, policies and key metadata are
   replicated under keycore). Writes forward to the primary.
9. **FIPS.** No new crypto. A usage that is non-approved in strict mode
   (for example FF3-1) refuses cleanly and is listed in `pkg/fips/impact.go`.
10. **Backend and dashboard together.** The UI never shows a control the
    API doesn't enforce, and shows "unavailable" when a call fails.
11. **Test the bad case end to end** through `Handler.ServeHTTP`, with a
    real Postgres run for anything touching JSONB grants or policies.

## 11. Dashboard

- **Keys list:** one row per key with a version count that expands (not one
  row per version). Filters: labels, owner, state, algorithm, "accessible to
  <subject>".
- **Key detail:** Overview · Usage (grouped mask editor with presets and
  algorithm-aware disabling) · Access (grouped operation matrix: Manage / Use
  / Material, with inherited policy rows shown read-only and their source) ·
  Policies · Properties (section 6) · Lifecycle (dates of section 7) ·
  Versions & Links · Activity (consumers plus audit timeline).
- **Key Policies** tab: selector → subjects → conditions → dry run → review.

## 12. Phases

| Phase | Scope | Status |
|---|---|---|
| 0 | Tokenless refusal; access and key-management routes on the kernel with permissions; owner-or-admin for grant changes; actor from token | **done, 4.0.0-beta** |
| 0 | Key visibility (option A, `key.inventory.read`, `read` grants); every remaining keycore write on the kernel | **done, 5.0.0-beta** |
| 0 | Delegated usage with the user's token for dataprotect, payment, certs (section 5) | **done, 6.0.0-beta** (payment moved out in 7.0.0-beta; engaged in dataprotect only from 7.2.0-beta, when it began verifying tokens) |
| 0 | Enforce the declared usage; bare service identities limited to their usages; field-encryption lease decision; step-up from a verified MFA claim | open |
| 1 | Usage-mask column (full vocabulary, per-key migration, KMIP mask kept); owner and change-owner; subjects from auth; explicit deny | open |
| 2 | Label policies, cache with NATS invalidation, explainers, dry run; tags into labels | open |
| 3 | Enforced dates; aliases; links; section 6 properties; KMIP Add/Modify/DeleteAttribute | open |
| 4 | Dashboard (section 11) | open |
| 5 | Every protocol through the decision; playbook triggers for high-risk grants and deny overrides | open |

## 13. Open decisions (owner)

1. ~~Default key visibility~~: decided 2026-09-29, option A (section 8).
2. Retire keycore's own groups into auth groups.
3. Label policies in keycore (recommended) or in `services/policy`.
4. ~~How payment gets key material~~: payment moved to KMS Extension, 7.0.0-beta (section 5a).
