# Learnings

Running log of non-obvious operational and architectural learnings for Vecta KMS.
Newest entries on top.

## 2026-06-18

### JWT service-to-service auth — per-service identities (phased rollout)
Moving internal auth from "mTLS / shared static INTERNAL_API_TOKEN" to per-
service JWTs. Landscape found: validation is universal (every service has the
cluster `JWT_PUBLIC_KEY_B64` + `pkgjwtauth`); minting exists (`POST
/auth/client-token`: API-key-authenticated client-credentials → JWT); the only
prior s2s auth was a narrow shared static token (`pkg/internalauth`, reconciler
→ keycore/kmip privileged endpoints).
- **Provisioning without secret sprawl:** one shared `INTERNAL_SERVICE_BOOTSTRAP_SECRET`;
  each service derives its own API key = HMAC-SHA256(secret, "kms-service-api-key:"+name)
  (`pkg/servicetoken.DeriveAPIKey`). auth bootstrap pre-registers a client +
  key-hash per service from the same derivation, so no per-service secret is
  distributed. `pkg/servicetoken.Source` mints/caches/refreshes the JWT and
  attaches it Bearer (best-effort: errors leave the call unauthenticated so a
  rollout-in-progress never hard-fails).
- **The crux (not yet done):** internal services are multi-tenant but a client-
  token is tenant-bound, and `tenantcheck.Enforce` 403s a root-tenant token
  acting for tenant X (only bypasses an *empty* tenant claim). So a `service`
  principal must be treated as tenant-unrestricted (acts for the request's
  tenant) AND authorized in keycore's `enforceKeyAccess` — else attaching a
  token would *deny* crypto that currently works tokenless. This is why it's
  phased: attach (non-enforcing) first, flip enforcement last.
- **Gotcha:** a directly-inserted *approved* client registration left
  `api_key_prefix` NULL (the normal flow sets it during approval), and
  `GetClientRegistration` scanned it into a plain string → 500. Fixed with
  `COALESCE(api_key_prefix,'')` in the read queries.
- **Phase 1 (done, non-breaking, verified):** pkg/servicetoken + auth
  provisions 20 per-service identities; verified kms-ekm mints a JWT
  (client_id=kms-ekm, role=client-service). Nothing attaches/enforces yet.
- **Remaining:** (2) tenantcheck + keycore access-control trust the service
  principal across tenants; (3) wire `servicetoken.FromEnv(name)` into the ~14
  per-service internal HTTP clients (attach-only); (4) flip enforcement,
  retiring the static INTERNAL_API_TOKEN path.

## 2026-06-17

### mTLS mesh topology edges = the configured call graph (honest, not faked)
"Which service talks to which" has no clean runtime source here: consul Connect
intentions are wildcard allow-all (no real edges) and envoy per-edge telemetry
isn't scraped. The honest source is the **configured dependency graph** — each
service's `*_URL` wiring (`grep -rn 'envOr("[A-Z_]*_URL"' services/*/main.go`),
which are exactly the mTLS HTTP calls. The discovery reconciler holds that graph
(`meshDependencyGraph`, display names) and upserts an edge only when BOTH
endpoints are present in the catalog, so the graph grows with the mesh and never
shows phantom edges. Edges are `mtls_verified=true` (every mesh hop is mutually
authenticated) with no `last_handshake_at` (we don't observe handshakes — UI
shows "No handshake"), which is truthful about provenance. Watch the display-
name mapping: consul names are `kms-hyok-proxy`/`kms-workload-identity`, not
`hyok`/`workload`. Full observed topology would need envoy stats scraping.

### mTLS mesh auto-discovers internal services from consul (live, self-updating)
The mesh view must reflect the *live* internal mTLS fabric, not a manual
registry. Source of truth = the **consul catalog** (`GET /v1/catalog/services`,
`/v1/catalog/service/{name}`): every KMS service self-registers there
(`pkgconsul.NewRegistrar`), so it lists all `kms-*` services and updates as they
come and go. The `certs` service runs a 60s discovery reconciler
(`ReconcileMeshFromConsul` → `UpsertDiscoveredMeshService`, keyed on
(tenant,name)) that records each as a mesh service under the root/platform
tenant (`MESH_DISCOVERY_TENANT`, default `root`; gate `MESH_DISCOVERY_ENABLED`).
New services appear automatically; no manual entry. consul runs at
`CONSUL_HTTP_ADDR` (consul:8500). Discovery is best-effort — a consul outage
never breaks certs. Note: the platform mesh is global infrastructure, so it's
recorded under the root tenant (customer/workload mesh entries stay per-tenant).

### "Showing mock data" ≠ no backend — check before judging a feature fake
The mTLS Mesh tab looked fake, but the `certs` service has a real backend
(`/mesh/services|certificates|trust-anchors|topology`, `…/renew`) — renew
actually generates an EC P-256 key and issues an X.509 leaf from the internal
CA. The tab only *looked* fake because it seeded state with `MOCK_*` and fell
back to mock on empty/error. Real use-case: SPIFFE-style **workload mTLS
identity lifecycle** for the consul/envoy service mesh — register a service,
issue it a short-lived mTLS cert from the KMS CA, track expiry, auto-renew,
manage trust anchors, view the verified-handshake topology. Verdict: KEEP;
removed the mock seed/fallback so it shows real registered services or an
honest empty state. Lesson: a `MOCK_*` fallback masks whether the backend is
real — always trace the lib → route → server handler before deciding to cut.

### Per-key operations belong in Key Management's row actions, not their own tabs
Verify-integrity and Attest are operations *on a key*, so they live in the Key
Management row action menu (alongside Rotate/Export/Destroy), not as a separate
top-level tab. Pattern: add a typed client fn in `lib/keycore.ts`, a handler in
KeysTab that calls it and reports via `onToast` (verify) or a small overlay
(attest, which returns a signed document to view/download). One fewer tab, and
the action is where the user already is.

### Distinguishing a real feature from a redundant management surface
When auditing "advanced feature" tabs, the test is whether the tab adds anything
beyond an operation/interface that already exists:
- **Key Derivation (KDF) tab** managed named `kdf_configs`, but derivation is
  the `POST /keys/{id}/derive` crypto op exposed via REST/PKCS#11/JCA — the
  configs were a redundant surface. Removed the tab + the `/kdf/configs`
  backend (handlers, routes, store methods, types, migration 017 dropping
  `kdf_configs`/`kdf_derivation_log`); the derive op stays.
- **Advanced Encryption tab** POSTed to `/encryption/encrypt|decrypt` which
  **never existed** in keycore (the real path is the Workbench's
  `/keys/{id}/encrypt`). Dead tab → removed; no backend to clean.
- **Envelope Encryption tab**: KEEP. It is a genuinely distinct feature — a KEK
  wraps many DEKs and rotating the KEK triggers bulk *rewrap* of the small DEKs
  instead of re-encrypting the underlying data. Backend is real
  (`/envelope/keks|deks|hierarchy|rewrap|rewrap-jobs`). The only problem was the
  tab fell back to fabricated KEK/DEK rows on load failure — replaced with an
  honest empty state + error (never fabricate security data in a KMS UI).

### Quick test for "is this tab backed by anything"
`grep -n "fetch(\`\${base}" Tab.tsx` then `grep -rn "<that route>" services/<svc>` —
if the route isn't registered server-side, the tab is dead (Advanced Encryption
hit non-existent `/encryption/*`). Mock fallbacks (`MOCK_*`, "showing mock
data") are the other tell.

## 2026-06-16

### Tenant enforcement: data-scoping is not the same as access-enforcement
All these features store data per tenant (RLS + `WHERE tenant_id`), but that
alone does not stop a caller from *asking* for another tenant's data. The
enforcement points and their gaps:
- `mustTenant` → `tenantcheck.Enforce` binds `tenant_id` to the JWT's tenant
  claim — but **only when a token is present**; with no claims it skips by
  design (so the outer layer is expected to require auth).
- **keycore does not require auth globally** (only rate-limit + audit
  middleware), and ~10 internal services (ekm, kmip, signing, payment, …) call
  its `/keys` crypto routes with a `tenant_id` and **no token**. So a blanket
  "require auth" would break platform crypto.
- **posture never parsed JWTs at all** → `tenantcheck.Enforce` was a no-op
  there → the leak scanner had *zero* tenant binding (any `tenant_id` returned
  that tenant's targets/findings).
- Fix without breaking tokenless internal callers: a `requireAuthedTenant`
  helper (reject if no claims, then `mustTenant`) applied to the *dashboard-only*
  feature endpoints (threat, credential-bindings, attest, verify, and posture
  `/leaks/*`). posture also gained an **optional** JWT-parse middleware
  (populate claims if present, 401 if invalid, pass through if absent) so
  `tenantcheck` works for token-bearing dashboard calls while tokenless
  `/posture/*` calls from reporting keep working.
- Check before tightening auth: who calls the endpoint? `grep <SVC>_URL`.
  Shared crypto/report routes have tokenless internal callers; feature routes
  are dashboard-only and safe to require auth on. Health probes use the gRPC
  port (18xxx), so requiring auth on the HTTP handler never breaks healthchecks.

### A tab showing "No keys found" while Key Management has keys = wrong list call
The Key Verification tab raw-fetched `/svc/keycore/keys`, read `d.keys`, and
searched/displayed `label`. But the keys endpoint needs `?tenant_id=` and
returns `{items: [...]}`, and keys have **`name`**, not `label`. Result: no
keys (or none matching a name search). Fix: use the same typed `listKeys(session)`
lib that Key Management uses, and search on `id`+`name`. Lesson: per-tab raw
fetches drift from the canonical client — reuse `lib/keycore` so every view
sees the same data.

### Key attestation (signed, offline-verifiable)
Added `POST /keys/{id}/attest`: builds a canonical statement (key identity,
properties, exportability, KCV, and a live integrity result) and signs it with
an ECDSA P-256 attestation key; `GET /attestation/public-key` publishes the
verifying key. Notes:
- **Central crypto only:** keycore must not import `crypto/ecdsa` directly
  (the `make conformance` central-crypto rule). Use `pkg/crypto`'s
  `GenerateKeyPair`/`Sign`/`MarshalPublicKeyPEM`/`ParsePrivateKeyPEM`.
- Signing key loads from `KEYCORE_ATTESTATION_PRIVATE_KEY_PEM/_B64` for a
  stable identity across restarts; falls back to an ephemeral key (logged) so
  the feature works out of the box. The pubkey endpoint always reflects the
  active key, so attestations verify for the key's lifetime.
- Statement is marshalled deterministically and the **exact signed bytes** are
  returned (`statement_b64`) so a relying party verifies the signature without
  re-serialising. Tested: signature verifies; a tampered statement does not.

## 2026-06-15

### Auto-generated "advanced feature" tabs were mostly decorative — keep only what's enforced
The "20 advanced features" batch (migration 012) produced several tabs that
looked functional but didn't actually do anything on real keys. Audit each
against "is it enforced / does it solve a real problem?" before trusting it:
- **Key Binding** (TPM PCR / region / IP-CIDR): config was stored in
  `key_binding_configs` but **never read at crypto time** — no enforcement
  anywhere outside its own CRUD. Decorative. Removed.
- **Key Metadata Extension**: duplicated fields the key already carries
  (`owner`, `tags`, `labels`, `compliance`) in a parallel `key_metadata_ext`
  table. Redundant. Removed.
- **Key Verification**: the handler hard-coded `"verified": true` and
  fingerprinted the *encrypted* material (meaningless — ciphertext changes on
  re-wrap). It never proved anything.
- **Decision:** merge to the one genuinely strong capability — real key
  integrity verification — and delete the rest (frontend tabs + libs, backend
  handlers/routes/store methods/types, and a migration dropping the tables).

### Real key-integrity verification
A meaningful integrity check decrypts the current version's material under the
MEK (an AES-GCM auth-tag failure = corruption / tampering / wrong-or-rotated
MEK) and, for keys with a KCV, recomputes the KCV from the live material and
constant-time compares it to the recorded value. Gotcha: the **authoritative
KCV lives on the key _version_** (`key_versions.kcv`), not the `keys` row — the
key row's `kcv` is a denormalised copy only updated on rotation, so it can be
empty on first create. Compare against `version.KCV` (fall back to `key.KCV`).
Reuse `decryptMaterial` + `computeKCVStrict` so the check matches creation
exactly. The old placeholder could never fail; the real one can and does
(tested by corrupting `key_versions.encrypted_material`).

### Removing a feature is a full-stack sweep
Per feature: frontend tab + lib + shell wiring (lazy import, component map,
TITLES, nav) + `moduleRegistry` gate; backend routes + handlers + `Store`
interface methods + SQLStore impls + types; a migration to drop the table; and
the **generated REST catalog** (`restApiCatalog.generated.ts`) which the
`build` script regenerates via `generate:rest-catalog` — so a plain
`npm run build` drops stale endpoints automatically.

## 2026-06-14

### "Create key failed: policy evaluator unavailable; fail-closed"
- **Cause:** keycore reads `POLICY_ENGINE_URL` to find the policy service. It was
  never set in `docker-compose.yml`, so keycore's policy evaluator fell back to
  the **deny-all** evaluator (because `KEYCORE_POLICY_FAIL_CLOSED` defaults true)
  and denied *every* key operation with this exact message.
- **Second layer:** the policy service requires a valid **Bearer JWT** on every
  request (`pkgjwtauth.MustWrap`), but keycore's `HTTPPolicyClient` only set
  `Content-Type` — so even with the URL set it would get `401` and still fail
  closed.
- **Fix:** set `POLICY_ENGINE_URL=http://policy:8040` in keycore's compose env,
  and make the policy client **forward the caller's bearer token** (and
  `X-Tenant-ID`). keycore already stashes the raw token in context as
  `rawBearerTokenCtxKey`; the client now reads it and sets `Authorization`.
- **Why forwarding works:** all services share the cluster-wide
  `JWT_PUBLIC_KEY_B64`, so a token signed by the auth service validates at the
  policy service unchanged. Service-to-service identity = propagate the caller's
  JWT, not a separate service token.
- **General principle:** fail-closed services turn *missing wiring* into a total
  outage, not a silent bypass. When "every operation is denied," suspect an
  unwired/unreachable dependency before suspecting data/permissions.

### Verifying auth paths without clobbering a user's credential
- To confirm keycore→policy auth, don't reset the admin password (the user may
  have already set their own). Any **valid JWT** satisfies the policy
  middleware, so log in as the bootstrap **cli-user** (password in `.env` as
  `AUTH_BOOTSTRAP_CLI_PASSWORD`) and call `/policy/evaluate` directly — a `200`
  with a `decision` proves the path; a `401` proves it's still broken.

### Default admin credential & forced first-login change
- Default is `admin`/`admin`, safe only because the seeded admin has
  `MustChangePassword=true` and login then issues a JWT **scoped to
  `auth.password.change`** — the default can do nothing but rotate itself.
- `bootstrapDefaultAdmin` is **one-shot / idempotent**: it never overwrites an
  existing user. On an upgraded deployment the old admin password persists and
  `admin`/`admin` is rejected. Recover with `AUTH_BOOTSTRAP_RESET_ADMIN=true`
  for one restart, then unset it (so a later restart can't clobber the rotated
  password). Keep `AUTH_BOOTSTRAP_FORCE_PASSWORD_CHANGE=true` in real envs.

### The dashboard is a build artifact — "I don't see it" usually means stale build
- Source changes (tab merges, the Threat & Exposure console, etc.) are **not
  live until the dashboard container is rebuilt and redeployed**:
  `docker compose up -d --build dashboard`. Then hard-refresh the browser
  (Cmd/Ctrl+Shift+R) to drop the cached bundle.
- Verify what's actually served by grepping the bundle inside the container
  (`/usr/share/nginx/html/assets/*.js`) for expected/removed label strings,
  rather than trusting the source tree.
- The dashboard auth path is controlled by `public/config/ui-auth.json`:
  `prefer_backend_auth` (use the real auth service) vs `allow_local_fallback`
  (local `ui-auth.json` credentials). Backend mode relies on the auth service's
  `must_change_password` response.

### Merging dashboard tabs
- A "merge" is a wrapper component with a segmented control that renders the
  existing child tabs as sub-views, plus cleanup of every reference:
  `VectaDashboardV3Shell.tsx` (lazy import, component map, TITLES, nav array),
  `config/moduleRegistry.ts` (feature gate), and the FeatureKey/TabId unions.
  Remove genuinely redundant tabs entirely (e.g. Shamir Key Recovery is
  subsumed by guardian-quorum Escrow); fold unique functionality, drop overlap
  (e.g. the `rotate` action left scheduled-jobs once rotation policies own it).
