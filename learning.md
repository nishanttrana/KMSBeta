# Learnings

Running log of non-obvious operational and architectural learnings for Vecta KMS.
Newest entries on top.

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
