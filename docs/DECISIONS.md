# Decisions

The approaches this product is built on, and why. Newest first. Add an entry
whenever you choose between real alternatives, so the choice isn't argued again
or quietly undone. Each entry covers the decision, why it was made, what was
rejected, and how it's enforced.

---

## 2026-09-25 — Documentation ships with the change
**Decision:** every change updates CHANGELOG.md, learning.md, this file and/or
`docs/SECURITY/` in the same commit. Standing instructions live in `CLAUDE.md`.
**Why:** the owner shouldn't have to repeat instructions, and FIPS reviewers
need a written trail of why each security control exists.
**Rejected:** documenting at release time (context is lost by then).
**Enforced by:** `scripts/check-docs.sh` in CI on pull requests, plus the
"Documentation is part of done" table in `CLAUDE.md`.

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

## 2026-06-12 — Cut features move to KMSExtension, not the bin
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
