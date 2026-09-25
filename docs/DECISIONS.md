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
