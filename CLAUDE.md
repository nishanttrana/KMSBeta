# Vecta KMS — engineering rules

Standing rules for all development on this repo, by people and by AI
assistants. The product targets FIPS 140-3 Level 1, so assume every crypto,
TLS, auth or audit change will be read by a certification reviewer.

**The owner should never have to repeat an instruction.** When they give a
standing instruction, add it to this file in the same change. When they correct
an approach, record it here or in the matching doc below.

## Non-negotiable

1. **One crypto library.** Primitives come only from `pkg/crypto`
   (FIPS-gated by `pkg/fips`). Never import `crypto/rand`, `crypto/aes`, etc.
   in a service. Never use `math/rand` for anything security-relevant.
2. **One audit pipeline.** Events go through `pkg/audit` `Client.Emit` onto the
   single `AUDIT` JetStream stream. No private streams, no raw publishes.
   Events carry actor, resource, severity and correlation, detailed enough for
   governance, reporting and DAM to run on them alone.
3. **Secure defaults** ([docs/SECURITY/SECURE_DEFAULTS.md](docs/SECURITY/SECURE_DEFAULTS.md)):
   - No secret falls back to a value in the repo. Require it (`${VAR:?}`) or
     generate it at random.
   - Validate strength, fail closed on weak values, and revoke anything a
     removed default already produced.
   - Every installer generates every secret compose requires.
   - The only repo-visible default is admin `changeit`, which is always seeded
     with a forced password change.
4. **Tenancy bypass must be unforgeable.** A privilege that skips tenant checks
   is keyed on something only the platform can mint (see
   `tenantcheck.IsServicePrincipal`), never on a role name or an `X-Actor-*`
   header.
5. **FIPS 140-3 is the customer's choice (made in the KMS UI), on the certified module**
   ([docs/SECURITY/FIPS.md](docs/SECURITY/FIPS.md)):
   - Every binary builds with `GOFIPS140` = `pkg/fips.CertifiedModuleVersion`.
   - A root admin picks `on` | `only` | `off` in System Administration.
     Services apply it by a staggered self-restart and re-exec;
     `VECTA_FIPS_MODE` only seeds it. Every feature must work, or refuse
     cleanly, in each mode.
   - A feature that behaves differently in strict mode must appear in the
     impact catalogue (`pkg/fips/impact.go`) that the UI shows before a
     change.
   - AES-GCM uses module-generated IVs.
   - Non-approved or third-party crypto gets a `fips140.Enforced()` guard that
     returns an error, never a panic.
   - Claim "validated" only when `fips.ModuleValidated()` is true.
6. **Keys are derived from secret material, never from identifiers.** A
   service that needs a working key gets it from keycore
   (`POST /keys/{id}/service-derive`, bound to the verified service identity).
   A KCV, key ID or other metadata is never key material. Changing how
   existing data is keyed needs a per-key migration, never a silent switch
   ([docs/SECURITY/DATAPROTECT_KEY_DERIVATION.md](docs/SECURITY/DATAPROTECT_KEY_DERIVATION.md)).
7. **Never fabricate security evidence.** No invented versions, scan results,
   certifications or "5/5 production-ready" claims. The UI shows "not assessed"
   rather than guessing. Evidence lives in `docs/SECURITY/` and comes from real
   tool output.

## Crypto and transport standards

- TLS 1.3 minimum (`MinVersion: tls.VersionTLS13`). Where an external protocol
  forces less (LDAP/AD, KMIP, Alibaba HMAC-SHA1), add a comment
  `FIPS exception: external protocol mandate` explaining why.
- Algorithms must be on the approved list in `pkg/fips/fips.go`.
- Key derivation uses HKDF-SHA256 or Argon2id, never a raw hash.
- Audit records are immutable and tamper-evident (hash chain, per-event HMAC,
  Merkle epochs).
- Every HTTP response carries `pkg/securityheaders`.

## How we build

- Code is tight, light and secure: no bloat, no speculative abstraction, no
  half-measures. Apply fixes directly rather than proposing them.
- New features and customer-side agents wire into the central spine
  (`pkg/crypto`, `pkg/audit`, auth service tokens) by construction. Agents
  that can't reach NATS use the audit service's authenticated HTTP ingest.
- When a backend capability is added or missing, build both the backend and
  the dashboard side.
- Shell scripts that users run (`install.sh`, `deploy-local.sh`) must work on
  macOS's bash 3.2 unless they explicitly re-exec under bash 4+.
- Don't use `git stash` as a scratch tool in a dirty working tree. Use a
  throwaway `git worktree` instead.
- Every new database table is classified for clustering in
  `pkg/clustercatalog/tables.go`: replicated under its component, node-local
  with a reason, or shared-append. Tables written during crypto operations
  are node-local. `TestEveryTableIsClassified` enforces this
  (docs/CLUSTERING.md).
- An internal endpoint that moves secrets or grants cluster access must
  restrict its caller: a specific service identity or a root administrator,
  never "any authenticated caller". Node-to-node endpoints authenticate
  themselves (one-time token, HMAC, pinned TLS).
- Features cut from the core move to the sibling `KMSExtension` repo (REST
  integration via `pkg/kmsclient`, no key material there). Don't delete them.

## Documentation is part of done

Every change is documented in the same commit. Don't leave it for later, and
don't wait to be asked. Where each kind of change goes:

| What changed | Document it in |
|---|---|
| Anything a user, operator or buyer would notice (features, fixes, security changes, defaults, breaking config) | [CHANGELOG.md](CHANGELOG.md), under the current version |
| A non-obvious lesson: root cause of a bug, a trap, why something failed | [learning.md](learning.md), newest on top under today's date |
| An approach or design decision (why X over Y, what was rejected) | [docs/DECISIONS.md](docs/DECISIONS.md) |
| A security practice or rule | `docs/SECURITY/` (for example `SECURE_DEFAULTS.md`), linked from its README |
| A standing instruction from the owner | this file |
| Operating steps (deploy, rotate, recover) | the matching guide in `docs/`, for example `SECRET_ROTATION.md` or `OPERATIONS_GUIDE.md` |
| API surface | `docs/API_REFERENCE.md` and the OpenAPI spec |

Write what a reviewer six months from now needs: what changed, why, how it's
enforced, and what's still open. `scripts/check-docs.sh` fails a PR that
changes code without touching CHANGELOG.md or learning.md.

## Before calling a change done

- `make conformance` passes. It enforces rules 1–3 and 5, and that every
  shell script parses under macOS bash 3.2.
- `make test-fips-modes` passes: the suite runs in FIPS modes `off`, `on` and
  `only`. A test of a non-approved feature calls `fipstest.SkipIfStrict` and
  is paired with a `fipstest.StrictOnly` test proving the clean refusal. Its allowlist only
  shrinks, and a new entry needs a crypto-boundary justification.
- `go vet` and `go test` pass for the touched packages. New security behaviour
  gets a test that proves the bad case is rejected.
- The documentation above is updated in the same change. New or changed
  endpoints, headers and env vars also go in `docs/API_REFERENCE.md`.
- Every security-relevant action and refusal emits a specific audit event
  (the HTTP middleware's generic request record isn't enough). New events are
  listed in `docs/SECURITY/` and proven by a test. Something that can't be
  audited (for example a service refusing to start) must say how it shows
  instead.
