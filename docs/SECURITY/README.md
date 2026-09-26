# Security Documentation

This directory is for **security scan and hardening evidence generated from real
tooling**. It does not contain pre-written "zero vulnerabilities" claims.

> Earlier versions of this directory contained narrative reports
> (`SECURITY_SCAN_REPORT.md`, `SECURITY_UPDATE_REPORT.md`,
> `VULNERABILITY_SUMMARY.txt`) that cited **non-existent dependency versions**
> as "SAFE" and a gRPC **downgrade** mislabeled as an upgrade. They were
> introduced by the `agents/kms-system-update-and-hardening` branch, never
> resolved or built, and have been **removed** because they could be mistaken
> for compliance evidence. Regenerate from the commands below instead.

## Standing rules

- [SECURE_DEFAULTS.md](SECURE_DEFAULTS.md): no secret may fall back to a value
  in the repo. Enforced by `make conformance`. Read it before adding any
  secret, installer step or seeded account.
- [FIPS.md](FIPS.md): every binary links the certified Go Cryptographic
  Module; the runtime mode (`on` / `only` / `off`) is the customer's choice
  and is tested in all three modes.
- [DATAPROTECT_KEY_DERIVATION.md](DATAPROTECT_KEY_DERIVATION.md): dataprotect
  working keys come from keycore key material (service-derive), never from
  identifiers; includes the per-key migration runbook for legacy data.
- [SECRET_ROTATION.md](SECRET_ROTATION.md): rotating secrets on a live stack.
- [AUDIT_EVENTS_2026-09.md](AUDIT_EVENTS_2026-09.md): every audit event the
  2026-09 refresh added, and what can't be audited (startup refusals) and how
  it shows instead.
- [../PLATFORM_CONTRACT.md](../PLATFORM_CONTRACT.md) (Routes): every HTTP
  route goes through the `pkg/route` kernel, which enforces authentication,
  tenant and permission, and audits each request and refusal. Enforced by
  `make conformance` (`route-kernel`).

## Latest scan — 2026-09-25 (v1.2.0-beta)

Raw output: [`govulncheck-2026-09-25.txt`](govulncheck-2026-09-25.txt).

| Scope | Before | After | How |
|---|---|---|---|
| Go stdlib (toolchain) | 25 advisories on go1.26.0 | 0 | go1.27.1 |
| Go modules | 4 (x/text, gRPC ×3) + unmaintained x/crypto/openpgp | 0 | module updates; gRPC pinned to the upstream fix commit (no tagged release yet); openpgp → ProtonMail/go-crypto |
| Dashboard npm | 8 advisories (incl. high) | 0 | dependency updates + `npm audit fix` |

`govulncheck` is run per module path (`./pkg/...`, `./services/<svc>/...`)
because a single `./...` run needs more than 7 GB of RAM on this codebase.

Every path reports **"Your code is affected by 0 vulnerabilities."** The one
remaining *module-level* note is GO-2026-5932 (`golang.org/x/crypto/openpgp`
is unmaintained). It is listed because the package ships inside the
`golang.org/x/crypto` module; no code here imports it any more (the secrets
service moved to `github.com/ProtonMail/go-crypto/openpgp`), and the advisory
has no fixed version.

When gRPC publishes a tagged release that contains the GO-2026-6443 fix
(v1.85.0+), replace the pseudo-version in `go.mod` with that tag.

## Generating a real scan

```bash
# Go modules (CVE check against the Go vulnerability database)
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./... | tee docs/SECURITY/govulncheck-$(date +%F).txt

# Dashboard npm dependencies
( cd web/dashboard && npm audit --omit=dev )

# Cross-ecosystem SBOM/CVE scan (Go + npm + Maven)
osv-scanner scan --recursive . | tee docs/SECURITY/osv-$(date +%F).txt
```

## Notes

- Dependencies are pinned to **verified latest-stable** registry versions
  (`go get -u ./...` + `go mod tidy`; npm packages verified with
  `npm-check-updates`).
- The compliance target is **FIPS 140-3** (see the user/project docs). Do not
  assert any external certification (SOC 2, PCI DSS, HIPAA, GDPR, etc.) in this
  repo without an actual audit artifact to back it.
- `.env` is git-ignored; never commit real secrets. Bootstrap values live in
  `.env.example`.
