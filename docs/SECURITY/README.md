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

## Latest scan — 2026-09-25 (v1.2.0-beta)

Raw output: [`govulncheck-2026-09-25.txt`](govulncheck-2026-09-25.txt).

| Scope | Before | After | How |
|---|---|---|---|
| Go stdlib (toolchain) | 25 advisories on go1.26.0 | 0 | go1.27.1 |
| Go modules | 4 (x/text, gRPC ×3) + unmaintained x/crypto/openpgp | 0 | module updates; gRPC pinned to the upstream fix commit (no tagged release yet); openpgp → ProtonMail/go-crypto |
| Dashboard npm | 8 advisories (incl. high) | 0 | dependency updates + `npm audit fix` |

`govulncheck` is run per module path (`./pkg/...`, `./services/<svc>/...`)
because a single `./...` run needs more than 7 GB of RAM on this codebase.

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
