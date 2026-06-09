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
