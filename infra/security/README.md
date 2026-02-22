# Supply Chain Security Pipeline

This directory implements the Section C "Supply Chain Security & Side-Channel Defense" pipeline for Vecta KMS.

## Checks

- `license-audit.sh`: scans Go dependencies and flags prohibited licenses (GPL/AGPL/SSPL and related blocklist entries).
- `cve-scan.sh`: scans all `vecta/*` container images from `docker-compose.yml` using Trivy and/or Grype.
- `side-channel-suite.sh`: runs timing and memory hardening tests in `side-channel-tests/`.
- `sbom-embed.sh`: generates CycloneDX SBOM files with Syft and embeds each SBOM into the image as `/opt/vecta/sbom/cyclonedx.json` plus OCI labels.
- `audit-pipeline.sh`: orchestrates all checks and generates consolidated pass/fail reports.

## Usage

Run the full pipeline:

```bash
bash infra/security/audit-pipeline.sh
```

Run individual checks:

```bash
bash infra/security/license-audit.sh
bash infra/security/cve-scan.sh
bash infra/security/side-channel-suite.sh
bash infra/security/sbom-embed.sh
```

## Outputs

Reports are written to:

- `infra/security/reports/<timestamp>/`
- `infra/security/reports/latest/`

Artifacts include:

- `audit-report.md` and `audit-report.json`
- per-check `status.txt`, `summary.txt`
- detailed CSV/JSON scanner outputs

## Required Tools

- Go toolchain (`go`)
- Docker (`docker`)
- Trivy (`trivy`) and/or Grype (`grype`)
- Syft (`syft`)

Optional:

- `jq` for more robust JSON parsing in scanner outputs
