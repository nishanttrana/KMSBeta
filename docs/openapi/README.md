# OpenAPI Specs

Machine-readable OpenAPI 3.0.3 specs for the recently expanded KMS services live in this directory.

Files:

- `ai.openapi.yaml`
- `ai.openapi.json`
- `sbom.openapi.yaml`
- `sbom.openapi.json`
- `posture.openapi.yaml`
- `posture.openapi.json`
- `compliance.openapi.yaml`
- `compliance.openapi.json`
- `reporting.openapi.yaml`
- `reporting.openapi.json`

Dashboard-served viewer pages:

- `/openapi/ai.html`
- `/openapi/sbom.html`
- `/openapi/posture.html`
- `/openapi/compliance.html`
- `/openapi/reporting.html`

Generation command:

```powershell
npm.cmd --prefix web/dashboard run generate:openapi
```

Validation command:

```powershell
npm.cmd --prefix web/dashboard run validate:openapi
```

Notes:

- `ai.openapi.*` documents the AI configuration and assistant endpoints.
- `sbom.openapi.*` documents SBOM generation, merged vulnerability findings, offline manual advisories, and CBOM/PQC readiness endpoints.
- `posture.openapi.*` documents posture dashboards, risk drivers, remediation cockpit actions, blast radius summaries, and scenario simulation workflows.
- `compliance.openapi.*` documents compliance posture, assessment execution/history, delta comparisons, and template-backed scoring.
- `reporting.openapi.*` documents evidence-pack generation, report jobs, and alert timing analytics including MTTD and MTTR.
- Specs include both dashboard proxy base URLs and direct localhost service URLs.
- The dashboard exposes a local Swagger UI viewer for each generated spec.
