# OpenAPI Specs

Machine-readable OpenAPI 3.0.3 specs for the recently expanded KMS services live in this directory.

Files:

- `ai.openapi.yaml`
- `ai.openapi.json`
- `sbom.openapi.yaml`
- `sbom.openapi.json`

Dashboard-served viewer pages:

- `/openapi/ai.html`
- `/openapi/sbom.html`

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
- Specs include both dashboard proxy base URLs and direct localhost service URLs.
- The dashboard exposes a local Swagger UI viewer for each generated spec.
