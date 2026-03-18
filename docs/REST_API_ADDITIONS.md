# REST API Additions

This document covers the REST API surfaces that were added or expanded for the recent AI, SBOM, posture, compliance, and reporting functionality.

Machine-readable OpenAPI specs for these services are available in [docs/openapi/README.md](openapi/README.md).

Generate them with:

```powershell
npm.cmd --prefix web/dashboard run generate:openapi
```

Validate committed OpenAPI artifacts with:

```powershell
npm.cmd --prefix web/dashboard run validate:openapi
```

## Common Conventions

- Dashboard proxy base path: `/svc/<service>`
- Edge/API base path through Envoy: `/api/<service>`
- Authentication: `Authorization: Bearer <jwt>`
- Tenant scoping:
  - Prefer `tenant_id` query parameter when the endpoint requires it
  - `X-Tenant-ID` is also accepted by tenant-aware handlers
- Response envelope:
  - Success responses usually return a top-level object such as `config`, `result`, `item`, `items`, `summary`, `snapshot`, or `diff`
  - Most handlers also include `request_id`
- Error envelope:

```json
{
  "error": {
    "code": "bad_request",
    "message": "tenant_id is required",
    "request_id": "req_123",
    "tenant_id": "root"
  }
}
```

## Security Posture Management

Service prefix:

```text
/svc/posture/posture
```

Key additions:

- `GET /posture/dashboard` now returns the richer posture dashboard payload used by the UI:
  - `risk_drivers`
  - `remediation_cockpit`
  - `blast_radius`
  - `scenario_simulator`
  - `validation_badges`
  - `sla_overview`
- `GET /posture/findings` returns findings enriched with `risk_drivers` and `blast_radius`.
- `GET /posture/actions` returns remediation actions enriched with:
  - `impact_estimate`
  - `rollback_hint`
  - `blast_radius`
  - `priority`
- `POST /posture/actions/{id}/execute` executes an approved or safe remediation action.

These routes are also published in the generated `posture.openapi.*` spec.

## Compliance

Service prefix:

```text
/svc/compliance/compliance
```

Key additions:

- `GET /compliance/assessment/delta`
  - Compares the latest and previous real assessment
  - Returns `added_findings`, `resolved_findings`, `recovered_domains`, `regressed_domains`, and `new_failing_connectors`
- `GET /compliance/assessment/history`
  - Supports trend rendering and "what changed since last scan" workflows
- `POST /compliance/assessment/run`
  - Supports template-scoped manual assessments with optional recompute

These routes are also published in the generated `compliance.openapi.*` spec.

## Reporting and Evidence Packs

Service prefix:

```text
/svc/reporting
```

Key additions:

- `GET /reports/templates`
  - Includes the `evidence_pack` template used by the Compliance tab
- `POST /reports/generate`
  - Supports `template_id=evidence_pack` for one-click audit exports containing posture findings, actions, approvals, incidents, timestamps, and tenant scope
- `GET /alerts/stats/mttd`
  - Returns mean time to detect by severity
- `GET /alerts/stats/mttr`
  - Returns mean time to resolve by severity
- `GET /alerts/stats/top-sources`
  - Returns the top actors, IPs, and services behind alert generation

These routes are also published in the generated `reporting.openapi.*` spec.

## Backup Coverage Notes

Governance backups already include the stored state behind posture/compliance/reporting when the corresponding tables exist, while still excluding:

- audit event partitions
- alert runtime tables
- operational log tables
- the backup job catalog itself

Backup artifact and key downloads now carry explicit `backup_coverage` metadata so operators can see which capability classes were preserved.

## AI Service

Service prefix:

```text
/svc/ai/ai
```

### Purpose

The AI service provides:

- provider-backed assistant responses
- governance-aware context assembly
- redaction before prompt delivery
- provider authentication configuration
- MCP compatibility metadata for external agent/tooling workflows

### GET /ai/config

Returns the saved AI configuration for a tenant.

Example request:

```http
GET /svc/ai/ai/config?tenant_id=root
Authorization: Bearer <jwt>
X-Tenant-ID: root
```

Example response:

```json
{
  "config": {
    "tenant_id": "root",
    "backend": "claude",
    "endpoint": "https://api.anthropic.com/v1/messages",
    "model": "claude-sonnet-4-6",
    "api_key_secret": "ai-provider-token",
    "provider_auth": {
      "required": true,
      "type": "bearer"
    },
    "mcp": {
      "enabled": false,
      "endpoint": ""
    },
    "max_context_tokens": 8000,
    "temperature": 0.3,
    "context_sources": {
      "keys": { "enabled": true, "limit": 25, "fields": ["id", "name", "algorithm", "status"] },
      "policies": { "enabled": true, "all": false, "limit": 20 },
      "audit": { "enabled": true, "last_hours": 24, "limit": 100 },
      "posture": { "enabled": true, "current": true },
      "alerts": { "enabled": true, "unresolved": true, "limit": 50 }
    },
    "redaction_fields": [
      "encrypted_material",
      "wrapped_dek",
      "pwd_hash",
      "api_key",
      "passphrase"
    ],
    "updated_at": "2026-03-11T09:30:00Z"
  },
  "request_id": "req_123"
}
```

### PUT /ai/config

Updates the tenant AI configuration.

Example request:

```http
PUT /svc/ai/ai/config?tenant_id=root
Authorization: Bearer <jwt>
Content-Type: application/json
```

```json
{
  "backend": "copilot",
  "endpoint": "https://api.githubcopilot.com/chat/completions",
  "model": "gpt-4o",
  "api_key_secret": "copilot-token",
  "provider_auth": {
    "required": true,
    "type": "bearer"
  },
  "mcp": {
    "enabled": true,
    "endpoint": "mcp://kms-ai"
  },
  "max_context_tokens": 12000,
  "temperature": 0.2,
  "context_sources": {
    "keys": { "enabled": true, "limit": 25, "fields": ["id", "name", "algorithm", "status"] },
    "policies": { "enabled": true, "all": false, "limit": 20 },
    "audit": { "enabled": true, "last_hours": 24, "limit": 100 },
    "posture": { "enabled": true, "current": true },
    "alerts": { "enabled": true, "unresolved": true, "limit": 50 }
  },
  "redaction_fields": [
    "encrypted_material",
    "wrapped_dek",
    "pwd_hash",
    "api_key",
    "passphrase"
  ]
}
```

Validation notes:

- `backend` must be supported by the AI service
- managed providers require `provider_auth.required=true`
- supported auth types are `api_key` and `bearer`
- `endpoint` is required for provider-backed configurations
- if `mcp.enabled=true`, `mcp.endpoint` must be set

### POST /ai/query

Submits a natural-language assistant request.

Example request:

```json
{
  "tenant_id": "root",
  "query": "Analyze recent unresolved alerts and recommend actions",
  "include_context": true
}
```

Example response:

```json
{
  "result": {
    "action": "query",
    "tenant_id": "root",
    "answer": "There are 3 unresolved alerts. Start with the posture risk spike and the pending approval backlog.",
    "backend": "claude",
    "model": "claude-sonnet-4-6",
    "redactions_applied": 4,
    "context_summary": {
      "keys": 12,
      "policies": 6,
      "audit_events": 45,
      "alerts": 3
    },
    "warnings": [],
    "generated_at": "2026-03-11T09:40:00Z"
  },
  "request_id": "req_124"
}
```

### POST /ai/analyze/incident

Produces an AI explanation for a security or governance event.

Example request:

```json
{
  "tenant_id": "root",
  "incident_id": "inc-001",
  "title": "Unauthorized key export attempt",
  "description": "A privileged user attempted an export against a production key.",
  "details": {
    "key_id": "key_123",
    "actor": "ops-admin",
    "approval_status": "missing"
  }
}
```

### POST /ai/recommend/posture

Builds posture guidance for the requested focus area.

Example request:

```json
{
  "tenant_id": "root",
  "focus": "key-rotation"
}
```

The service can return either a provider-backed answer or a fallback deterministic answer with warnings when the configured provider is unavailable.

### POST /ai/explain/policy

Explains a policy by ID or from an inline policy object.

Example request:

```json
{
  "tenant_id": "root",
  "policy_id": "policy-rotate-90d",
  "policy": {
    "id": "policy-rotate-90d",
    "name": "Rotate every 90 days",
    "status": "active"
  }
}
```

## SBOM and CBOM Service

Service prefix:

```text
/svc/sbom
```

### Purpose

The SBOM service now supports:

- software BOM generation
- crypto BOM generation
- merged vulnerability correlation
- offline advisory management
- air-gapped advisory workflows
- OSV-backed dependency findings
- Trivy-backed repository findings

### Vulnerability Source Order

The vulnerability list returned by `/sbom/vulnerabilities` is assembled from:

1. Manual OSV advisories stored in KMS
2. OSV online package matches
3. Trivy repository scan findings

This allows disconnected environments to operate with manually entered advisories while still using richer sources when internet access is available.

### POST /sbom/generate

Generates a fresh software BOM snapshot.

Example request:

```json
{
  "trigger": "manual"
}
```

Example response:

```json
{
  "status": "accepted",
  "snapshot": {
    "id": "sbom_20260311_001",
    "created_at": "2026-03-11T09:45:00Z"
  },
  "request_id": "req_200"
}
```

### GET /sbom/vulnerabilities

Returns the merged vulnerability findings for the latest SBOM snapshot.

Example response:

```json
{
  "items": [
    {
      "id": "CVE-2026-1000",
      "source": "OSV",
      "severity": "high",
      "component": "golang.org/x/net",
      "installed_version": "v0.20.0",
      "fixed_version": "v0.35.0",
      "summary": "HTTP issue in golang.org/x/net.",
      "reference": "https://osv.dev/vulnerability/GO-2026-0001"
    },
    {
      "id": "CVE-2025-29923",
      "source": "Trivy",
      "severity": "low",
      "component": "github.com/redis/go-redis/v9",
      "installed_version": "v9.7.0",
      "fixed_version": "9.7.3",
      "summary": "go-redis vulnerability",
      "reference": "https://avd.aquasec.com/nvd/cve-2025-29923"
    }
  ],
  "request_id": "req_201"
}
```

### GET /sbom/advisories

Lists manually managed offline advisories.

Example response:

```json
{
  "items": [
    {
      "id": "CVE-2026-5000",
      "component": "example/module",
      "ecosystem": "go",
      "introduced_version": "v1.0.0",
      "fixed_version": "v1.3.0",
      "severity": "critical",
      "summary": "Offline advisory",
      "reference": "https://example.test/CVE-2026-5000",
      "created_at": "2026-03-11T09:46:00Z",
      "updated_at": "2026-03-11T09:46:00Z"
    }
  ],
  "request_id": "req_202"
}
```

### POST /sbom/advisories

Creates or updates a manual advisory for offline environments.

Example request:

```json
{
  "id": "CVE-2026-5000",
  "component": "example/module",
  "ecosystem": "go",
  "introduced_version": "v1.0.0",
  "fixed_version": "v1.3.0",
  "severity": "critical",
  "summary": "Offline advisory for an air-gapped deployment",
  "reference": "https://example.test/CVE-2026-5000"
}
```

Example response:

```json
{
  "item": {
    "id": "CVE-2026-5000",
    "component": "example/module",
    "ecosystem": "go",
    "fixed_version": "v1.3.0",
    "severity": "critical",
    "summary": "Offline advisory for an air-gapped deployment"
  },
  "request_id": "req_203"
}
```

### DELETE /sbom/advisories/{id}

Deletes a manual advisory by advisory ID.

Example request:

```http
DELETE /svc/sbom/sbom/advisories/CVE-2026-5000?tenant_id=root
Authorization: Bearer <jwt>
```

### POST /cbom/generate

Generates a fresh cryptographic BOM snapshot for the tenant.

Example request:

```json
{
  "tenant_id": "root",
  "trigger": "manual"
}
```

### GET /cbom/pqc-readiness

Returns post-quantum readiness metrics derived from the latest CBOM.

Example response:

```json
{
  "pqc_readiness": {
    "total_assets": 42,
    "pqc_ready_count": 8,
    "pqc_readiness_percent": 19,
    "deprecated_count": 4,
    "algorithm_distribution": {
      "AES": 16,
      "RSA": 9,
      "ECDSA": 9,
      "ML-DSA": 8
    },
    "strength_histogram": {
      "128": 8,
      "256": 34
    }
  },
  "request_id": "req_204"
}
```

## Dashboard REST Catalog

The dashboard REST API tab merges:

- curated catalog entries from `web/dashboard/src/components/v3/restApiCatalog.ts`
- discovered routes generated from Go handlers into `web/dashboard/src/generated/restApiCatalog.generated.ts`

The generator is:

```text
web/dashboard/scripts/generate-rest-catalog.mjs
```

Run:

```bash
npm --prefix web/dashboard run generate:rest-catalog
```

This should be rerun whenever handler routes are added or updated.
