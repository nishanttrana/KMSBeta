# REST API Additions

This document covers the REST API surfaces that were added or expanded for the recent AI, SBOM, posture, compliance, reporting, identity, SCIM provisioning, PQC, confidential-compute, Autokey, and certificate-lifecycle functionality.

Operator-oriented explanations live here too:

- [Architecture Guide](ARCHITECTURE.md)
- [Administrator Guide](ADMIN_GUIDE.md)
- [Component Guide](COMPONENT_GUIDE.md)
- [Feature Reference](FEATURE_REFERENCE.md)
- [Operations Guide](OPERATIONS_GUIDE.md)
- [Workflow Examples](WORKFLOW_EXAMPLES.md)

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

## Sender-Constrained REST Client Security

Service prefix:

```text
/svc/auth/auth
```

Key additions:

- `POST /auth/client-token`
  - Issues client access tokens that can now be bound to a client certificate thumbprint (`oauth_mtls`) or proof key thumbprint (`dpop`)
  - Accepts HTTP Message Signature-protected token requests for clients registered in `http_message_signature` mode
- `GET /auth/clients`
  - Returns client registrations with `auth_mode`, replay-protection state, and verification counters
- `PUT /auth/clients/{id}`
  - Updates per-client auth mode, mTLS binding fields, HTTP Message Signature key material, rate limit, and IP allowlist
- `GET /auth/rest-client-security/summary`
  - Returns aggregate sender-constrained auth posture:
    - sender-constrained vs legacy clients
    - replay-protected clients
    - replay violations
    - signature failures
    - unsigned-request rejects

Operational notes:

- Resource requests protected by sender-constrained auth now emit specific audit subjects for:
  - certificate binding failures
  - DPoP failures and replay attempts
  - HTTP Message Signature failures and replay attempts
  - unsigned request blocks
- The dashboard uses this summary directly in:
  - `REST API -> REST Client Security`
  - `Posture`
  - `Compliance`

## SCIM 2.0 Provisioning

Service prefix:

```text
/svc/auth
```

Key additions:

- `GET /auth/scim/settings`
  - Returns tenant SCIM provisioning settings:
    - enablement
    - default role and status
    - whether local password change is required on first login
    - deprovision mode (`disable` or `delete`)
    - whether group-role mappings are active
- `PUT /auth/scim/settings`
  - Updates tenant SCIM provisioning settings
- `POST /auth/scim/settings/rotate-token`
  - Rotates the tenant SCIM bearer token used by the external IdP connector
  - Returns the raw bearer token once so it can be pasted into the IdP
- `GET /auth/scim/summary`
  - Returns the tenant SCIM operations summary used by the dashboard, posture, and compliance cards:
    - managed users
    - managed groups
    - memberships
    - role-mapped groups
    - last provisioned and deprovisioned timestamps
- `GET /auth/scim/users`
  - Lists SCIM-managed KMS users and their external IDs
- `GET /auth/scim/groups`
  - Lists SCIM-managed KMS groups and their membership counts
- `GET /scim/v2/ServiceProviderConfig`
- `GET /scim/v2/Schemas`
- `GET /scim/v2/ResourceTypes`
  - RFC 7643 / RFC 7644 discovery endpoints
- `GET /scim/v2/Users`
- `POST /scim/v2/Users`
- `GET /scim/v2/Users/{id}`
- `PUT /scim/v2/Users/{id}`
- `PATCH /scim/v2/Users/{id}`
- `DELETE /scim/v2/Users/{id}`
  - RFC 7644 user lifecycle endpoints
- `GET /scim/v2/Groups`
- `POST /scim/v2/Groups`
- `GET /scim/v2/Groups/{id}`
- `PUT /scim/v2/Groups/{id}`
- `PATCH /scim/v2/Groups/{id}`
- `DELETE /scim/v2/Groups/{id}`
  - RFC 7644 group lifecycle endpoints

Operational notes:

- SCIM is tenant-scoped state that lives with the Auth service and replicates with the normal auth control-plane state.
- Group-to-role enforcement is not stored inside the SCIM payload itself; directory groups are provisioned first, then mapped to existing KMS roles through the group-role binding path.
- Deprovision can either disable users for evidence retention or remove them entirely.
- SCIM lifecycle operations emit dedicated audit subjects, including:
  - `audit.auth.scim_settings_updated`
  - `audit.auth.scim_token_rotated`
  - `audit.auth.scim_user_provisioned`
  - `audit.auth.scim_user_updated`
  - `audit.auth.scim_user_disabled`
  - `audit.auth.scim_user_deprovisioned`
  - `audit.auth.scim_group_provisioned`
  - `audit.auth.scim_group_updated`
  - `audit.auth.scim_group_deleted`
- In clustered deployments, SCIM settings, managed identities, managed groups, and memberships are part of the replicated Auth control plane rather than node-local runtime cache.
- Backup coverage should therefore include SCIM settings and membership state alongside the rest of the Auth domain.
- The dashboard uses SCIM summary directly in:
  - `Administration -> User Admin -> SCIM Provisioning`
  - `Posture`
  - `Compliance`

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

## Policy-Driven Autokey / Key Handle Provisioning

Service prefix:

```text
/svc/autokey/autokey
```

Key additions:

- `GET /autokey/settings`
  - Returns the tenant Autokey control settings:
    - enablement
    - enforce vs audit mode
    - approval/justification requirements
    - template override rules
- `PUT /autokey/settings`
  - Updates the tenant Autokey control settings
- `GET /autokey/templates`
  - Lists resource templates used to generate managed handle names, key names, algorithms, purposes, labels, and approval defaults
- `POST /autokey/templates`
- `PUT /autokey/templates/{id}`
- `DELETE /autokey/templates/{id}`
  - Create, update, and delete Autokey templates
- `GET /autokey/service-policies`
  - Lists per-service default policies that define the default template and central key policy for a workload or service
- `POST /autokey/service-policies`
- `PUT /autokey/service-policies/{service}`
- `DELETE /autokey/service-policies/{service}`
  - Create, update, and delete per-service Autokey defaults
- `POST /autokey/requests`
  - Creates a key-handle provisioning request
  - The service either:
    - reuses an existing managed handle
    - creates a pending governance request
    - provisions the real key immediately through KeyCore
- `GET /autokey/requests`
  - Lists request history with status, policy-match result, approval state, and fulfilled key/handle binding
- `GET /autokey/requests/{id}`
  - Returns one request
- `GET /autokey/handles`
  - Lists the managed handle catalog for the tenant
- `GET /autokey/summary`
  - Returns the dashboard/posture/compliance summary:
    - template count
    - service-policy count
    - handle count
    - pending approvals
    - provisioned in last 24h
    - denied/failed count
    - policy matched vs mismatched count

Operational notes:

- Autokey is tenant-scoped control-plane state, not node-local state.
- Approval-required requests use the existing Governance approval engine.
- Final key creation is delegated to KeyCore, so created keys remain standard KMS keys with Autokey labels.
- The dashboard uses this summary directly in:
  - `Autokey`
  - `Posture`
  - `Compliance`

## Certificate Renewal Intelligence and ACME ARI

Service prefix:

```text
/svc/certs
```

Key additions:

- `GET /certs/renewal-intelligence`
  - Returns the tenant renewal summary used by PKI and Compliance:
    - coordinated renewal windows
    - CA-directed schedule groups
    - mass-renewal hotspots
    - missed-window and emergency-rotation counters
- `GET /certs/renewal-intelligence/{id}`
  - Returns one certificate renewal record by certificate ID
- `POST /certs/renewal-intelligence/refresh`
  - Recomputes coordinated windows and hotspot analysis immediately
- `GET /acme/renewal-info/{id}`
  - Returns RFC 9773 ACME Renewal Information with:
    - `suggestedWindow.start`
    - `suggestedWindow.end`
    - `explanationURL`
    - `Retry-After` response header

Operational notes:

- ACME protocol settings now support:
  - `enable_ari`
  - `ari_poll_hours`
  - `ari_window_bias_percent`
  - `emergency_rotation_threshold_hours`
  - `mass_renewal_risk_threshold`
- Renewal intelligence is tenant-scoped PKI state derived from certificate validity and CA grouping.
- Cluster replication treats this as part of the `certs` control-plane state, so coordinated windows and hotspot markers follow the replicated PKI state instead of staying node-local.
- Compliance posture now carries renewal-window metrics, and Security Posture now raises findings for missed windows, emergency rotations, and mass-renewal hotspots using the audited cert lifecycle events.
- Governance backup coverage includes certificate renewal intelligence when the `cert_renewal_intelligence` table is present.
- Audit subjects now include:
  - `audit.cert.renewal_schedule_viewed`
  - `audit.cert.renewal_window_missed`
  - `audit.cert.emergency_rotation_started`
  - `audit.cert.mass_renewal_risk_detected`

## Key Access Justifications

Service prefix:

```text
/svc/keyaccess
```

Key additions:

- `GET /key-access/settings`
  - Returns tenant enablement, default action, and whether code or text justifications are mandatory
- `PUT /key-access/settings`
  - Updates the tenant external-key justification enforcement mode
- `GET /key-access/summary`
  - Returns counters used by Dashboard, Posture, and Compliance:
    - total requests
    - allowed / denied / approval-held
    - unjustified requests
    - bypass signals
- `GET /key-access/codes`
  - Lists reason-code rules
- `POST /key-access/codes`
  - Creates a new reason-code rule
- `PUT /key-access/codes/{id}`
  - Updates a rule
- `DELETE /key-access/codes/{id}`
  - Deletes a rule
- `GET /key-access/decisions`
  - Lists evaluated decisions

Operational notes:

- This is tenant-scoped control-plane policy for HYOK, EKM, cloud, and similar external-key usage paths.
- Approval-required branches reuse Governance rather than introducing a second approval engine.
- Cluster replication carries settings, rules, and decision history, while short-lived anti-replay or request caches remain node-local.
- Governance backup coverage includes key-access settings, rules, and decision history.

## Artifact Signing And Keyless Provenance

Service prefix:

```text
/svc/signing
```

Key additions:

- `GET /signing/settings`
  - Returns tenant artifact-signing policy and allowed identity modes
- `PUT /signing/settings`
  - Updates tenant signing defaults and transparency requirements
- `GET /signing/summary`
  - Returns the dashboard/posture/compliance summary:
    - profile count
    - signed records in last 24h
    - transparency logged count
    - workload vs OIDC signing distribution
    - verification failures
- `GET /signing/profiles`
  - Lists signing profiles
- `POST /signing/profiles`
  - Creates a signing profile
- `PUT /signing/profiles/{id}`
  - Updates a signing profile
- `DELETE /signing/profiles/{id}`
  - Deletes a signing profile
- `GET /signing/records`
  - Lists prior signing records
- `POST /signing/blob`
  - Signs a generic blob
- `POST /signing/git`
  - Signs Git-oriented artifact metadata
- `POST /signing/verify`
  - Re-verifies a stored record

Operational notes:

- Signing profiles are tenant-scoped control-plane state, not runtime-only cache.
- Signing records carry transparency-linked metadata that is preserved in governance backup coverage.
- Cluster replication carries signing settings, profiles, and signature records so provenance state survives node failover.

## Threshold Signing And MPC/FROST Workflows

Service prefix:

```text
/svc/mpc
```

Important routes already in the platform and now treated as first-class evidence surfaces:

- `GET /mpc/overview`
- `GET /mpc/participants`
- `GET /mpc/policies`
- `GET /mpc/keys`
- `GET /mpc/ceremonies`
- `POST /mpc/dkg/initiate`
- `POST /mpc/sign/initiate`
- `POST /mpc/sign/{id}/contribute`
- `GET /mpc/sign/{id}/result`

Operational notes:

- The KMS uses the existing MPC service for quorum-backed key ceremonies and FROST-style operational separation of trust.
- Cluster replication already includes MPC state in the full cluster profile.
- Governance backup coverage now includes MPC participant, policy, key, share-backup, and ceremony metadata.
- Audit classification now explicitly recognizes DKG, threshold signing, threshold decryption, share backup, participant, and policy lifecycle events.

## ACME STAR Short-Lived Certificates

Service prefix:

```text
/svc/certs
```

Key additions:

- `GET /certs/star/summary`
  - Returns tenant STAR posture used by PKI and Compliance:
    - total subscriptions
    - delegated subscriber count
    - due-soon subscriptions
    - rollout-group risk counts
- `GET /certs/star/subscriptions`
  - Lists STAR subscriptions with issuance counters, next renewal time, and latest certificate pointer
- `POST /certs/star/subscriptions`
  - Creates a short-lived subscription under the tenant ACME STAR policy
- `POST /certs/star/subscriptions/{id}/refresh`
  - Forces immediate re-issuance for a STAR subscription
- `DELETE /certs/star/subscriptions/{id}`
  - Removes a STAR subscription and stops future renewal activity for it

Operational notes:

- ACME protocol settings now support:
  - `enable_star`
  - `default_star_validity_hours`
  - `max_star_validity_hours`
  - `allow_star_delegation`
  - `max_star_subscriptions`
  - `star_mass_rollout_threshold`
- STAR subscriptions are tenant-scoped PKI control-plane state, not node-local cache.
- Cluster replication carries delegated subscriber metadata, next-renewal cadence, latest certificate pointers, and rollout-group assignments with the `certs` service state.
- Governance backup coverage includes the STAR subscription catalog and delegated subscriber metadata in the certificate backup scope.
- Audit subjects now include:
  - `audit.cert.star_summary_viewed`
  - `audit.cert.star_subscription_created`
  - `audit.cert.star_subscription_renewed`
  - `audit.cert.star_subscription_deleted`
  - `audit.cert.star_subscription_failed`
  - `audit.cert.star_delegation_configured`
  - `audit.cert.star_mass_rollout_risk_detected`

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

Backup artifact and key downloads now carry explicit `backup_coverage` metadata so operators can see which capability classes were preserved. When Autokey tables are present, tenant Autokey settings, resource templates, per-service defaults, request catalogs, and managed key-handle bindings are included in the encrypted snapshot.

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
