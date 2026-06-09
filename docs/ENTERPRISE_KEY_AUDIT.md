# Enterprise Key Audit, Analytics, and Response

> Version: Beta - Last updated 2026-06-09
> Audience: Security Operations, KMS Administrators, Compliance Officers, Platform Engineers

This guide documents the Tier 1 enterprise-value audit implementation for Vecta KMS. It turns the identified quick wins into an API-backed operating model for rotation analytics, compromise response, key analytics, health scoring, and inventory/dependency mapping.

## Scope

Implemented Tier 1 capabilities:

| Capability | Status | Primary Outcome |
|---|---|---|
| Key Rotation Analytics Dashboard | Implemented | Rotation schedules, success rates, overdue rotations, batch visibility |
| Key Compromise Detection and Response | Implemented | Advisory/event ingestion, automatic suspension, incident status tracking |
| Advanced Key Analytics and Reporting | Implemented | Usage metrics, hotspots, trends, algorithm latency benchmarks |
| Key Health Scoring and Monitoring | Implemented | 0-100 health score, backup status, expiry/rotation warnings, recommendations |
| Key Inventory and Dependency Mapping | Implemented | Key inventory sync, dependency records, orphaned key and duplicate KCV detection |

Tier 2-4 items remain documented roadmap/foundation items. Existing platform foundations already cover parts of scheduling, escrow, Merkle audit, KDF, key verification, compliance, binding, edge agents, sharing, metadata, and threat protection.

## Data Model

The KeyCore migration `010_tier1_features.sql` adds six tenant-scoped tables:

| Table | Purpose |
|---|---|
| `key_rotation_metrics` | Records scheduled, in-progress, completed, failed, and cancelled rotations. |
| `key_analytics_metrics` | Stores time-series usage, latency, trend, and custom key metrics. |
| `key_health_scores` | Stores latest calculated key health score and recommendations. |
| `key_inventory` | Maintains normalized inventory for each key across source systems. |
| `key_dependencies` | Maps keys to services/apps and operational criticality. |
| `compromise_events` | Tracks suspected/confirmed compromise events and remediation workflow state. |

All tables are tenant-scoped and have row-level security policies using `app.tenant_id`, matching KeyCore's existing tenant isolation model.

## API Overview

All examples use the dashboard proxy form:

```bash
BASE="http://localhost:5173/svc/keycore"
TENANT="root"
AUTH="Authorization: Bearer $TOKEN"
```

### Enterprise Summary

```bash
curl "$BASE/enterprise/summary?tenant_id=$TENANT&days=30" -H "$AUTH"
```

Returns one consolidated view:

- rotation summary
- health summary
- inventory summary
- compromise summary
- key hotspots
- algorithm benchmarks
- roadmap implementation state

Use this endpoint for an executive or SOC landing view.

## Rotation Analytics

Rotation analytics are recorded automatically when `RotateKey` runs. Manual records can also be posted by schedulers, batch tools, or external KMS adapters.

### Summary

```bash
curl "$BASE/rotation/analytics?tenant_id=$TENANT&days=30" -H "$AUTH"
```

Response includes:

- total rotations
- scheduled, in-progress, completed, failed, cancelled counts
- overdue count
- success rate
- average duration
- batch operation count
- next scheduled and last completed timestamps

### Overdue Rotations

```bash
curl "$BASE/rotation/analytics/overdue?tenant_id=$TENANT&limit=100" -H "$AUTH"
```

### Per-Key Rotation Metrics

```bash
curl "$BASE/keys/$KEY_ID/rotation-metrics?tenant_id=$TENANT&status=completed" -H "$AUTH"
```

### Record an External Rotation Metric

```bash
curl -X POST "$BASE/keys/$KEY_ID/rotation-metrics?tenant_id=$TENANT" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "rotation_id": "batch-2026-06-09-001",
    "scheduled_date": "2026-06-09T01:00:00Z",
    "actual_date": "2026-06-09T01:02:14Z",
    "status": "completed",
    "duration_ms": 134000,
    "reason": "bulk-quarterly",
    "initiated_by": "rotation-scheduler",
    "completed_by": "keycore",
    "old_version": 3,
    "new_version": 4,
    "metadata": {
      "batch_id": "q2-critical-data-keys"
    }
  }'
```

## Compromise Detection and Response

Compromise response accepts direct events and feed-style advisories. High and critical events can automatically suspend active keys. Deactivated keys can be promoted to `compromised` when the lifecycle state machine allows it.

### Report a Single Compromise Event

```bash
curl -X POST "$BASE/compromise/events?tenant_id=$TENANT" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "key_id": "'"$KEY_ID"'",
    "cve_id": "CVE-2026-0001",
    "threat_type": "cve",
    "severity": "critical",
    "detection_source": "nvd-feed",
    "auto_suspend": true,
    "affected_systems": ["payments-api", "settlement-worker"],
    "metadata": {
      "feed_score": 9.8
    }
  }'
```

For high or critical events, `auto_suspend=true` changes an active key to `suspended` and emits audit event `audit.key.compromise_auto_suspended`.

### Ingest Feed Advisories

```bash
curl -X POST "$BASE/compromise/advisories/ingest?tenant_id=$TENANT" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "auto_suspend": true,
    "advisories": [
      {
        "cve_id": "CVE-2026-0001",
        "threat_type": "algorithm_weakness",
        "severity": "high",
        "summary": "Example advisory impacting RSA-2048 estate",
        "affected_algorithms": ["RSA-2048"],
        "detection_source": "nvd"
      }
    ]
  }'
```

The ingest flow expands `affected_algorithms` and `affected_key_ids` into individual compromise events.

### List Events

```bash
curl "$BASE/compromise/events?tenant_id=$TENANT&status=pending&severity=high" -H "$AUTH"
```

### Update Event Status

```bash
curl -X POST "$BASE/compromise/events/$EVENT_ID/status?tenant_id=$TENANT" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "status": "confirmed",
    "remediation_status": "in_progress",
    "root_cause": "vendor advisory matched local algorithm inventory",
    "notifications_sent": ["security-oncall", "kms-owner"]
  }'
```

Recommended incident statuses:

| Status | Meaning |
|---|---|
| `pending` | Event was created and awaits triage. |
| `investigating` | SOC or key owner is validating impact. |
| `confirmed` | Compromise or weakness is confirmed. |
| `false_positive` | Event is closed as non-impacting. |
| `resolved` | Remediation is complete and evidence is attached. |

Recommended remediation statuses:

| Status | Meaning |
|---|---|
| `not_started` | No remediation has started. |
| `in_progress` | Rotation, replacement, notification, or validation is underway. |
| `completed` | Required remediation has completed. |

## Advanced Key Analytics

Crypto operations automatically record realtime usage and latency metrics. External systems can post custom metrics for cloud KMS adapters, KMIP operations, or HSM vendor telemetry.

### Record a Metric

```bash
curl -X POST "$BASE/analytics/metrics?tenant_id=$TENANT" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "key_id": "'"$KEY_ID"'",
    "metric_type": "latency_encrypt",
    "value": 18,
    "aggregation_period": "realtime",
    "timestamp": "2026-06-09T12:00:00Z",
    "metadata": {
      "service": "payments-api",
      "region": "us-east-1"
    }
  }'
```

### Usage Summary

```bash
curl "$BASE/analytics/usage?tenant_id=$TENANT&key_id=$KEY_ID&days=7" -H "$AUTH"
```

### Hotspot Keys

```bash
curl "$BASE/analytics/hotspots?tenant_id=$TENANT&days=7&limit=20" -H "$AUTH"
```

Use hotspots to find:

- keys with unexpectedly high access
- services concentrating encryption traffic
- keys that need dedicated HSM capacity
- candidates for caching or envelope encryption optimization

### Trend Data

```bash
curl "$BASE/analytics/trends?tenant_id=$TENANT&metric_type=usage_encrypt&days=30" -H "$AUTH"
```

### Algorithm Benchmarks

```bash
curl "$BASE/analytics/algorithms?tenant_id=$TENANT&days=7" -H "$AUTH"
```

Benchmarks group latency metrics by key algorithm and operation, returning a performance band:

| Band | Average Latency |
|---|---|
| `excellent` | 25 ms or lower |
| `good` | 100 ms or lower |
| `fair` | 250 ms or lower |
| `poor` | Above 250 ms |

## Health Scoring

Key health is calculated from:

- algorithm strength
- estimated entropy/security level
- key age
- usage activity
- backup verification status
- rotation overdue status
- expiry window
- lifecycle state

### Get or Calculate Key Health

```bash
curl "$BASE/keys/$KEY_ID/health?tenant_id=$TENANT" -H "$AUTH"
```

If no score exists yet, KeyCore calculates and stores one.

### Force Recalculation

```bash
curl -X POST "$BASE/keys/$KEY_ID/health/recalculate?tenant_id=$TENANT" -H "$AUTH"
```

### Tenant Health Summary

```bash
curl "$BASE/health/summary?tenant_id=$TENANT&limit=50" -H "$AUTH"
```

Score bands:

| Score | Meaning | Default Action |
|---|---|---|
| 80-100 | Healthy | Continue scheduled monitoring. |
| 60-79 | Watch | Review recommendations and next rotation. |
| 40-59 | At risk | Open key owner review. |
| 0-39 | Critical | Treat as urgent operational/security work. |

## Inventory and Dependency Mapping

Inventory can be synced from KeyCore metadata and enriched with backup/HSM/cloud/source metadata. Dependencies are explicit records that connect a key to a service or application.

### Sync Inventory

```bash
curl -X POST "$BASE/inventory/sync?tenant_id=$TENANT" -H "$AUTH"
```

Sync also recalculates health for synced keys.

### List Inventory

```bash
curl "$BASE/inventory/keys?tenant_id=$TENANT&status=active&owner=security&limit=100" -H "$AUTH"
```

### Orphaned Keys

```bash
curl "$BASE/inventory/orphans?tenant_id=$TENANT&limit=100" -H "$AUTH"
```

An orphaned key is an active, pre-active, or suspended inventory item with no dependency records. Orphan status is not automatically destructive; it is a review signal.

### Duplicate Key Detection

```bash
curl "$BASE/inventory/duplicates?tenant_id=$TENANT" -H "$AUTH"
```

Duplicate groups are based on matching algorithm and KCV. This detects likely duplicated material without exposing key material.

### Add or Update Dependency

```bash
curl -X POST "$BASE/inventory/dependencies?tenant_id=$TENANT" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "dependency_id": "dep-payments-api-primary",
    "key_id": "'"$KEY_ID"'",
    "service_id": "payments-api",
    "app_id": "payments",
    "dependency_type": "encryption",
    "criticality": "critical",
    "verification_status": "verified",
    "usage_frequency": "high",
    "metadata": {
      "owner_group": "payments-platform"
    }
  }'
```

### List Dependencies

```bash
curl "$BASE/inventory/dependencies?tenant_id=$TENANT&key_id=$KEY_ID" -H "$AUTH"
```

## Tier 2-4 Enterprise Controls and DSPM

The second implementation pass turns the remaining roadmap items into backend capabilities. The design is intentionally secure-by-default:

- no raw key material is persisted in enterprise control records or DSPM findings
- KDF and Shamir APIs return sensitive material only in the direct response
- unsupported research cryptography is represented as governed control state instead of fake encryption
- every state-changing endpoint emits a KeyCore audit event
- high-risk control records are mirrored into KeyCore DSPM findings and can be exported as posture events

### Enterprise Control Records

Enterprise control records are the common persistence model for orchestration, federation, edge agents, sharing grants, metadata profiles, binding policies, threat signals, and advanced encryption mode governance.

```bash
curl -X POST "$BASE/enterprise/federation/providers?tenant_id=$TENANT" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "record_id": "fed-aws-prod",
    "name": "AWS KMS production",
    "status": "active",
    "severity": "info",
    "metadata": {
      "provider": "aws-kms",
      "regions": ["us-east-1", "us-west-2"],
      "lookup_mode": "external_id_mapping"
    }
  }'
```

List controls:

```bash
curl "$BASE/enterprise/controls?tenant_id=$TENANT&category=federation_provider" -H "$AUTH"
```

Supported categories include:

| Category | Capability |
|---|---|
| `anomaly` | Statistical anomaly findings generated from health, compromise, inventory, hotspot, and benchmark signals. |
| `orchestration_workflow` / `orchestration_run` | Cron/workflow metadata and executable batch rotation runs. |
| `federation_provider`, `federation_mapping`, `federation_failover` | Multi-KMS registry, cross-KMS mappings, and failover evidence. |
| `escrow_tier`, `escrow_shamir` | Tiered recovery metadata and Shamir split verification. |
| `advanced_encryption` | Searchable token mode plus governed research-mode controls. |
| `binding_policy` | Hardware attestation/geolocation binding policy records. |
| `edge_agent`, `edge_lease`, `edge_receipt` | Edge/IoT agent, offline lease, and receipt records. |
| `sharing_grant` | Temporary/delegated key sharing records. |
| `metadata_profile` | Classification, tagging, and enrichment profiles. |
| `threat_signal` | Side-channel, DPA, canary, or other advanced threat signals. |

### Anomaly Detection and DSPM Feed

Run a statistical anomaly scan:

```bash
curl -X POST "$BASE/enterprise/anomaly/scan?tenant_id=$TENANT&days=7" -H "$AUTH"
```

The scan creates DSPM findings for:

- degraded key health
- open compromise events
- inventory/dependency gaps
- heavy key usage hotspots
- algorithm benchmark degradation

List KeyCore DSPM findings:

```bash
curl "$BASE/enterprise/dspm/findings?tenant_id=$TENANT&status=open&limit=100" -H "$AUTH"
```

Export posture-service-compatible events:

```bash
curl "$BASE/enterprise/dspm/events?tenant_id=$TENANT&status=open" -H "$AUTH"
```

The export shape matches the existing DSPM/posture `/posture/events/batch` ingestion schema. The audit service also receives `audit.key.dspm_finding_upserted`, so posture can ingest through the existing audit sync path.

### Advanced Scheduling and Orchestration

Create workflow metadata:

```bash
curl -X POST "$BASE/enterprise/orchestration/workflows?tenant_id=$TENANT" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "record_id": "wf-quarterly-critical",
    "name": "Quarterly critical-key rotation",
    "status": "active",
    "metadata": {
      "cron_expr": "0 2 1 */3 *",
      "steps": ["dependency_check", "rotate", "health_recalculate", "dspm_export"]
    }
  }'
```

Trigger an executable batch rotation run:

```bash
curl -X POST "$BASE/enterprise/orchestration/runs?tenant_id=$TENANT" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "workflow_id": "wf-quarterly-critical",
    "key_ids": ["key-prod-001", "key-prod-002"],
    "reason": "quarterly-critical-rotation",
    "execute_rotation": true
  }'
```

Failures are retained in the run metadata and become DSPM findings when risk is elevated.

### KDF Support

The enterprise KDF API supports HKDF-SHA256, PBKDF2-SHA256, Scrypt, and Argon2id. Secrets and derived keys are never persisted; audit records include only hashes, algorithm, length, and parameter summary.

```bash
curl -X POST "$BASE/enterprise/kdf/derive?tenant_id=$TENANT" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "algorithm": "argon2id",
    "secret_base64": "'"$(printf 'source-secret-source-secret-32!!' | base64)"'",
    "salt_base64": "'"$(printf 'tenant-salt-123456' | base64)"'",
    "length": 32,
    "iterations": 3,
    "memory_kib": 65536,
    "parallelism": 1
  }'
```

Minimums:

- PBKDF2 iterations must be at least `100000`.
- Argon2id memory must be at least `19456` KiB and at most `262144` KiB.
- Salt must decode to at least 16 bytes.

### Shamir Escrow

Split a secret:

```bash
curl -X POST "$BASE/enterprise/escrow/shamir/split?tenant_id=$TENANT" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "secret_base64": "'"$(printf 'recoverable-secret-material-32' | base64)"'",
    "threshold": 3,
    "shares": 5,
    "context": "break-glass-root-key"
  }'
```

Verify a recovery quorum:

```bash
curl -X POST "$BASE/enterprise/escrow/shamir/verify?tenant_id=$TENANT" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"split_id":"ss_example","shares":[...]}'
```

Only the split metadata and secret hash are persisted. Shares are returned once and must be stored by approved guardians outside KeyCore.

### Audit Chain Anchoring

Create an internal anchor with an optional external reference:

```bash
curl -X POST "$BASE/enterprise/audit-chain/anchors?tenant_id=$TENANT" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"anchor_type":"external_notary","external_reference":"notary://2026-06-09/root"}'
```

Anchors store a Merkle-style root, previous anchor hash, anchor hash, and external reference. External blockchain/notary publication should be performed by a trusted anchor publisher using the returned anchor data.

### Key Material Verification

Verify a caller-provided KCV/fingerprint without exposing key material:

```bash
curl -X POST "$BASE/enterprise/verification/fingerprint?tenant_id=$TENANT" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{"key_id":"'"$KEY_ID"'","fingerprint":"AABBCC"}'
```

The comparison uses constant-time equality and creates a DSPM finding on mismatch.

### Advanced Encryption Modes

Searchable encryption is implemented as a deterministic HMAC token for equality lookup. The secret and plaintext are not persisted; audit stores only the token hash.

```bash
curl -X POST "$BASE/enterprise/advanced-encryption/search-token?tenant_id=$TENANT" \
  -H "$AUTH" -H "Content-Type: application/json" \
  -d '{
    "secret_base64": "'"$(printf 'search-token-secret-material-32-bytes' | base64)"'",
    "plaintext_base64": "'"$(printf 'alice@example.com' | base64)"'",
    "context": "customer-email"
  }'
```

Homomorphic and functional encryption should be registered as `advanced_encryption` control records until a reviewed provider is integrated. This avoids presenting research-mode cryptography as production-safe.

### Compliance and Cost Views

```bash
curl "$BASE/enterprise/compliance/dashboard?tenant_id=$TENANT" -H "$AUTH"
curl "$BASE/enterprise/cost/optimization?tenant_id=$TENANT&days=30" -H "$AUTH"
```

The compliance dashboard scores health, compromise response, DSPM findings, and enterprise controls. Cost optimization estimates operation cost from analytics metrics and recommends hotspot remediation.

## Operating Workflows

### Weekly KMS Operations Review

1. Run `POST /inventory/sync`.
2. Review `GET /enterprise/summary`.
3. Review overdue rotations from `GET /rotation/analytics/overdue`.
4. Review low health scores from `GET /health/summary`.
5. Review orphaned and duplicate keys.
6. Run `POST /enterprise/anomaly/scan`.
7. Export `GET /enterprise/dspm/events` to posture/DSPM when using pull ingestion.
8. Create remediation tickets for health scores below 60, overdue critical keys, unresolved high/critical compromise events, and open DSPM findings.

### Security Incident Response

1. Ingest advisory or create a compromise event.
2. Confirm automatic suspension for critical/high active keys.
3. List dependencies for each impacted key.
4. Rotate or replace impacted keys.
5. Verify applications using dependency records.
6. Update compromise event to `confirmed`, then `resolved` when evidence is complete.
7. Export audit events from the audit service for the incident record.

### Migration and Modernization Planning

1. Sync inventory.
2. Review low algorithm health scores.
3. Use duplicate detection to find repeated material.
4. Use dependency records to plan service-by-service migration.
5. Use rotation analytics to validate migration completion and failure rate.

## Audit Events

The implementation emits these KeyCore audit subjects:

| Subject | When Emitted |
|---|---|
| `audit.key.rotate` | Existing key rotation event. |
| `audit.key.health_scored` | Health score recalculated. |
| `audit.key.inventory_synced` | Inventory sync completed. |
| `audit.key.compromise_detected` | Compromise event recorded. |
| `audit.key.compromise_auto_suspended` | Key automatically suspended or promoted due to compromise response. |
| `audit.key.anomaly_scan_completed` | Enterprise anomaly scan completed. |
| `audit.key.dspm_finding_upserted` | KeyCore DSPM finding created or updated. |
| `audit.key.kdf_derived` | Enterprise KDF operation completed without persisting secret material. |
| `audit.key.escrow_shamir_split` | Shamir split generated and metadata persisted. |
| `audit.key.escrow_shamir_verified` | Shamir share quorum verified. |
| `audit.key.audit_chain_anchored` | Audit chain anchor persisted. |
| `audit.key.material_fingerprint_verified` | KCV/fingerprint verification completed. |
| `audit.key.searchable_token_generated` | Searchable HMAC token generated. |
| `audit.key.enterprise.*.upserted` | Enterprise control record created or updated. |

## Roadmap Status

The `GET /enterprise/summary` response includes a `roadmap` array for all 20 identified items. Status values:

| Status | Meaning |
|---|---|
| `implemented` | API-backed capability is implemented in this audit work. |
| `implemented_statistical` | Statistical detection is implemented; this is not presented as opaque ML. |
| `implemented_registry` | Registry/control-plane workflow is implemented for providers, agents, policies, or mappings. |
| `implemented_anchor` | Internal anchor records and external-reference workflow are implemented. |
| `implemented_guarded` | Safe subset is implemented and research-only modes are gated by control records. |

## Security Notes

- Automatic suspension is intentionally conservative: high and critical compromise events can suspend active keys.
- Key material is never read for duplicate detection; the implementation uses algorithm plus KCV.
- Health scores are advisory and should not be the only control for destructive action.
- Orphaned key detection depends on dependency record completeness.
- Feed ingestion accepts normalized advisories; external NVD/GitHub polling should be handled by a trusted feeder job that posts to KeyCore.
- KDF, Shamir, and searchable-token APIs return sensitive outputs directly to the caller. Callers must handle those responses as secret material.
- Homomorphic and functional encryption are not faked; use governed provider records until a reviewed implementation is integrated.
- The shared HTTP audit middleware now captures request-level audit events by default. Set `AUDIT_CAPTURE_HTTP_REQUESTS=false` only for controlled test environments.

## Validation

Focused package validation:

```bash
GOCACHE="$PWD/.cache/go-build" go test ./pkg/analytics ./pkg/health
GOCACHE=/private/tmp/kms-go-build-cache go test ./services/keycore
GOCACHE=/private/tmp/kms-go-build-cache go test ./pkg/auditmw ./services/audit
```
