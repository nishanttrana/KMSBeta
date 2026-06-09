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

## Operating Workflows

### Weekly KMS Operations Review

1. Run `POST /inventory/sync`.
2. Review `GET /enterprise/summary`.
3. Review overdue rotations from `GET /rotation/analytics/overdue`.
4. Review low health scores from `GET /health/summary`.
5. Review orphaned and duplicate keys.
6. Create remediation tickets for health scores below 60, overdue critical keys, and unresolved high/critical compromise events.

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

## Roadmap Status

The `GET /enterprise/summary` response includes a `roadmap` array for all 20 identified items. Status values:

| Status | Meaning |
|---|---|
| `implemented` | API-backed capability is implemented in this audit work. |
| `foundation` | Existing platform features provide a base, but a dedicated product workflow remains. |
| `roadmap` | Recommended strategic implementation remains. |
| `research` | Capability needs deeper design, cryptographic review, or vendor validation. |

## Security Notes

- Automatic suspension is intentionally conservative: high and critical compromise events can suspend active keys.
- Key material is never read for duplicate detection; the implementation uses algorithm plus KCV.
- Health scores are advisory and should not be the only control for destructive action.
- Orphaned key detection depends on dependency record completeness.
- Feed ingestion accepts normalized advisories; external NVD/GitHub polling should be handled by a trusted feeder job that posts to KeyCore.

## Validation

Focused package validation:

```bash
GOCACHE="$PWD/.cache/go-build" go test ./pkg/analytics ./pkg/health
```

KeyCore tests require the repository's Go module versions to resolve. If `go test ./services/keycore` reports `unknown revision` for module versions in `go.mod`, correct dependency versions or provide a populated module proxy/cache before running the service test suite.
