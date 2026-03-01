# KMS Posture Management Service

This service implements a dedicated posture pipeline on top of existing KMS audit/log streams with:

- Unified normalized event schema ingestion.
- Hot + historical event storage.
- Parallel predictive, preventive, and corrective engines.
- Risk snapshots, findings, and remediation action workflow.

## Normalized event schema

Every event is normalized to:

- `timestamp`
- `tenant_id`
- `service`
- `action`
- `result`
- `severity`
- `actor`
- `ip`
- `request_id`
- `resource_id`
- `error_code`
- `latency_ms`
- `node_id`
- `details` (opaque map)

## Storage model

- `posture_events_hot`: short-lived real-time window.
- `posture_events_history`: trend/forecast history.
- `posture_findings`: posture detections with `risk_score`, `recommended_action`, `auto_action_allowed`.
- `posture_actions`: corrective runbook actions and execution state.
- `posture_risk_snapshots`: risk over time (`24h`, `7d`, per-engine).
- `posture_engine_state`: scan/sync cursor metadata.

## APIs

- `POST /posture/events`
- `POST /posture/events/batch`
- `POST /posture/ingest/audit?tenant_id=...&limit=...`
- `POST /posture/scan?tenant_id=...&sync_audit=true|false`
- `GET /posture/findings?tenant_id=...`
- `PUT /posture/findings/{id}/status?tenant_id=...`
- `GET /posture/risk?tenant_id=...`
- `GET /posture/risk/history?tenant_id=...`
- `GET /posture/actions?tenant_id=...`
- `POST /posture/actions/{id}/execute?tenant_id=...`
- `GET /posture/dashboard?tenant_id=...`

## Engine behavior

- Predictive:
  - auth/crypto/policy anomaly spikes
  - expiry backlog forecast
  - HSM latency and cluster lag early degradation
  - KMS-specific detections (FIPS non-approved algorithm attempts, quorum bypass, tenant mismatch, cluster drift, delete velocity)
- Preventive:
  - quorum-force recommendation
  - step-up auth recommendation
  - connector sync pause recommendation
  - preemptive rotation windows
  - guardrail policy recommendation
- Corrective:
  - SLA breach escalation
  - runbook action generation (`restart_connector`, `failover_hsm_profile`, `quarantine_profile`, `rotate_credentials`, etc.)
  - optional auto-remediation for low-impact actions if `POSTURE_AUTO_REMEDIATE=true`

## Runtime knobs

- `POSTURE_ENGINE_INTERVAL_SEC` (default `60`)
- `POSTURE_HOT_RETENTION_HOURS` (default `72`)
- `POSTURE_AUDIT_SYNC_LIMIT` (default `500`)
- `POSTURE_AUTO_REMEDIATE` (default `false`)

