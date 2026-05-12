# Automation, Automated Key Lifecycle Management, and PQC

This guide describes the closed-loop automation, NIST SP 800-57 lifecycle
controls, and post-quantum key-management features delivered as part of
the second hardening wave. It is intended for operators who already
understand the [Component Guide](COMPONENT_GUIDE.md) and want to
configure, observe, or extend the new controllers.

## At a glance

| Capability | Owner service | Activates via |
|---|---|---|
| Tenant lifecycle reconciler | `reconciler` | `RECONCILER_MANIFEST_DIR` |
| Key lifecycle reconciler | `reconciler` | runs automatically once `keycore /keys/due-for-lifecycle` returns items |
| KMIP auto-decommission | `reconciler` + `kmip` | `EvaluateDecommission` thresholds |
| Quota auto-throttle | `policy` | `PUT /policy/quota/{tenant_id}` (or tenant manifest `ops_budget_per_day`) |
| Policy lint / dry-run | `policy` | `POST /policies/lint`, `POST /policies/dry-run` |
| HNDL detector | `audit` | governance posture `posture_hndl_detection_enabled` |
| Sustained-risk auto-quarantine | `audit` | governance posture `posture_auto_quarantine_enabled` |
| Webhook circuit breaker | `audit` | enabled by default; per-target breaker |
| CBOM inventory & diff | `audit` | `GET /audit/cbom/inventory`, `GET /audit/cbom/diff` |
| Cryptoperiod enforcement | `keycore` | active when `CryptoperiodPolicy` is set (default) |
| Lifecycle state machine | `keycore` | active on every status change |
| Predictive rotation | `keycore` | `RotationForecaster` + ops-sample feed |
| Zeroization scheduler | `keycore` | `KEYCORE_ZEROIZATION_SCHEDULER_ENABLED=true` (default) |
| Dependency-aware destroy | `keycore` | active when a `DependencyChecker` is wired |
| Auto-tagging at registration | `kmip`, `keycore` | active on `Register` / import |
| Self-test on wake | `keycore` | `WakeSelfTestRegistry` on the Service |
| Workflow templates | `keycore` | request `template_id` at key creation |
| Composite keys (hybrid PQC) | `keycore` | algorithms named `<classical>+<pqc>` |
| Y2Q risk score | `keycore` | `sensitivity` + `y2q_window_years` labels |
| PQC KCV | `keycore` | `ComputePQCKCV` at PQC import |
| Stateful HBS tracker | `keycore` | XMSS/LMS key creation |
| Composite signatures | `keycore` | `signing-pqc-hybrid` template |
| PQC HSM attestation | `keycore` | recorded at key creation |
| Migration planner | `keycore` | `POST /pqc/migration/plan` (when handler is wired) |
| Service heartbeats | every service | `pkg/heartbeat` publisher at boot |
| Watchdog SLO probe | `watchdog` | subscribes to `health.*.heartbeat` |
| Playbook engine | `watchdog` | fires per-service playbook on SLO breach |

## Posture toggles

The new governance posture fields, surfaced through the existing
governance service, are:

```
posture_hndl_detection_enabled
posture_auto_quarantine_enabled
posture_auto_migration_enabled
posture_min_algorithm_tier            // classical-128 | classical-192 | classical-256 | pqc-hybrid | pqc-only
posture_zeroization_interval_mins
```

Operators set them on the governance "Posture" surface; keycore, audit,
and the reconciler refresh their view of posture every 60 seconds.

## Reconciler manifests

Tenant manifests are plain YAML and live in the directory mounted at
`RECONCILER_MANIFEST_DIR` (default `/etc/vecta/manifests`). Minimal
example:

```yaml
apiVersion: vecta-kms/v1
kind: TenantManifest
tenant:
  id: tenant-prod-01
  name: Production
  status: active
  min_algorithm_tier: pqc-hybrid
  ops_budget_per_day: 1000000
policies:
  - id: pol-deny-non-pqc
    yaml: |
      apiVersion: kms.vecta.com/v1
      kind: CryptoPolicy
      metadata:
        name: deny-non-pqc
        tenant: tenant-prod-01
      spec:
        type: algorithm
        minAlgorithmTier: pqc-hybrid
        targets:
          selector: {}
        rules:
          - name: block-classical
            condition: "key.algorithm == RSA-2048"
            action: deny
            message: "RSA-2048 is below the pqc-hybrid floor"
```

The reconciler re-applies the manifest every tick (30s default). Edits
are picked up automatically; deletions remove the corresponding state on
the next pass.

## Audit events

The catalogued event subjects added by this wave are listed in
`services/audit/event_catalog.go`. The most important to alert on:

- `audit.security.hndl_pattern_detected`
- `audit.security.auto_quarantined`
- `audit.key.hbs_exhausted`
- `audit.key.wake_kat_failed`
- `audit.health.incident`
- `audit.policy.crypto_floor_violation`
- `audit.policy.quota_exceeded`

## Dashboards

The "Health & Reconciliation" tab in the v3 dashboard surfaces:

- service heartbeats (state, silence-seconds, healthy boolean)
- per-controller reconciler status (last run, last error)
- recent playbook incidents (timestamp, service, action)

The existing "Crypto Agility" tab continues to render the CBOM
inventory; live data lands via `lib/cbom.ts`.

## Caveats and follow-ups

- PQC primitives are wired in interface only — `ComputePQCKCV`,
  `CompositeSignature.Marshal`, etc. assemble bundles but the actual
  ML-KEM, ML-DSA, SLH-DSA calls have not yet been bound to
  `crypto/mlkem` / `crypto/mldsa`. That work is gated on a CMVP-ready
  module and lives in a separate PR.
- The "due for lifecycle" scan in keycore is a stub that returns empty
  until the SQL store gains a cross-tenant index keyed by cryptoperiod
  expiry. The reconciler tolerates this gracefully.
- Cluster sync of the new event subjects flows through the existing
  `pkg/clustersync` publisher; no schema changes were required.
