# Automation, Automated Key Lifecycle Management, and PQC

This guide describes the automation controllers, NIST SP 800-57 lifecycle
controls and post-quantum key management that actually run, and how to
operate them. It assumes the [Component Guide](COMPONENT_GUIDE.md).

Everything below was checked against the code in 5.3.0-beta. Capabilities
this page used to list that did not exist are in
[Removed claims](#removed-claims-530-beta) at the end, so a reader who
remembers them can see why they're gone.

## At a glance

| Capability | Owner service | How it runs |
|---|---|---|
| Tenant manifests | `reconciler` | YAML in `RECONCILER_MANIFEST_DIR`; applies `ops_budget_per_day` and creates `policies` ([below](#reconciler-manifests)) |
| Key lifecycle rotation | `reconciler` + `keycore` | every 30 s: `GET /keys/due-for-lifecycle` (internal token), then `POST /keys/{id}/rotate` as `kms-reconciler` |
| Cryptoperiods | `keycore` | built-in SP 800-57 table, input to the lifecycle scan |
| Lifecycle state table | `keycore` | consulted only by compromise detection's automatic suspend |
| Quota auto-throttle | `policy` | `PUT /policy/quota/{tenant_id}` (or manifest `ops_budget_per_day`) |
| Policy lint / dry-run | `policy` | `POST /policies/lint`, `POST /policies/dry-run` |
| Crypto floor | `policy` | a policy's `spec.minAlgorithmTier` ([ALGORITHM_TRANSITIONS.md](SECURITY/ALGORITHM_TRANSITIONS.md)) |
| Migration policy rules | `keycore` | `/agility/policy/rules`: from the customer's date, matching keys become deprecated, decrypt-only or disallowed; enforced in every key operation, refusals `audit.key.crypto_policy_refused` ([ALGORITHM_TRANSITIONS.md](SECURITY/ALGORITHM_TRANSITIONS.md)) |
| Sustained-risk signal | `audit` | always on; `audit.security.sustained_risk_detected`, playbook trigger `sustained_risk_detected` |
| Event-stream circuit breaker | `audit` | per-target breaker on event-stream deliveries (Playbooks → Event streaming) |
| CBOM inventory & diff | `audit` | `GET /audit/cbom/inventory`, `GET /audit/cbom/diff` |
| PQC key generation | `keycore` | `POST /keys` with an ML-KEM, ML-DSA or SLH-DSA algorithm |
| PQC migration plans | `pqc` | `POST /svc/pqc/pqc/migration/plans`, then `.../{id}/execute` |
| Service heartbeats | keycore, kmip, policy, audit, and services started with `platform.Boot` | `pkg/heartbeat` on `health.<service>.heartbeat` |
| Watchdog | `watchdog` | subscribes to `health.*.heartbeat`; raises `audit.health.incident`; compliance playbooks with the `service_health_degraded` trigger respond (the watchdog acts on nothing itself) |

### Key lifecycle rotation

Keycore's `GET /keys/due-for-lifecycle` scans active keys across tenants
(`ScanLifecycleCandidates`) and `EvaluateLifecycle` names each one due for
rotation, in this order:

1. the operator-set expiry (`expiry_date`) has passed;
2. the key is older than its cryptoperiod;
3. `ops_total` has reached 80% of `ops_limit`.

The reconciler rotates each through keycore's normal `POST
/keys/{id}/rotate`, so the rotation is audited like an operator's. A scan
keycore refuses is the controller's `last_error` in System Administration →
Health, not "nothing due".

Nothing is destroyed automatically. A compromised key, or one deactivated
long ago, is destroyed by a person, through keycore's destroy and its
pre-destroy checks; playbooks have no destroy step. (Until 5.3.0-beta the scan also returned "destroy" for
those keys; keycore refused every one because the reconciler never sent the
pre-destroy acknowledgements.)

### Cryptoperiods

`NewCryptoperiodPolicy` holds the upper bounds of SP 800-57 Part 1 Rev. 5
§5.3.5 Table 1: 2 years for symmetric encrypt, MAC and key-wrap keys, 1 year
for signing keys, 30 days for DEK and ephemeral keys, 5 years for master keys
and KEKs. There is no operator setting for them yet. They feed only the
lifecycle scan above.

### Lifecycle state table

`lifecycle_state.go` lists the allowed moves between pre-active, active,
suspended, deactivated, compromised and destroyed. Only compromise
detection's automatic suspend (`enterprise_audit_service.go`) checks it.
`SetKeyStatus` doesn't, so an operator can move a compromised key back to
active. That is open (see [Open items](#open-items)).

### Sustained-risk signal

Audit gives every event a risk score. When one target (a key, another named
target, or else the tenant) collects 3 events scoring 80 or more within 5
minutes, audit publishes `audit.security.sustained_risk_detected` once for
that window, with `target_type` / `target_id` set. It changes nothing
itself: a playbook on the `sustained_risk_detected` trigger can act on
`{{event.target_id}}`, for example `disable_key`, or `deactivate_key` (which
waits for a governance approval).

### PQC keys

Keycore generates ML-KEM-768 and ML-KEM-1024 (`crypto/mlkem`), ML-DSA-65 and
ML-DSA-87, and the SLH-DSA parameter sets. It refuses, with
`audit.key.create_refused`, hybrid (composite) names such as
`AES-256-GCM+ML-KEM-768` (create each component key instead), stateful
hash-based signatures (XMSS, LMS, HSS), and Ed448/X448. A PQC key's
check value is the `sha256-material` KCV keycore gives every non-symmetric
key (`computeKCVStrict`). There is no separate PQC KCV.

## Posture

Governance's posture controls that keycore reads are
`posture_force_quorum_destructive_ops`, `posture_require_step_up_auth`,
`posture_pause_connector_sync` and `posture_guardrail_policy_required`.

Keycore also reads `posture_min_algorithm_tier` and, since 5.1.0-beta,
refuses new protection below it. **Governance does not store or return that
field**, so in a deployment it is always empty and the check never fires
(open item in [ALGORITHM_TRANSITIONS.md](SECURITY/ALGORITHM_TRANSITIONS.md)).
A floor that takes effect today is a policy's `spec.minAlgorithmTier` or a
migration policy rule.

This page used to list four more (`posture_hndl_detection_enabled`,
`posture_auto_quarantine_enabled`, `posture_auto_migration_enabled`,
`posture_zeroization_interval_mins`). Governance never stored them and
nothing read them. Keycore stopped parsing them in 5.3.0-beta.

## Reconciler manifests

Tenant manifests are plain YAML in the directory mounted at
`RECONCILER_MANIFEST_DIR` (default `/etc/vecta/manifests`). The reconciler
reads them every tick (30 s) and applies two things:

- `tenant.ops_budget_per_day` becomes the tenant's policy quota. It is
  re-applied every tick, so the policy service's in-memory tracker recovers
  after a restart.
- each entry in `policies` is created under the tenant. The policy service
  refuses a second policy with the same name, so a policy is created once:
  **a later edit to it in the manifest is not applied** (the refusal is
  logged). Change an existing policy in the Policies UI or API.

Removing a manifest, or a policy from one, removes nothing. Other keys in
the file are ignored.

```yaml
tenant:
  id: tenant-prod-01
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

## Audit events

Severities for these subjects are in `services/audit/event_catalog.go`. The
ones to alert on:

- `audit.security.sustained_risk_detected`
- `audit.health.incident`
- `audit.policy.crypto_floor_violation` (a policy's `minAlgorithmTier`
  denied a request; with `algorithm` and `tier`)
- `audit.policy.quota_exceeded`
- `audit.pqc.migration_step_executed` / `audit.pqc.migration_failed`

## Dashboards

System Administration → Health shows:

- service heartbeats (state, silence in seconds, healthy);
- each reconciler controller's last run and last error;
- watchdog incidents (time, service, reason, recommendation).

Services that publish no heartbeat aren't watched, and don't appear there.

The Crypto Agility tab shows keycore's `GET /agility/posture`: live keys
against the customer's own migration policy rules, which keycore enforces
([ALGORITHM_TRANSITIONS.md](SECURITY/ALGORITHM_TRANSITIONS.md)). CBOM tiers
use the same `pkg/cryptocatalog` facts.

## Open items

- Governance has no `posture_min_algorithm_tier` setting, so keycore's
  tenant minimum-tier check never fires in a deployment.
- `SetKeyStatus` doesn't enforce the lifecycle state table (a compromised key
  can be set active again).
- Manifest policies are created once; edits and deletions in a manifest
  aren't applied.
- Cryptoperiods have no operator setting.
- Hybrid (composite) keys and stateful hash-based signatures are not
  implemented; creation refuses them.
- Risk ratings for migration priority are being built by the crypto-agility
  CARAF work (threats, asset profiles, X/Y/Z timelines); the unused Y2Q
  score was removed rather than kept alongside.

## Removed claims (5.3.0-beta)

Each of these was listed as a capability here but was dead code, a no-op or
mislabelled. The code was removed (recoverable from git history before the
5.3.0-beta commit; see CHANGELOG.md).

| Former claim | What the code actually did |
|---|---|
| Composite keys (hybrid PQC) | Keycore refuses any algorithm containing `+` |
| Y2Q risk score, keycore migration planner | `MigrationPlanner`, `y2q_score.go` and `pkg/migration` were never constructed or called |
| PQC KCV (`ComputePQCKCV`) | Never called |
| PQC primitives "wired in interface only" | The wrappers in `pqc_primitives.go` were unused; keycore generates PQC keys directly (above) |
| Stateful HBS tracker, `audit.key.hbs_exhausted` | XMSS/LMS creation is refused; the event was never emitted |
| Composite signatures (`signing-pqc-hybrid`) | Only a template table entry; no `CompositeSignature` code existed |
| PQC HSM attestation | Nothing recorded; `audit.pqc.attestation_recorded` never emitted |
| Workflow templates (`template_id`) | Keycore's template table was never read; key creation has no `template_id` |
| Auto-tagging at registration | Neither keycore's nor KMIP's tagger was called |
| Dependency-aware destroy | No `DependencyChecker` was ever wired |
| Self-test on wake | The registry was set and never read; `WakeKAT` never ran |
| Zeroization scheduler | Ran hourly over a store method that didn't exist and so did nothing; `KEYCORE_ZEROIZATION_SCHEDULER_ENABLED` is gone |
| Predictive rotation (`RotationForecaster`) | No forecaster existed; the real rule is the 80%-of-`ops_limit` rotation above |
| HNDL detector | Counted raw encrypt volume per tenant, any algorithm, with a byte count nothing reported; not a harvest-now-decrypt-later measurement |
| Sustained-risk auto-quarantine | Quarantined nothing; renamed to the sustained-risk signal above |
| KMIP auto-decommission | Judged inactivity from the client row's `updated_at`, which KMIP traffic never touches, so every client went dormant (and was refused) 90 days after creation |
| Tenant onboarding (`POST /tenants/onboard`, removed) | Provisioned nothing, but emitted `audit.tenant.onboarded` every 30 s per manifest |
| Key archive (`POST /keys/{id}/archive`, `KEYCORE_ARCHIVE_*`, removed) | Returned `archive_queued` and queued nothing |
| "The due-for-lifecycle scan is a stub" | It wasn't: it has scanned the keys table since it was added |
