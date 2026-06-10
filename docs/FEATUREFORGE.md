# Feature Forge

Feature Forge lets an operator describe a change in plain language and have the
platform turn it into a **guardrailed, audited, environment-gated** action. It is
the Vecta KMS answer to "type what you want and the system builds it" — adapted
to the reality of a key-management system, where auto-generating and deploying
changes is a security event, not a convenience.

## Two modes

Feature Forge classifies every request into one of two modes, which have very
different risk profiles and therefore different paths.

### Config mode (runs locally)

The operator types an intent that maps to a **fixed, allow-listed action** from
the catalog (for example, "block RSA-1024 for this tenant"). The classifier only
selects an action and fills its parameter schema — it never generates code. The
dry-run and apply happen locally within the platform; no external build server is
involved. Because the universe of outcomes is bounded by the catalog, config mode
is safe to apply automatically to staging.

### Scaffold mode (external MCP build server)

The operator types a feature request that implies new code (for example, "add an
EdDSA signing endpoint"). Feature Forge delegates the scaffolding, build, and
validation to an **external, separately-deployed MCP server**, configured via
`MCP_SERVER_URL`. Feature Forge never builds code itself — it submits the intent,
polls for the MCP server's pass/fail verdict, and consumes it as a guardrail
layer. Scaffold changes are deployed to **staging only**; promotion to production
always requires a governance quorum.

If `MCP_SERVER_URL` is not set, scaffold-mode intents are rejected with a clear
message, and config mode continues to work.

## The six-layer guardrail pipeline

Every intent — in either mode — passes through the same ordered pipeline. Failing
any layer halts progression and is audited.

1. **Classify** — raw text to mode, catalog action, and parameters. Treated as
   untrusted output.
2. **Validate** — confidence floor plus schema and required-parameter checks;
   config actions must resolve to a catalog entry.
3. **Policy** — the resolved action is evaluated by the existing `policy` service.
   Risk-raising changes (for example, blocking a PQC algorithm) are refused.
4. **Dry-run / Build** — config mode runs a local dry-run with no writes; scaffold
   mode runs build and validation on the external MCP server.
5. **Stage** — the change is applied to the staging environment automatically. For
   catalog actions with a `policy` applier, this applies through the `policy`
   service.
6. **Governance gate** — promotion to production requires a quorum approval from
   the existing `governance` service for sensitive config actions and for all
   scaffold (code) changes.

There is no code path from intake to production. The submit call stops at
"staged"; production is only reachable through a separate, governance-gated
promotion call. Every stage emits a tamper-evident event consumed by the `audit`
service, producing a complete trail for each intent.

## The action catalog

Config mode can only produce an action from a fixed allow-list. Each entry
declares its required parameters, whether production promotion needs a quorum, and
its applier:

- `policy.restrict_algorithm` — disallow a named algorithm (applier: policy)
- `policy.set_min_key_size` — set a minimum key size for a key type (applier: policy)
- `policy.require_approval_for` — require approval for an operation (quorum; applier: stub)
- `pqc.enable_hybrid` — enable hybrid posture on an interface (quorum; applier: stub)

Extending the self-service surface means adding a catalog entry and an applier,
both through normal code review. The classifier can never invent an action outside
this list.

## Service

`featureforge` is a standard Vecta KMS service (`services/featureforge`). It
orchestrates the existing `policy`, `governance`, and `audit` services rather than
inventing shadow lifecycles, and respects the platform's trust boundaries.

### Configuration

| Variable | Purpose | Default |
| --- | --- | --- |
| `HTTP_PORT` | REST port | `8260` |
| `GRPC_PORT` | gRPC/health port | `18260` |
| `POLICY_URL` | policy service base URL | `http://policy:8040` |
| `GOVERNANCE_URL` | governance service base URL | `http://governance:8050` |
| `AUDIT_URL` | optional audit HTTP sink | unset (NATS still used) |
| `MCP_SERVER_URL` | external MCP build server | unset (scaffold mode disabled) |
| `MCP_SERVER_API_KEY` | bearer token for the MCP server | unset |

### REST API

Reached through the dashboard proxy at `/svc/featureforge/...`:

- `GET /catalog` — list allow-listed config actions
- `GET /intents?tenant_id=...` — list intents for a tenant
- `POST /intents` — submit an intent (runs through to staging)
- `GET /intents/{id}` — fetch an intent and its guardrail trail
- `POST /intents/{id}/promote` — attempt production promotion (gated)

### External MCP server contract

Feature Forge expects the MCP server to expose:

- `POST /v1/builds` with `{tenant_id, actor, intent, target}`, returning
  `{job_id}`.
- `GET /v1/builds/{job_id}`, returning `{status, detail, validated}` where
  `status` is one of `queued|building|passed|failed`.

The MCP server is responsible for scaffolding code, building it, running tests,
and performing crypto-specific validation. Feature Forge treats its verdict as the
scaffold-mode build guardrail.

## Dashboard

Feature Forge appears under **ADMIN -> Feature Forge** when the `feature_forge`
feature is enabled. The tab provides an intent input box, per-intent guardrail
trails, a staged/awaiting/production/rejected summary, a promotion control that
surfaces the governance gate, and a view of the config action catalog.

## Enabling

Set `feature_forge: true` under `features` in
`infra/deployment/deployment.yaml`. The startup scripts translate this into the
`feature_forge` Compose profile, which activates the `featureforge` service. To
enable scaffold mode, additionally set `MCP_SERVER_URL` (and
`MCP_SERVER_API_KEY`) in the environment.

`install.sh` carries `feature_forge` through end to end: it is part of the
`FEATURE_KEYS` registry, so the generated `deployment.yaml` features block,
the `recommended`/`all`/`custom` feature-profile prompts, and the
`feature_forge` Compose profile all pick it up automatically. Adding a future
feature is the same one-line registry edit (plus its Compose profile and the
matching `FEATURE_ORDER` entry in `infra/scripts/parse-deployment.sh`).

## Backup and tenant capability

Feature Forge state is tenant-scoped (`ff_intents`, `ff_events`,
`ff_guardrail_results`, `ff_prod_approvals`, all carrying `tenant_id`) and is
captured by the governance backup service through table auto-discovery. The
backup coverage report surfaces it under the
`feature_intent_classification_and_promotion_governance` tenant capability,
with a coverage note recording that feature intents, classification outcomes,
guardrail results, and production-promotion approvals are preserved while
transient classifier queues and evaluation caches are excluded. Tenant-scoped
backups filter `ff_*` rows by `tenant_id`.

## High-availability replication

FeatureForge is a first-class cluster replication component (`featureforge`).
It is included in the built-in `cluster-profile-full` preset. Operators who
want to replicate only selected services can choose the **custom** cluster
profile in `install.sh` and pick `featureforge` (and any other services)
individually; the selection is written to `CLUSTER_BOOTSTRAP_COMPONENTS` and
seeded by cluster-manager as a `cluster-profile-custom` profile. Core services
(auth, keycore, policy, governance) are always replicated and need not be
selected.
