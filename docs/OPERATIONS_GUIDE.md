# Vecta KMS Operations Guide

This guide focuses on running the platform: installation, startup, health checks, backups, cluster operations, and practical troubleshooting.

## Operating Model

The platform is deployment-profile driven.

That means:

- `infra/deployment/deployment.yaml` decides which features are enabled
- startup scripts translate that into active Compose profiles
- service behavior is influenced by both deployment-time features and tenant-scoped runtime configuration

Read these first if you are changing service enablement:

- [../infra/deployment/README.md](../infra/deployment/README.md)
- [../infra/scripts/README.md](../infra/scripts/README.md)

## Installation Paths

Use the platform installer for the host OS:

```bash
./install.sh
./install-macos.sh
```

Windows:

```powershell
.\install-windows.ps1
```

## Starting The Platform

Preferred path:

```bash
./infra/scripts/start-kms.sh
```

Health check:

```bash
./infra/scripts/healthcheck-enabled-services.sh
```

Stop:

```bash
./infra/scripts/stop-kms.sh
```

Recovery:

```bash
./infra/scripts/recover-kms.sh
```

## What A Healthy Startup Looks Like

A healthy startup usually means:

- dashboard returns `200`
- core services are healthy
- enabled optional services are reachable
- the dashboard reflects the expected feature set
- audit, auth, keycore, and supporting stateful services are stable

For certificate-aware environments:

- ACME directory should advertise `renewalInfo`
- renewal intelligence endpoints should be live
- ACME STAR summary should load if STAR is enabled for the tenant

For tenant identity automation:

- SCIM-enabled tenants should return a healthy summary from `/svc/auth/auth/scim/summary`
- Auth should show no migration or startup failures for SCIM tables
- the dashboard should surface SCIM inventory in `Administration -> User Admin -> SCIM Provisioning`

## Service Health Checklist

### Core

Always verify:

- `auth`
- `keycore`
- `audit`
- `policy`
- `governance`
- `cluster-manager`
- `dashboard`

### Stateful Dependencies

Usually verify:

- `postgres`
- `nats`
- `consul`
- `valkey`
- `etcd`

### Optional Feature Services

Verify only if enabled:

- `certs`
- `secrets`
- `cloud`
- `ekm`
- `kmip`
- `payment`
- `compliance`
- `posture`
- `reporting`
- `discovery`
- `autokey`
- `keyaccess`
- `signing`
- `workload`
- `confidential`
- `pqc`

## Daily Operational Tasks

### Check Platform Health

Use:

- dashboard home page
- healthcheck script
- cluster overview if clustering is enabled

### Review High-Risk Events

Look in:

- `Audit Log`
- `Posture`
- `Reporting`

Pay special attention to:

- failed auth or replay attempts
- unusual key use or key export requests
- certificate emergency rotation
- missed renewal windows
- attestation denials
- SCIM token rotation
- bulk user disable or deprovision activity
- unexpected SCIM group deletions or membership churn

### Check Backup Freshness

Use `Governance` to confirm:

- recent successful backups exist
- backup coverage matches enabled features
- restore path is documented and approved

## Weekly Operational Tasks

- run or review compliance assessments
- review posture drift and open findings
- review REST client security posture
- review key access justification decisions, bypasses, and approval backlog
- review artifact signing profiles, transparency coverage, and verification failures
- review SCIM provisioning summary, disabled identities, and role-mapped group counts
- review workload identity registrations and expiries
- review certificate renewal windows
- review AP2 or payment policy changes if payment features are enabled

## Monthly Operational Tasks

- review tenant and role inventory
- review SCIM connector state, token age, deprovision mode, and group-role mapping posture
- review cluster replication profile
- review Autokey templates and exceptions
- review PQC readiness and migration backlog
- review HSM and external integration posture

## Backup And Restore

### What To Back Up

Backups should preserve control-plane state such as:

- tenants, users, and clients
- SCIM settings, managed users, managed groups, and memberships
- keys and handles
- certificates and renewal intelligence
- ACME STAR subscription state and delegated subscriber metadata
- Autokey state
- key access justification settings, rules, and decision history
- artifact signing settings, profiles, signature records, and transparency metadata
- workload identity state
- confidential-compute policy
- PQC migration state
- MPC key and ceremony metadata when threshold workflows are enabled
- governance metadata

### What Not To Treat As Recovery State

Do not confuse runtime counters or ephemeral sessions with restorable state.

Examples:

- temporary connection state
- in-memory caches
- transient request statistics

### Backup Workflow

1. Open `Governance`.
2. Create a backup before significant change.
3. Confirm backup coverage metadata.
4. Store artifacts according to your operational policy.

### Restore Workflow

1. Validate backup provenance and intended scope.
2. Confirm restore approvals where required.
3. Restore through governance flow.
4. Re-run health checks and spot-check critical feature areas.

## Cluster Operations

Cluster awareness matters when more than one node participates in the control plane.

### Before Enabling Clustered Operation

Confirm:

- which features are enabled
- which state should replicate
- how nodes are identified and joined
- whether outbound network requirements are satisfied

For Auth and SCIM specifically, confirm that shared identity state includes:

- tenant SCIM settings
- SCIM-managed user and group resources
- group memberships and role-mapping inputs
- audit visibility for provisioning and deprovision events across nodes

### After Cluster Changes

Verify:

- node status
- replicated service state
- tenant visibility
- interface and certificate consistency
- backup coverage still matches the effective state model
- SCIM summary counts match across the cluster for the same tenant
- SCIM-driven group-to-role behavior is consistent regardless of which node serves the login or admin request

## Feature Enablement And Startup

When a feature is enabled in deployment YAML, startup scripts should ensure the service is not only started but also logically initialized.

Examples:

- certificate renewal intelligence should be applied after `certs` startup
- cluster profile should reflect enabled optional services
- optional services such as `autokey`, `workload`, `confidential`, and `pqc` should appear in health and dashboard state
- auth startup should include SCIM schema readiness before the tenant provisioning UI is treated as healthy

## Troubleshooting By Symptom

### "I can’t log in"

Check:

- `auth`
- tenant bootstrap state
- client or admin credentials
- interface and TLS settings if login path moved

### "API calls work for some clients but not others"

Check:

- sender-constrained auth mode
- DPoP proof handling
- mTLS bindings
- HTTP Message Signature failures
- audit events for replay or unsigned calls

### "SCIM users or groups are not appearing"

Check:

- `auth` health and migration state
- tenant SCIM settings and whether the connector is enabled
- SCIM token age and most recent token rotation event
- the IdP SCIM base URL and bearer token
- audit events for `scim_user_provisioned`, `scim_user_disabled`, `scim_user_deprovisioned`, `scim_group_provisioned`, and `scim_group_deleted`
- cluster replication if only some nodes show the new identities

### "Certificates are expiring unexpectedly"

Check:

- renewal intelligence
- CA-directed renewal window
- missed renewal windows
- ACME directory exposure

### "A workload cannot use its key"

Check:

- workload registration
- SVID or token-exchange state
- allowed interfaces and key IDs
- audit events for denial reason

### "An enclave or confidential runtime cannot receive the key"

Check:

- provider selection
- claim and measurement requirements
- attestation verification state
- policy version used for the decision

### "PQC readiness looks wrong"

Check:

- certificate inventory classification
- interface PQC mode
- key inventory freshness
- migration report inputs

## Runbook References

Use these together:

- [ADMIN_GUIDE.md](ADMIN_GUIDE.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [COMPONENT_GUIDE.md](COMPONENT_GUIDE.md)
- [WORKFLOW_EXAMPLES.md](WORKFLOW_EXAMPLES.md)
