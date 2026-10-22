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

## Runtime And Package Baseline

Current source and container builds target:

- Go `1.26.4` for service builds and tests
- Node.js `24` LTS with npm `11` for the dashboard
- Alpine `3.23` for lightweight service runtime images
- nginx `1.30.1` for the dashboard runtime image

Generated dashboard output under `web/dashboard/dist/` and local Go caches are intentionally ignored. Recreate generated assets with `npm run build` from `web/dashboard` when packaging or testing a release.

Security-relevant maintenance in this baseline:

- dashboard npm audit is clean after upgrading Vite, PostCSS, TypeScript, React, Tailwind, Swagger UI, Playwright, and related tooling
- Go modules are refreshed for current security and compatibility fixes, including `golang.org/x/crypto`, `golang.org/x/net`, `google.golang.org/grpc`, OpenTelemetry, AWS SDK, Redis, and SQLite dependencies
- outbound webhook and OIDC URL validation blocks loopback, private, link-local, reserved, and cloud metadata addresses while allowing public IPv4 addresses
- HTTP security header expectations include `frame-ancestors 'none'`, `no-cache`, `no-referrer`, and a payment-denying permissions policy

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

On a single machine, `./deploy-local.sh` builds and starts the stack, and
`./deploy-local.sh --no-build` restarts it on the images already built.
After every deploy or rebuild run the two live checks in
[Check Platform Health](#check-platform-health).

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

### Optional Feature Services

Verify only if enabled:

- `certs`
- `secrets`
- `cloud`
- `hyok`
- `ekm`
- `kmip`
- `dataprotect`
- `hsm-connector`
- `compliance`
- `posture`
- `reporting`
- `discovery`
- `sbom`
- `autokey`
- `keyaccess`
- `signing`
- `workload`
- `confidential`
- `pqc`
- `backup`

### What System Health lists

Administration → System Administration → Health lists the services
registered in Consul plus a fixed set of TCP probes for components that
register nothing there: Envoy, the dashboard, the reconciler, the watchdog,
posture and backup (10.2.0-beta). A test keeps the probe list covering every
platform identity in `pkg/svctls`. The auth service has no access to the
container runtime, so an optional component that is not reachable is not
listed, and Network Interfaces reads "unavailable".

### A service that will not start

A service refuses to start, rather than starting healthy and refusing every
call, when something it needs is missing: a token-verification key, a
required `https://` address, its port. The reason is the last
`refusing to start: …` line in `docker compose logs <service>`. HYOK, for
example, reads `HYOK_JWT_PUBLIC_KEY_PEM`/`_B64` and then the shared
`JWT_PUBLIC_KEY_B64`, like keycore and governance (10.1.0-beta).

## Reaching Postgres, NATS, Valkey And Consul Directly

**Everything is internal mTLS** (docs/SECURITY/INTERNAL_TLS.md). A client on
the host without a certificate from the internal-services Sub CA is refused
at the TLS handshake. For administration, use the container's own socket
and pass secrets through the environment, never on the command line:

```bash
export PGPASSWORD="$(sed -n 's/^POSTGRES_PASSWORD=//p' .env)"
docker compose exec -e PGPASSWORD postgres psql -U postgres -d vecta
```

**Checks:**
- **Every database connection is TLS 1.3 with a service certificate:**
  `select * from pg_stat_ssl join pg_stat_activity using (pid)`.
- **Audit ingestion is live:** `select max(timestamp) from audit_events`
  should be seconds old. If not, read `docker compose logs audit` for
  ingest errors.

### Audit restart-loops on a corrupt consumer

`docker compose logs audit` repeats `subscribe failed: nats: error creating
store for consumer`, and `docker compose logs nats` says `Error adding
consumer '$G > AUDIT > audit-ingest': ... corrupt state file (10104)`.
Services that depend on audit report `dependency audit failed to start`.
NATS lost the consumer's position (its `o.dat`), usually through a write cut
off by a crash or a host reboot. The stream's messages are intact.

Don't delete the consumer while events stored before 13.39.0-beta are still
in the stream (90 days after the upgrade). A new consumer starts at the
beginning, and those older events would be stored again
(docs/SECURITY/AUDIT_INTEGRITY.md, "One row per stream message"). Restore
the position instead:

1. Stop audit. Find the newest row it stored: `select action, timestamp
   from audit_events order by created_at desc limit 5`.
2. Copy `/data/jetstream/jetstream/$G/streams/AUDIT/msgs` out of the nats
   container and find that event's stream sequence: each record in a
   `.blk` file is a little-endian length, sequence, stored time and
   subject, then the JSON payload. Match on action and timestamp, and check
   that every message before it in the last few minutes has a row.
3. Back up `.../AUDIT/obs/audit-ingest/`, remove `o.dat.tmp`, and write
   `o.dat` as the bytes `16 02`, then the sequence as an unsigned varint
   four times (ack floor and delivered, consumer and stream), then `00 00`.
   The healthy `playbook-trigger-listener/o.dat` next to it has the same
   shape.
4. Restart nats, then start audit. NATS delivers only the messages after
   that sequence, and the row count grows by exactly that many.

Once only 13.39.0-beta ids remain in the stream, deleting the consumer is
safe: the replay finds every row already stored.

## Rotating Internal Certificates

Go to **Certificates / PKI > Service mTLS** (root administrator).
- **Rotate:** revokes the identity's certificate. The service restarts
  gracefully and enrols a new key.
- **Force restart:** use it when a key may be compromised. The certificate
  is revoked as `keyCompromise` and the service exits at once.
- **Rotate every certificate:** services restart one every 20 s, certs last.
  Type `rotate-all` to confirm.
- **Daemons** (Envoy client, dashboard, Postgres, NATS, Valkey, Consul) get a
  new certificate that they reload within 30 s.

**When it's done:** the State column turns green once each instance reports
the new generation, and `audit.certs.internal_mtls_applied` is emitted.

**If it stays amber:** check the service's log for `mTLS policy for ...
changed`, and its container restart count.

## Daily Operational Tasks

### Check Platform Health

Use:

- dashboard home page
- healthcheck script
- cluster overview if clustering is enabled

After every deploy or rebuild, run both live checks against the running
stack. Both are read-only and print no secret.

| Command | Fails when | Notes |
|---|---|---|
| `scripts/live-sweep.sh [minutes]` | a container is not healthy, or an error-like line (`error`, `failed`, `refused`, `denied`, `panic`, ...) repeats at least `MIN_REPEAT` times (default 5) in the last 20 minutes | Identifiers, addresses and credentials are stripped before lines are compared. Health-probe handshakes are ignored, and so are tab-indented lines, which only continue the line above: a statement in Postgres's slow-query log, or the frames under a Go `panic:` line (13.13.0-beta). Containers still `starting` right after a deploy are reported; run it again once they are healthy. |
| `scripts/live-check.py` | a dashboard GET answers 401, 5xx or the router's 404, or answers 2xx with no token or for another tenant | Signs in as the bootstrap CLI user from `.env`. Routes that answer by design are listed in its `PUBLIC` and `SAME_FOR_EVERY_TENANT` lists with the reason. |

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
- `audit.audit.chain_broken`, `audit.audit.wal_record_refused`, and a
  `last_full_verification` from `GET /svc/audit/audit/chain/verify` older
  than two hours (the full walk runs hourly)

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
- governance metadata
- the audit volume (`audit-data`, mounted at `/app/data`): the cluster
  audit signing key, the write-ahead buffer and its HMAC key
  (`audit-wal-hmac-key.b64`). Losing the key makes records still in the
  buffer unverifiable; they are then quarantined in `buffer.log.rejected`
  and audited, not ingested (docs/SECURITY/AUDIT_INTEGRITY.md)

### What Not To Treat As Recovery State

Do not confuse runtime counters or ephemeral sessions with restorable state.

Examples:

- temporary connection state
- in-memory caches
- transient request statistics

### Backup Workflow

1. Open Backup & Restore → Encrypted Backups.
2. Create a backup before significant change.
3. Confirm backup coverage metadata.
4. Store artifacts according to your operational policy.

### Scheduled Backups

Backup & Restore → Schedules (root administrators). A schedule takes a
backup every N hours and keeps the newest M it took.

1. Choose how its key is kept. With an enabled HSM profile, choose the HSM.
   Otherwise make a key pair on a machine you control and keep the private
   key offline:

   ```bash
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out backup-private.pem
   openssl pkey -in backup-private.pem -pubout -out backup-public.pem
   ```

   Paste `backup-public.pem` into the schedule. Never paste the private key:
   the form refuses one.
2. Check the first run: the schedule shows `last succeeded` and the backup
   lists as "scheduled" under Encrypted Backups. Download its artifact and
   key file and run Verify Backup with the private key; the key opens in the
   browser and is never sent.
3. A schedule pauses when the administrator who saved it leaves or loses
   `auth.tenant.write`; another administrator saves it again to resume.
   Failed and paused runs are audited (`scheduled_backup_failed`,
   `scheduled_backup_refused`) and can start a playbook ("Scheduled backup
   failed or paused").

The backups stay in the governance database on the cluster primary. Copy
artifacts and key files off the platform as your policy requires: a
schedule alone does not protect against losing that database.

### Restore Workflow

Partitioned tables (keycore `keys`, audit `audit_events`) are backed up and
restored through their parent table. A backup taken before 1.24.0-beta also
lists the partitions; the restore skips them (they appear under
"skipped") and restores each row once, through the parent.


Columns the database computes itself (for example `users.username_lower`)
are not written on restore; the database recomputes them. Before
12.2.0-beta every restore of a backup holding users failed on that column
and changed nothing (a restore runs in one transaction). Backups taken
before then restore as they are.

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
- the console reads `infra/deployment/deployment.yaml` itself: compose mounts it read-only into the dashboard container at `/config/deployment.yaml`, and a module whose feature is `false` there (Cluster with `clustering: false`) is not shown. After changing a feature, restart the dashboard with the rest of the stack (`start-kms`). The image carries no copy of the file.
- with `hyok_proxy` on, the hyok service also listens for Azure Managed HSM on `8443` (`AZURE_EKM_HOST_PORT`, bind `AZURE_EKM_BIND`, default `0.0.0.0`), with the edge certificate from `runtime-certs`. It refuses to start if that certificate never appears. Managed HSM must reach this port; allow it through the firewall only from Azure.
- auth startup should include SCIM schema readiness before the tenant provisioning UI is treated as healthy
- `ekm`, `cloud` and `hyok` learn whether key access justifications are deployed from `VECTA_DEPLOYED_PROFILES` (compose sets it from `COMPOSE_PROFILES`). Change `key_access_justifications` in `deployment.yaml` and restart with `start-kms`; don't add the profile only with `docker compose --profile`. Each logs `key access justifications deployed=<bool>` at start.

### "EKM, BYOK or HYOK operations fail with `424 key_access_unavailable`"

Key access justifications are deployed (or the profile list reached the
service empty, which fails closed) and `keyaccess` didn't answer. Check:

- `keyaccess` is running and healthy (`docker compose ps keyaccess`)
- the service's start log line `key access justifications deployed=...`
- `audit.ekm.key_access_denied`, `audit.cloud.key_access_denied` or `audit.hyok.request_denied` events with `reason: key_access_unavailable` and their `error`
- if the feature is meant to be off, set `key_access_justifications: false` in `deployment.yaml` and restart with `start-kms`; operations then run with `key_access_reason: key_access_not_deployed`

## Posture Remediation Approvals

Escalating an overdue posture finding needs a governance approval. No setup
is required (1.35.0-beta). The first escalation request in a tenant creates
the built-in policy **Posture escalation (built-in)**:
- it covers `posture.escalate_remediation`;
- any tenant administrator (role `admin` or `tenant-admin`, direct or through
  a group) other than the requester can approve, and one approval is enough;
- its creation is audited as `audit.governance.builtin_policy_created`.

1. The operator clicks Execute on the action (or calls
   `POST /svc/posture/posture/actions/{id}/execute`). Posture opens the
   governance request in their name and answers `409 approval_pending`.
2. Another tenant administrator approves it in Governance.
3. The same operator clicks Execute again; the escalation runs.

To change who approves, edit the policy's approver roles or users (or its
quorum) in Governance. A policy of your own whose trigger actions cover
`posture.escalate_remediation` or `posture.*` also works; if one is active
the built-in one isn't created. To stop escalations, set the built-in policy
to inactive. It can't be deleted, since it would be created again. Execution
is refused (`approval_unavailable`) and nothing changes when:
- the built-in policy is disabled and no other policy covers the action;
- no tenant administrator other than the requester has an email address;
- governance is unreachable.

## Troubleshooting By Symptom

### "I can’t log in"

Check:

- `auth`
- tenant bootstrap state
- client or admin credentials
- interface and TLS settings if login path moved

### "Opening a page signs me out"

The dashboard ends the session on any `401`, so a service that cannot
verify tokens signs everyone out of the page that calls it. Look for a `401`
from that service (`scripts/live-check.py` lists them) and for a missing
token-verification key in its startup log; a service now refuses to start
without one (10.1.0-beta). A valid token for another tenant is `403`, never
`401`.

### "Every service refuses every token after the volumes were removed"

Auth generates a new signing key when its volume is empty, and every other
service verifies with `JWT_PUBLIC_KEY_B64` from `.env`. `./deploy-local.sh`
mints the key whenever the auth volume has none and always derives
`JWT_PUBLIC_KEY_B64` from the key in the volume (9.4.0-beta). A stack left
in this state is repaired with `./deploy-local.sh --no-build`.

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
- key inventory freshness
- migration report inputs

## Runbook References

Use these together:

- [ADMIN_GUIDE.md](ADMIN_GUIDE.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [COMPONENT_GUIDE.md](COMPONENT_GUIDE.md)
- [WORKFLOW_EXAMPLES.md](WORKFLOW_EXAMPLES.md)
