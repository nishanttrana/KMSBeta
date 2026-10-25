# Scheduling

Every schedule in the platform has one home: the **Scheduling** module of the
console (13.66.0-beta; owner, 2026-10-25: "all the scheduling for keys,
backup, reporting etc anything in the scheduling and secrets schedule should
be under scheduling, build new but not fake"). Each schedule is stored and run
by the service that owns the work; Scheduling only shows and edits them. Nothing
in it schedules work a service would not do.

## What can be scheduled

| Sub-option | What runs | Service and code | Interval |
|---|---|---|---|
| Key rotation | rotates every active key a policy's filter selects, each through the same `RotateKey` path as a manual rotation | keycore `rotation_engine.go` | days, per policy |
| Key integrity | decrypts each matching active key's current material under the master key and recomputes its KCV (`VerifyKeyIntegrity`); a key held in an HSM is **not assessed** | keycore `integrity_schedule.go` | 1 to 2160 hours |
| Secret rotation | writes fresh material of the same kind as the next version of a secret the KMS generated (an SSH key or a key pair) | secrets `rotation_schedule.go` | 1 to 8760 hours |
| Reports | queues a report job (listed in Compliance → Reports; not emailed) | reporting `schedule.go` | hourly, daily, weekly |
| Scans & assessments | the tenant's crypto discovery scan and its compliance assessment | discovery `schedule.go`, compliance `assessment_schedule.go` | hours; hourly, daily, weekly |
| Backups | encrypted backups with retention (platform administrators) | governance `backup_schedule.go` | 1 to 720 hours |
| Cryptoperiods | not a schedule: how long each kind of key may be used, which rotation follows | keycore | — |

The **Overview** lists every schedule from every source, with what is due in
24 hours, what is paused and what failed or was refused on its last run, and
the runs due in the next seven days. Each source loads on its own; one that
fails reads "unavailable" with its error, never "no schedules". The tiles and
the bars filter the table to exactly the schedules they count; a row opens its
kind's view. Old addresses redirect: `#rotation` to `#scheduling/keys`,
`#backup/schedules` to `#scheduling/backups`.

A secret whose value came from outside the KMS (a password, an API key)
cannot be rotated by the KMS, so it cannot have a schedule: the route answers
`409 not_generated`. Only generated secrets are offered.

## Whose authority a schedule runs on

A schedule acts only on the authority of the person who **last saved it**
(`authorized_by`; docs/PLATFORM_CONTRACT.md). Before every run the service
asks auth (`POST /auth/delegated/authority`, through `pkg/authority`) whether
that person is still active and still holds the permission:

| Schedule | Permission re-checked |
|---|---|
| Key rotation | `key.rotation.write` and `key.rotate`; the rotation then runs **as that person**, so their key grants decide each key (a key they can't reach fails that rotation) |
| Key integrity | `key.integrity.verify`; only the keys that person can see are checked |
| Secret rotation | `secrets.write`, and the vault's access rules must still let them write the secret's path (auth also returns their role, for rules that name a role) |
| Reports | `reporting.write` |
| Compliance assessment | `compliance.assessment.write` |
| Discovery scan | `discovery.write` |
| Backups | `auth.tenant.write` (root administrators) |

- **Authority gone** (inactive, a permission lost, an access rule now denies,
  no one on record): the schedule **pauses** with the reason
  (`paused_reason`), the refusal is audited (`result: refused`, `reason:
  authority_revoked`), and nothing runs until someone with the authority saves
  it again. Saving makes the saver its new authority.
- **Auth did not answer**: the run is postponed 15 minutes and audited
  (`reason: authority_unknown`); it neither runs on unverified authority nor
  pauses a schedule that may still be valid.
- **Run now** runs the schedule at once on its saved authority, exactly as a
  scheduled run would; a paused schedule refuses it (`409 schedule_paused`).

**Upgrading to 13.66.0-beta:** rotation policies, scheduled reports and the
assessment schedule saved before it have no one on record. Each pauses at its
next run with "no one is on record as authorizing this; save it again to
resume". Open Scheduling → Overview, filter **Paused**, and save each one
(docs/OPERATIONS_GUIDE.md).

## What each run records

Every schedule keeps its last run: `last_run_at`, `last_result` and
`last_error` (key integrity also the counts checked, failed and not assessed;
secret rotation the version it made; reports the queued job; the assessment
its ID). Each run is audited by the service that ran it:
`audit.key.rotation_policy_run`, `audit.key.integrity_check_run`,
`audit.secrets.rotation_schedule_run`, `audit.reporting.scheduled_report_run`,
`audit.compliance.assessment_schedule_run`,
`audit.governance.scheduled_backup_taken` / `_failed` / `_refused`, `audit.discovery.scheduled_scan`
(docs/SECURITY/AUDIT_EVENTS_2026-09.md). A failed key integrity check and a
failed scheduled rotation are Playbooks triggers (`key_integrity_failed`,
`scheduled_rotation_failed`).

Schedulers run on the cluster primary only and check every minute what is
due, judged from the stored next run, so a restart never skips a run.

## Removed

The keycore "scheduled jobs" (`/scheduling/jobs`, table `key_scheduling_jobs`)
are removed: they stored jobs that nothing ever ran, the console read a field
the service never returned, and every job it created was refused. Migration
039 drops the table. Key integrity schedules are the real replacement for its
"verify" job.
