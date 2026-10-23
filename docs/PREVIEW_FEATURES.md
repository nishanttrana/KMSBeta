# Preview Features

**Standing rule.** A feature that only stores configuration, without enforcing
or executing it, is a **preview**. It is never presented as finished (CLAUDE.md
rule 7). The single catalogue is `pkg/features.Preview`, and every surface
reflects it:

- **API:** responses carry `X-Vecta-Feature-Status: preview` and
  `X-Vecta-Feature-Status-Id: <id>`. keycore control records carry
  `feature_status` and `feature_id`.
- **Dashboard:** `web/dashboard/src/lib/featureStatus.ts` mirrors the catalogue.
  `make conformance` (rule `preview-catalogue`) fails if the two differ. Preview
  screens show a Preview banner with their actions disabled.
- **Docs:** this page, [RECOMMENDED_FEATURES.md](RECOMMENDED_FEATURES.md).

| ID | Feature | What does not happen |
|---|---|---|
| `keycore.federation` | Key federation / multi-KMS failover | Providers, mappings and failovers are stored; no key is replicated and no failover happens. |
| `keycore.advanced_encryption_modes` | Homomorphic / functional encryption modes | Registered as controls; no homomorphic or functional encryption is performed. Searchable HMAC tokens are available. |

## Corrections made on 2026-09-25

- **Backup scheduler** (`services/backup`):
  - **What it did:** it simulated backups. It invented key counts and sizes
    with a random generator, wrote a fake file path, "verified" integrity with
    a SHA-256 of its own made-up metadata, and its restore did nothing.
  - **Now:** the simulation is removed. Run and Restore return
    `409 feature_preview`, and existing runs and restore points are relabelled
    `simulated` (migration 002), so no report counts them.
  - **Command Center:** the backup check now uses governance's real encrypted
    backups.
  - **Where real backup lives:** governance (System Administration → Backups):
    AES-256-GCM artifacts, a separate key package, restore with tamper and
    scope (AAD) checks. Integration-tested against Postgres.
  - **Removed in 13.43.0-beta:** the service, its routes and its tables
    (governance migration 019). Scheduled backups are governance's own
    (Backup & Restore → Schedules; [SECURITY/BACKUP_KEYS.md](SECURITY/BACKUP_KEYS.md#scheduled-backups-13430-beta)).
- **Audit-chain anchors:**
  - **What they did:** reported a tree root computed from
    tenant/type/reference/time, with status `anchored`.
  - **Then:** relabelled `recorded`, root dropped (3.0.0-beta).
  - **Now:** removed in 3.1.0-beta (routes, table via keycore migration 027).
    The audit service's signed checkpoints are the real tamper evidence
    ([SECURITY/AUDIT_INTEGRITY.md](SECURITY/AUDIT_INTEGRITY.md)).

- **Key metadata profiles** (13.50.0-beta):
  - **What they did:** stored a record per profile; key creation never
    read it.
  - **Now:** real profiles enforced on create, import and update
    ([KEYS.md 5.5](KEYS.md#55-metadata-profiles-13500-beta)). The preview
    route is removed, a new record of its category is refused (`410
    feature_retired`, `pkg/features.Retired`), and old records list as
    `retired`.
- **Key binding policies and sharing grants** (13.51.0-beta):
  - **What they did:** stored records; no key operation read them.
  - **Now:** binding policies are enforced on every key operation
    ([KEYS.md 5.6](KEYS.md#56-binding-policies-13510-beta)). Sharing
    grants are retired in favour of key access grants, which keycore
    already enforced. Both preview routes are removed, new records of
    either category are refused (`410 feature_retired`), old ones list as
    `retired`.
- **Edge agents, leases and receipts** (13.52.0-beta):
  - **What they did:** stored records in keycore; nothing ran on a device.
  - **Now:** edge devices enrol, lease data keys sealed to their own
    ML-KEM key, work offline with the `edge-agent`, and report signed
    receipts ([SECURITY/EDGE_DEVICES.md](SECURITY/EDGE_DEVICES.md)). The
    preview routes are removed, new records are refused (`410
    feature_retired`), old ones list as `retired`.

## Leaving preview

A feature leaves the catalogue only once:
- it enforces or executes what it describes;
- a test proves the bad case is refused;
- this page and the dashboard list are updated.
