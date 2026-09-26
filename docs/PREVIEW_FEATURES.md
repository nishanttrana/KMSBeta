# Preview Features

**Standing rule.** A feature that only stores configuration, without enforcing
or executing it, is a **preview**. It is never presented as finished (CLAUDE.md
rule 7). The single catalogue is `pkg/features.Preview`, and every surface
reflects it:

- **API:** responses carry `X-Vecta-Feature-Status: preview` and
  `X-Vecta-Feature-Status-Id: <id>`. keycore control records carry
  `feature_status` and `feature_id`.
- **Dashboard:** `web/dashboard/src/lib/featureStatus.ts` mirrors the catalogue.
  `make conformance` (rule `preview-catalogue`) fails if the two differ. The
  Docs tab has a Preview Features page, and preview screens show a Preview
  banner with their actions disabled.
- **Docs:** this page, [RECOMMENDED_FEATURES.md](RECOMMENDED_FEATURES.md).

| ID | Feature | What does not happen |
|---|---|---|
| `keycore.federation` | Key federation / multi-KMS failover | Providers, mappings and failovers are stored; no key is replicated and no failover happens. |
| `keycore.binding_policy` | Key binding policies | Stored only; key operations do not evaluate them. |
| `keycore.sharing_grant` | Fine-grained key sharing grants | Stored only; use key access grants for enforced sharing. |
| `keycore.metadata_profile` | Key metadata profiles | Stored only; key creation does not apply or validate them. |
| `keycore.edge` | Edge & IoT agents, leases and receipts | Stored only; there is no edge runtime. |
| `keycore.advanced_encryption_modes` | Homomorphic / functional encryption modes | Registered as controls; no homomorphic or functional encryption is performed. Searchable HMAC tokens are available. |
| `keycore.audit_chain_anchor` | External audit-chain anchors | Records an external reference in a local hash chain; nothing is anchored externally. |
| `backup.scheduler` | Backup policies, runs and restore points (Backup tab) | Policies are stored but no backup is executed or restored. |

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
- **Audit-chain anchors:**
  - **What they did:** reported a `merkle_root` computed from
    tenant/type/reference/time, with status `anchored`.
  - **Now:** they report no Merkle root and status `recorded`. Existing rows
    are relabelled (keycore migration 018). The platform's actual audit tamper
    evidence is the audit service's hash chain, per-event HMAC and Merkle
    epochs.

## Leaving preview

A feature leaves the catalogue only once:
- it enforces or executes what it describes;
- a test proves the bad case is refused;
- this page and the dashboard list are updated.
