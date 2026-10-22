-- Scheduled encrypted backups (13.43.0-beta). A schedule takes a governance
-- backup every interval_hours, on the authority of the root administrator
-- who saved it, and keeps the newest retain_count. Nobody is there to take a
-- software-mode key, so the backup key is either wrapped in the tenant's HSM
-- (key_protection 'hsm') or sealed to the administrator's RSA public key
-- (key_protection 'recipient'); the private key never reaches the platform.
--
-- Replicated (pkg/clustercatalog, governance): written by the primary only.
CREATE TABLE IF NOT EXISTS governance_backup_schedules (
    id                      TEXT PRIMARY KEY,
    tenant_id               TEXT NOT NULL,
    name                    TEXT NOT NULL,
    enabled                 BOOLEAN NOT NULL DEFAULT TRUE,
    scope                   TEXT NOT NULL,
    target_tenant_id        TEXT NOT NULL DEFAULT '',
    interval_hours          INTEGER NOT NULL,
    retain_count            INTEGER NOT NULL,
    key_protection          TEXT NOT NULL,
    recipient_public_key    TEXT NOT NULL DEFAULT '',
    recipient_key_sha256    TEXT NOT NULL DEFAULT '',
    authorized_by           TEXT NOT NULL,
    paused_reason           TEXT NOT NULL DEFAULT '',
    next_run_at             TIMESTAMPTZ,
    last_run_at             TIMESTAMPTZ,
    last_result             TEXT NOT NULL DEFAULT '',
    last_backup_id          TEXT NOT NULL DEFAULT '',
    last_error              TEXT NOT NULL DEFAULT '',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_governance_backup_schedules_due
    ON governance_backup_schedules (enabled, next_run_at);

-- The schedule a backup was taken by ('' for one taken by hand), so
-- retention removes only that schedule's own backups.
ALTER TABLE governance_backup_jobs ADD COLUMN IF NOT EXISTS schedule_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_governance_backup_jobs_schedule
    ON governance_backup_jobs (tenant_id, schedule_id, created_at DESC);
