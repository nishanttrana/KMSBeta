-- 039: scheduling on a person's authority (13.66.0-beta, docs/SCHEDULING.md).
--
-- Rotation policies record who last saved them; a scheduled run acts as that
-- person after asking auth, and pauses with a reason when the authority is
-- gone. Policies saved before this have no one on record and pause at their
-- next run until someone saves them again.
ALTER TABLE rotation_policies ADD COLUMN IF NOT EXISTS authorized_by TEXT NOT NULL DEFAULT '';
ALTER TABLE rotation_policies ADD COLUMN IF NOT EXISTS paused_reason TEXT NOT NULL DEFAULT '';

-- Key integrity schedules: the material and KCV check of matching keys on
-- an interval (integrity_schedule.go).
CREATE TABLE IF NOT EXISTS key_integrity_schedules (
    id                TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    name              TEXT NOT NULL,
    target_filter     TEXT NOT NULL,
    interval_hours    INTEGER NOT NULL,
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    authorized_by     TEXT NOT NULL DEFAULT '',
    paused_reason     TEXT NOT NULL DEFAULT '',
    next_run_at       TIMESTAMPTZ,
    last_run_at       TIMESTAMPTZ,
    last_result       TEXT NOT NULL DEFAULT '',
    last_error        TEXT NOT NULL DEFAULT '',
    last_checked      INTEGER NOT NULL DEFAULT 0,
    last_failed       INTEGER NOT NULL DEFAULT 0,
    last_not_assessed INTEGER NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS idx_key_integrity_schedules_due ON key_integrity_schedules(next_run_at) WHERE enabled AND paused_reason = '';

-- The "scheduled jobs" table (012) held jobs nothing ever ran; its routes
-- are removed in the same release.
DROP TABLE IF EXISTS key_scheduling_jobs;
