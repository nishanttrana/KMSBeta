-- Rotation schedules for secrets the KMS generated (13.66.0-beta,
-- rotation_schedule.go, docs/SCHEDULING.md). One per secret; a run makes
-- fresh material of the same kind as the next version, on the authority of
-- the person who saved the schedule, re-checked before every run.
CREATE TABLE IF NOT EXISTS secret_rotation_schedules (
    tenant_id      TEXT NOT NULL,
    secret_id      TEXT NOT NULL,
    interval_hours INTEGER NOT NULL,
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    authorized_by  TEXT NOT NULL DEFAULT '',
    paused_reason  TEXT NOT NULL DEFAULT '',
    next_run_at    TIMESTAMPTZ,
    last_run_at    TIMESTAMPTZ,
    last_result    TEXT NOT NULL DEFAULT '',
    last_error     TEXT NOT NULL DEFAULT '',
    last_version   INTEGER NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, secret_id)
);
CREATE INDEX IF NOT EXISTS idx_secret_rotation_schedules_due ON secret_rotation_schedules(next_run_at) WHERE enabled AND paused_reason = '';
