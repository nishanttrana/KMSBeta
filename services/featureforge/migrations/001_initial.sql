-- FeatureForge schema. SQLite/Postgres compatible (same style as other services).

CREATE TABLE IF NOT EXISTS ff_intents (
    id          TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    actor       TEXT NOT NULL DEFAULT '',
    raw_text    TEXT NOT NULL,
    mode        TEXT NOT NULL DEFAULT 'config',
    stage       TEXT NOT NULL DEFAULT 'received',
    action      TEXT NOT NULL DEFAULT '',
    params      TEXT NOT NULL DEFAULT '{}',
    confidence  REAL NOT NULL DEFAULT 0,
    reasons     TEXT NOT NULL DEFAULT '[]',
    mcp_job_id  TEXT NOT NULL DEFAULT '',
    approval_id TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ff_intents_tenant ON ff_intents(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ff_intents_stage  ON ff_intents(tenant_id, stage);

-- Per-intent guardrail event trail (inspectability + post-hoc review).
CREATE TABLE IF NOT EXISTS ff_events (
    id         BIGSERIAL PRIMARY KEY,
    intent_id  TEXT NOT NULL,
    tenant_id  TEXT NOT NULL,
    actor      TEXT NOT NULL DEFAULT '',
    action     TEXT NOT NULL DEFAULT '',
    stage      TEXT NOT NULL,
    outcome    TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT '',
    ts         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ff_events_intent ON ff_events(intent_id, id);
