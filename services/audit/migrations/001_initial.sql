BEGIN;

CREATE TABLE IF NOT EXISTS audit_events (
    id              TEXT NOT NULL,
    tenant_id       TEXT NOT NULL,
    sequence        BIGINT NOT NULL,
    chain_hash      TEXT NOT NULL,
    previous_hash   TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    service         TEXT NOT NULL,
    action          TEXT NOT NULL,
    actor_id        TEXT NOT NULL,
    actor_type      TEXT NOT NULL,
    target_type     TEXT,
    target_id       TEXT,
    method          TEXT,
    endpoint        TEXT,
    source_ip       INET,
    user_agent      TEXT,
    request_hash    TEXT,
    correlation_id  TEXT,
    parent_event_id TEXT,
    session_id      TEXT,
    result          TEXT NOT NULL,
    status_code     INTEGER,
    error_message   TEXT,
    duration_ms     REAL,
    fips_compliant  BOOLEAN,
    approval_id     TEXT,
    risk_score      INTEGER DEFAULT 0,
    tags            JSONB,
    node_id         TEXT,
    details         JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE TABLE IF NOT EXISTS audit_events_2026_01 PARTITION OF audit_events
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE IF NOT EXISTS audit_events_2026_02 PARTITION OF audit_events
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Audit events are immutable - updates and deletes are prohibited';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_immutable_update ON audit_events;
DROP TRIGGER IF EXISTS audit_immutable_delete ON audit_events;
CREATE TRIGGER audit_immutable_update BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
CREATE TRIGGER audit_immutable_delete BEFORE DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_events(tenant_id, correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_events(tenant_id, target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(tenant_id, actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(tenant_id, action);
CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events(tenant_id, session_id);
CREATE INDEX IF NOT EXISTS idx_audit_risk ON audit_events(tenant_id, risk_score) WHERE risk_score > 50;
CREATE INDEX IF NOT EXISTS idx_audit_fips ON audit_events(tenant_id, fips_compliant) WHERE fips_compliant = FALSE;
CREATE INDEX IF NOT EXISTS idx_audit_result ON audit_events(tenant_id, result) WHERE result != 'success';
CREATE INDEX IF NOT EXISTS idx_audit_chain ON audit_events(tenant_id, sequence);
CREATE INDEX IF NOT EXISTS idx_audit_event_lookup ON audit_events(tenant_id, id, timestamp DESC);

CREATE TABLE IF NOT EXISTS alerts (
    id                  TEXT NOT NULL,
    tenant_id           TEXT NOT NULL,
    audit_event_id      TEXT NOT NULL,
    severity            TEXT NOT NULL,
    category            TEXT NOT NULL,
    title               TEXT NOT NULL,
    description         TEXT,
    source_service      TEXT NOT NULL,
    actor_id            TEXT,
    target_id           TEXT,
    risk_score          INTEGER DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'open',
    acknowledged_by     TEXT,
    acknowledged_at     TIMESTAMPTZ,
    resolved_by         TEXT,
    resolved_at         TIMESTAMPTZ,
    resolution_note     TEXT,
    dispatched_channels JSONB,
    dispatch_status     JSONB,
    dedup_key           TEXT,
    occurrence_count    INTEGER DEFAULT 1,
    escalated_from      TEXT,
    escalated_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(tenant_id, severity, status);
CREATE INDEX IF NOT EXISTS idx_alerts_open ON alerts(tenant_id, status) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_alerts_audit ON alerts(tenant_id, audit_event_id);
CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(tenant_id, category);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(tenant_id, dedup_key);

CREATE TABLE IF NOT EXISTS alert_rules (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL,
    name            TEXT NOT NULL,
    condition_expr  TEXT NOT NULL,
    severity        TEXT NOT NULL,
    title           TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMIT;
