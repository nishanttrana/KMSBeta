CREATE TABLE IF NOT EXISTS posture_events_hot (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    event_ts TIMESTAMP NOT NULL,
    service TEXT NOT NULL,
    action TEXT NOT NULL,
    result TEXT NOT NULL,
    severity TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    resource_id TEXT NOT NULL DEFAULT '',
    error_code TEXT NOT NULL DEFAULT '',
    latency_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
    node_id TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_posture_events_hot_tenant_time
    ON posture_events_hot (tenant_id, event_ts DESC);
CREATE INDEX IF NOT EXISTS idx_posture_events_hot_service_action
    ON posture_events_hot (tenant_id, service, action, event_ts DESC);
CREATE INDEX IF NOT EXISTS idx_posture_events_hot_result
    ON posture_events_hot (tenant_id, result, event_ts DESC);
CREATE INDEX IF NOT EXISTS idx_posture_events_hot_request
    ON posture_events_hot (tenant_id, request_id);

CREATE TABLE IF NOT EXISTS posture_events_history (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    event_ts TIMESTAMP NOT NULL,
    service TEXT NOT NULL,
    action TEXT NOT NULL,
    result TEXT NOT NULL,
    severity TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    resource_id TEXT NOT NULL DEFAULT '',
    error_code TEXT NOT NULL DEFAULT '',
    latency_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
    node_id TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_posture_events_history_tenant_time
    ON posture_events_history (tenant_id, event_ts DESC);
CREATE INDEX IF NOT EXISTS idx_posture_events_history_service_action
    ON posture_events_history (tenant_id, service, action, event_ts DESC);
CREATE INDEX IF NOT EXISTS idx_posture_events_history_result
    ON posture_events_history (tenant_id, result, event_ts DESC);

CREATE TABLE IF NOT EXISTS posture_findings (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    engine TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    recommended_action TEXT NOT NULL DEFAULT '',
    auto_action_allowed BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'open',
    fingerprint TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    sla_due_at TIMESTAMP,
    reopen_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_posture_findings_fingerprint
    ON posture_findings (tenant_id, fingerprint);
CREATE INDEX IF NOT EXISTS idx_posture_findings_status
    ON posture_findings (tenant_id, status, severity, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_posture_findings_engine
    ON posture_findings (tenant_id, engine, finding_type, updated_at DESC);

CREATE TABLE IF NOT EXISTS posture_risk_snapshots (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    risk_24h INTEGER NOT NULL DEFAULT 0,
    risk_7d INTEGER NOT NULL DEFAULT 0,
    predictive_score INTEGER NOT NULL DEFAULT 0,
    preventive_score INTEGER NOT NULL DEFAULT 0,
    corrective_score INTEGER NOT NULL DEFAULT 0,
    top_signals_json TEXT NOT NULL DEFAULT '{}',
    captured_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_posture_risk_snapshots_time
    ON posture_risk_snapshots (tenant_id, captured_at DESC);

CREATE TABLE IF NOT EXISTS posture_actions (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    finding_id TEXT NOT NULL DEFAULT '',
    action_type TEXT NOT NULL,
    recommended_action TEXT NOT NULL DEFAULT '',
    safety_gate TEXT NOT NULL DEFAULT 'manual',
    approval_required BOOLEAN NOT NULL DEFAULT TRUE,
    approval_request_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'suggested',
    executed_by TEXT NOT NULL DEFAULT '',
    executed_at TIMESTAMP,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    result_message TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_posture_actions_status
    ON posture_actions (tenant_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posture_actions_finding
    ON posture_actions (tenant_id, finding_id);

CREATE TABLE IF NOT EXISTS posture_engine_state (
    tenant_id TEXT NOT NULL PRIMARY KEY,
    last_audit_sync_at TIMESTAMP,
    last_audit_event_ts TIMESTAMP,
    last_run_at TIMESTAMP
);

