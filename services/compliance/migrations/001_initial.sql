CREATE TABLE IF NOT EXISTS compliance_posture_snapshots (
    tenant_id         TEXT NOT NULL,
    id                TEXT NOT NULL,
    overall_score     INTEGER NOT NULL,
    key_hygiene       INTEGER NOT NULL,
    policy_compliance INTEGER NOT NULL,
    access_security   INTEGER NOT NULL,
    crypto_posture    INTEGER NOT NULL,
    pqc_readiness     INTEGER NOT NULL,
    framework_scores  TEXT NOT NULL DEFAULT '{}',
    metrics_json      TEXT NOT NULL DEFAULT '{}',
    gap_count         INTEGER NOT NULL DEFAULT 0,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_posture_tenant_created
    ON compliance_posture_snapshots (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS compliance_framework_assessments (
    tenant_id     TEXT NOT NULL,
    id            TEXT NOT NULL,
    framework_id  TEXT NOT NULL,
    score         INTEGER NOT NULL,
    status        TEXT NOT NULL,
    controls_json TEXT NOT NULL DEFAULT '[]',
    gaps_json     TEXT NOT NULL DEFAULT '[]',
    pqc_ready     INTEGER NOT NULL DEFAULT 0,
    qsl_avg       DOUBLE PRECISION NOT NULL DEFAULT 0,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_compliance_framework_assessments_tenant_framework
    ON compliance_framework_assessments (tenant_id, framework_id);

CREATE TABLE IF NOT EXISTS compliance_gaps (
    tenant_id     TEXT NOT NULL,
    id            TEXT NOT NULL,
    framework_id  TEXT NOT NULL,
    control_id    TEXT NOT NULL,
    severity      TEXT NOT NULL,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL,
    resource_id   TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'open',
    detected_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at   TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_gaps_tenant_framework
    ON compliance_gaps (tenant_id, framework_id, status, detected_at DESC);

CREATE TABLE IF NOT EXISTS compliance_cbom_snapshots (
    tenant_id     TEXT NOT NULL,
    id            TEXT NOT NULL,
    summary_json  TEXT NOT NULL DEFAULT '{}',
    document_json TEXT NOT NULL DEFAULT '{}',
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_compliance_cbom_tenant_created
    ON compliance_cbom_snapshots (tenant_id, created_at DESC);
