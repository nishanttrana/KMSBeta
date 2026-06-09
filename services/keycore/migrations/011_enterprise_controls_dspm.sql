BEGIN;

CREATE TABLE IF NOT EXISTS enterprise_control_records (
    record_id     TEXT NOT NULL,
    tenant_id     TEXT NOT NULL,
    category      TEXT NOT NULL,
    key_id        TEXT,
    name          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'active',
    severity      TEXT,
    risk_score    INTEGER NOT NULL DEFAULT 0,
    expires_at    TIMESTAMPTZ,
    metadata_json JSONB NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, category, record_id)
);

CREATE INDEX IF NOT EXISTS idx_enterprise_controls_category ON enterprise_control_records(tenant_id, category, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_enterprise_controls_key ON enterprise_control_records(tenant_id, key_id, category) WHERE key_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_enterprise_controls_risk ON enterprise_control_records(tenant_id, risk_score DESC, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_enterprise_controls_status ON enterprise_control_records(tenant_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS key_dspm_findings (
    finding_id         TEXT NOT NULL,
    tenant_id          TEXT NOT NULL,
    source             TEXT NOT NULL DEFAULT 'keycore',
    finding_type       TEXT NOT NULL,
    title              TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    severity           TEXT NOT NULL DEFAULT 'info',
    risk_score         INTEGER NOT NULL DEFAULT 0,
    status             TEXT NOT NULL DEFAULT 'open',
    key_id             TEXT,
    recommended_action TEXT NOT NULL DEFAULT '',
    evidence_json      JSONB NOT NULL DEFAULT '{}',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_key_dspm_findings_source ON key_dspm_findings(tenant_id, source, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_key_dspm_findings_type ON key_dspm_findings(tenant_id, finding_type, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_key_dspm_findings_risk ON key_dspm_findings(tenant_id, risk_score DESC, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_key_dspm_findings_key ON key_dspm_findings(tenant_id, key_id) WHERE key_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS key_audit_chain_anchors (
    anchor_id          TEXT NOT NULL,
    tenant_id          TEXT NOT NULL,
    anchor_type        TEXT NOT NULL,
    merkle_root        TEXT NOT NULL,
    previous_hash      TEXT,
    anchor_hash        TEXT NOT NULL,
    external_reference TEXT,
    status             TEXT NOT NULL DEFAULT 'anchored',
    metadata_json      JSONB NOT NULL DEFAULT '{}',
    anchored_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_at        TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, anchor_id)
);

CREATE INDEX IF NOT EXISTS idx_key_audit_anchors_time ON key_audit_chain_anchors(tenant_id, anchored_at DESC);
CREATE INDEX IF NOT EXISTS idx_key_audit_anchors_hash ON key_audit_chain_anchors(tenant_id, anchor_hash);

ALTER TABLE enterprise_control_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_dspm_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_audit_chain_anchors ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_enterprise_control_records') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_enterprise_control_records ON enterprise_control_records USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_dspm_findings') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_dspm_findings ON key_dspm_findings USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_key_audit_chain_anchors') THEN
        EXECUTE 'CREATE POLICY tenant_isolation_key_audit_chain_anchors ON key_audit_chain_anchors USING (tenant_id = current_setting(''app.tenant_id'', true))';
    END IF;
END $$;

COMMIT;
