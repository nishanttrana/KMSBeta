-- Crypto agility risk assessment (CARAF). Every value is the customer's:
-- threats with the years they expect each to materialise (Z), and assets
-- with their shelf life (X), migration time (Y), cost, profile and the keys
-- they use. Keycore computes exposure (X + Y against Z) and tracks each
-- asset's decision (secure, accept, phase out, compensating control).
CREATE TABLE IF NOT EXISTS caraf_threats (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    match_kind TEXT NOT NULL,
    match_value TEXT NOT NULL DEFAULT '',
    years_to_threat INT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS caraf_assets (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    owner TEXT NOT NULL DEFAULT '',
    ownership TEXT NOT NULL DEFAULT 'unknown',
    implementation TEXT NOT NULL DEFAULT 'unknown',
    pqc_support TEXT NOT NULL DEFAULT 'unknown',
    location TEXT NOT NULL DEFAULT 'unknown',
    jurisdiction TEXT NOT NULL DEFAULT '',
    sensitivity TEXT NOT NULL DEFAULT 'unknown',
    shelf_life_years INT,
    migration_years INT,
    cost TEXT NOT NULL DEFAULT 'unknown',
    algorithms TEXT NOT NULL DEFAULT '[]',
    key_ids TEXT NOT NULL DEFAULT '[]',
    decision TEXT NOT NULL DEFAULT '',
    decision_owner TEXT NOT NULL DEFAULT '',
    decision_due TIMESTAMPTZ,
    decision_review_by TIMESTAMPTZ,
    decision_status TEXT NOT NULL DEFAULT '',
    decision_note TEXT NOT NULL DEFAULT '',
    decided_by TEXT NOT NULL DEFAULT '',
    decided_at TIMESTAMPTZ,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);
