CREATE TABLE IF NOT EXISTS confidential_attestation_policy (
    tenant_id TEXT PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    provider TEXT NOT NULL DEFAULT 'aws_nitro_enclaves',
    mode TEXT NOT NULL DEFAULT 'enforce',
    key_scopes_json TEXT NOT NULL DEFAULT '[]',
    approved_images_json TEXT NOT NULL DEFAULT '[]',
    approved_subjects_json TEXT NOT NULL DEFAULT '[]',
    allowed_attesters_json TEXT NOT NULL DEFAULT '[]',
    required_measurements_json TEXT NOT NULL DEFAULT '{}',
    required_claims_json TEXT NOT NULL DEFAULT '{}',
    require_secure_boot BOOLEAN NOT NULL DEFAULT TRUE,
    require_debug_disabled BOOLEAN NOT NULL DEFAULT TRUE,
    max_evidence_age_sec INTEGER NOT NULL DEFAULT 300,
    cluster_scope TEXT NOT NULL DEFAULT 'cluster_wide',
    allowed_cluster_nodes_json TEXT NOT NULL DEFAULT '[]',
    fallback_action TEXT NOT NULL DEFAULT 'deny',
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS confidential_release_history (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_scope TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL,
    workload_identity TEXT NOT NULL DEFAULT '',
    attester TEXT NOT NULL DEFAULT '',
    image_ref TEXT NOT NULL DEFAULT '',
    image_digest TEXT NOT NULL DEFAULT '',
    audience TEXT NOT NULL DEFAULT '',
    nonce TEXT NOT NULL DEFAULT '',
    evidence_issued_at TIMESTAMP NULL,
    claims_json TEXT NOT NULL DEFAULT '{}',
    measurements_json TEXT NOT NULL DEFAULT '{}',
    secure_boot BOOLEAN NOT NULL DEFAULT FALSE,
    debug_disabled BOOLEAN NOT NULL DEFAULT FALSE,
    cluster_node_id TEXT NOT NULL DEFAULT '',
    requester TEXT NOT NULL DEFAULT '',
    release_reason TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL,
    allowed BOOLEAN NOT NULL DEFAULT FALSE,
    reasons_json TEXT NOT NULL DEFAULT '[]',
    matched_claims_json TEXT NOT NULL DEFAULT '[]',
    matched_measurements_json TEXT NOT NULL DEFAULT '[]',
    missing_claims_json TEXT NOT NULL DEFAULT '[]',
    missing_measurements_json TEXT NOT NULL DEFAULT '[]',
    missing_attributes_json TEXT NOT NULL DEFAULT '[]',
    measurement_hash TEXT NOT NULL DEFAULT '',
    claims_hash TEXT NOT NULL DEFAULT '',
    policy_version TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_confidential_release_history_created_at
    ON confidential_release_history (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_confidential_release_history_decision
    ON confidential_release_history (tenant_id, decision, created_at DESC);
