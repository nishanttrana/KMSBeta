CREATE TABLE IF NOT EXISTS pqc_policies (
    tenant_id TEXT NOT NULL PRIMARY KEY,
    profile_id TEXT NOT NULL DEFAULT 'balanced_hybrid',
    default_kem TEXT NOT NULL DEFAULT 'ML-KEM-768',
    default_signature TEXT NOT NULL DEFAULT 'ML-DSA-65',
    interface_default_mode TEXT NOT NULL DEFAULT 'hybrid',
    certificate_default_mode TEXT NOT NULL DEFAULT 'hybrid',
    hqc_backup_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    flag_classical_usage BOOLEAN NOT NULL DEFAULT TRUE,
    flag_classical_certificates BOOLEAN NOT NULL DEFAULT TRUE,
    flag_non_migrated_interfaces BOOLEAN NOT NULL DEFAULT TRUE,
    require_pqc_for_new_keys BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
