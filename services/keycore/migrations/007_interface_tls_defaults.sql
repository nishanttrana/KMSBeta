BEGIN;

CREATE TABLE IF NOT EXISTS key_interface_tls_defaults (
    tenant_id TEXT PRIMARY KEY,
    certificate_source TEXT NOT NULL DEFAULT 'internal_ca',
    ca_id TEXT,
    certificate_id TEXT,
    updated_by TEXT,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMIT;
