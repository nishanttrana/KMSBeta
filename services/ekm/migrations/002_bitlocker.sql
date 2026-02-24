CREATE TABLE IF NOT EXISTS ekm_bitlocker_clients (
    tenant_id                TEXT NOT NULL,
    id                       TEXT NOT NULL,
    name                     TEXT NOT NULL,
    host                     TEXT NOT NULL DEFAULT '',
    os_version               TEXT NOT NULL DEFAULT '',
    status                   TEXT NOT NULL DEFAULT 'connected',
    health                   TEXT NOT NULL DEFAULT 'unknown',
    protection_status        TEXT NOT NULL DEFAULT 'unknown',
    encryption_percentage    REAL NOT NULL DEFAULT 0,
    mount_point              TEXT NOT NULL DEFAULT 'C:',
    heartbeat_interval_sec   INTEGER NOT NULL DEFAULT 30,
    last_heartbeat_at        TIMESTAMP,
    tpm_present              BOOLEAN NOT NULL DEFAULT FALSE,
    tpm_ready                BOOLEAN NOT NULL DEFAULT FALSE,
    jwt_subject              TEXT NOT NULL DEFAULT '',
    tls_client_cn            TEXT NOT NULL DEFAULT '',
    metadata_json            TEXT NOT NULL DEFAULT '{}',
    created_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS ekm_bitlocker_jobs (
    tenant_id             TEXT NOT NULL,
    id                    TEXT NOT NULL,
    client_id             TEXT NOT NULL,
    operation             TEXT NOT NULL,
    params_json           TEXT NOT NULL DEFAULT '{}',
    status                TEXT NOT NULL DEFAULT 'pending',
    requested_by          TEXT NOT NULL DEFAULT '',
    request_id            TEXT NOT NULL DEFAULT '',
    requested_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    dispatched_at         TIMESTAMP,
    completed_at          TIMESTAMP,
    result_json           TEXT NOT NULL DEFAULT '{}',
    error_message         TEXT NOT NULL DEFAULT '',
    recovery_key_ref      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE IF NOT EXISTS ekm_bitlocker_recovery_keys (
    tenant_id              TEXT NOT NULL,
    id                     TEXT NOT NULL,
    client_id              TEXT NOT NULL,
    job_id                 TEXT NOT NULL DEFAULT '',
    volume_mount_point     TEXT NOT NULL DEFAULT 'C:',
    protector_id           TEXT NOT NULL DEFAULT '',
    key_fingerprint        TEXT NOT NULL DEFAULT '',
    key_masked             TEXT NOT NULL DEFAULT '',
    wrapped_dek            TEXT NOT NULL,
    wrapped_dek_iv         TEXT NOT NULL,
    ciphertext             TEXT NOT NULL,
    data_iv                TEXT NOT NULL,
    source                 TEXT NOT NULL DEFAULT 'agent',
    created_at             TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_ekm_bitlocker_clients_status
    ON ekm_bitlocker_clients (tenant_id, status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_ekm_bitlocker_jobs_client
    ON ekm_bitlocker_jobs (tenant_id, client_id, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_ekm_bitlocker_jobs_status
    ON ekm_bitlocker_jobs (tenant_id, status, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_ekm_bitlocker_recovery_client
    ON ekm_bitlocker_recovery_keys (tenant_id, client_id, created_at DESC);
