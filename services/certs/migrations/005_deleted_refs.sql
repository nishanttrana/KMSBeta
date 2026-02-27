CREATE TABLE IF NOT EXISTS cert_deleted_refs (
    tenant_id      TEXT NOT NULL,
    cert_id        TEXT NOT NULL,
    ca_id          TEXT NOT NULL,
    serial_number  TEXT NOT NULL,
    subject_cn     TEXT NOT NULL,
    deleted_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, cert_id)
);

CREATE INDEX IF NOT EXISTS idx_cert_deleted_refs_deleted_at ON cert_deleted_refs (tenant_id, deleted_at DESC);
