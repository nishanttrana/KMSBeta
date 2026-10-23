-- 012: edge devices, their key leases and usage receipts (13.52.0-beta,
-- docs/SECURITY/EDGE_DEVICES.md).
--
-- A device enrols with a one-use registration token and presents two public
-- keys: an ML-KEM-768 encapsulation key (leases are sealed to it) and an
-- ECDSA P-256 key (its usage receipts are signed with it). Its credential,
-- like an EKM client's, is stored only as a SHA-256. A lease is a data key
-- from keycore under one of the device's allowed keys: the device receives
-- it sealed, and only keycore's wrapped copy is kept here, so the data stays
-- decryptable centrally. Receipts are what the device did offline, in order.
-- Replicated (pkg/clustercatalog, ekm).
CREATE TABLE IF NOT EXISTS ekm_edge_devices (
    tenant_id          TEXT NOT NULL,
    id                 TEXT NOT NULL,
    name               TEXT NOT NULL,
    status             TEXT NOT NULL DEFAULT 'pending',
    allowed_key_ids    TEXT NOT NULL DEFAULT '[]',
    max_lease_seconds  BIGINT NOT NULL DEFAULT 86400,
    token_hash         TEXT NOT NULL DEFAULT '',
    token_expires_at   TIMESTAMPTZ,
    credential_hash    TEXT NOT NULL DEFAULT '',
    signing_public_key TEXT NOT NULL DEFAULT '',
    kem_public_key     TEXT NOT NULL DEFAULT '',
    last_receipt_seq   BIGINT NOT NULL DEFAULT 0,
    last_seen_at       TIMESTAMPTZ,
    last_source_ip     TEXT NOT NULL DEFAULT '',
    agent_version      TEXT NOT NULL DEFAULT '',
    created_by         TEXT NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    enrolled_at        TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    revoked_by         TEXT NOT NULL DEFAULT '',
    revoke_reason      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS ekm_edge_devices_name ON ekm_edge_devices (tenant_id, name);

CREATE TABLE IF NOT EXISTS ekm_edge_leases (
    tenant_id      TEXT NOT NULL,
    id             TEXT NOT NULL,
    device_id      TEXT NOT NULL,
    key_id         TEXT NOT NULL,
    key_version    BIGINT NOT NULL DEFAULT 0,
    wrapped_dek    TEXT NOT NULL,
    wrapped_dek_iv TEXT NOT NULL DEFAULT '',
    issued_at      TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    revoked_at     TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS ekm_edge_leases_device ON ekm_edge_leases (tenant_id, device_id, issued_at);

CREATE TABLE IF NOT EXISTS ekm_edge_receipts (
    tenant_id   TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    seq         BIGINT NOT NULL,
    lease_id    TEXT NOT NULL,
    operation   TEXT NOT NULL,
    bytes       BIGINT NOT NULL DEFAULT 0,
    device_time TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, device_id, seq)
);
