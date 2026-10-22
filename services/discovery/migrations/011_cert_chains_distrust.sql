-- Certificate chains and distrusted CAs (13.46.0-beta).
--
-- discovery_cert_chains: the chain a TLS endpoint presented for a
-- discovered certificate, one row per certificate (position 0 is the leaf),
-- by the SHA-256 of its SubjectPublicKeyInfo. A rescan replaces the rows.
-- Whether a chain runs through a distrusted CA is decided when it is read,
-- against the list as it is then, so a CA distrusted after a scan is found
-- without rescanning.
--
-- discovery_distrusted_cas: CA keys a tenant distrusts, by SPKI SHA-256.
-- The platform's own list (services/discovery/distrust.go) is not stored.
--
-- Both replicated (pkg/clustercatalog, discovery).
CREATE TABLE IF NOT EXISTS discovery_cert_chains (
    tenant_id    TEXT NOT NULL,
    asset_id     TEXT NOT NULL,
    position     INTEGER NOT NULL,
    spki_sha256  TEXT NOT NULL,
    subject      TEXT NOT NULL DEFAULT '',
    issuer       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, asset_id, position)
);
CREATE INDEX IF NOT EXISTS idx_discovery_cert_chains_spki ON discovery_cert_chains (tenant_id, spki_sha256);

CREATE TABLE IF NOT EXISTS discovery_distrusted_cas (
    tenant_id    TEXT NOT NULL,
    spki_sha256  TEXT NOT NULL,
    label        TEXT NOT NULL,
    added_by     TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, spki_sha256)
);
