-- 038: key federation across separate KMS installations (13.60.0-beta,
-- docs/FEDERATION.md). Replaces the federation preview, which stored
-- providers, mappings and failovers and replicated nothing.
--
-- An identity is a tenant's ML-KEM-768 key (key material is sealed to it)
-- and ECDSA P-256 key (it signs what the tenant sends). Its secrets are
-- sealed under keycore's master key, like key material. A peer is another
-- installation's identity, address and REST client. A link replicates one
-- key to one peer. The state row says whether a key here is the primary, a
-- replica, or a former primary fenced by a promotion (demoted), and at
-- which epoch. Replicated (pkg/clustercatalog, keycore).
CREATE TABLE IF NOT EXISTS key_federation_identities (
    tenant_id        TEXT PRIMARY KEY,
    kem_seed_sealed  TEXT NOT NULL,
    sign_key_sealed  TEXT NOT NULL,
    kem_public       TEXT NOT NULL,
    sign_public_pem  TEXT NOT NULL,
    fingerprint      TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS key_federation_peers (
    tenant_id        TEXT NOT NULL,
    id               TEXT NOT NULL,
    name             TEXT NOT NULL,
    url              TEXT NOT NULL,
    peer_tenant_id   TEXT NOT NULL,
    kem_public       TEXT NOT NULL,
    sign_public_pem  TEXT NOT NULL,
    fingerprint      TEXT NOT NULL,
    ca_pem           TEXT NOT NULL DEFAULT '',
    client_id        TEXT NOT NULL,
    api_key_sealed   TEXT NOT NULL,
    created_by       TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS key_federation_peers_name ON key_federation_peers (tenant_id, name);
CREATE UNIQUE INDEX IF NOT EXISTS key_federation_peers_fingerprint ON key_federation_peers (tenant_id, fingerprint);

CREATE TABLE IF NOT EXISTS key_federation_links (
    tenant_id     TEXT NOT NULL,
    id            TEXT NOT NULL,
    key_id        TEXT NOT NULL,
    peer_id       TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    last_digest   TEXT NOT NULL DEFAULT '',
    last_sync_at  TIMESTAMPTZ,
    last_error    TEXT NOT NULL DEFAULT '',
    created_by    TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS key_federation_links_pair ON key_federation_links (tenant_id, key_id, peer_id);

CREATE TABLE IF NOT EXISTS key_federation_state (
    tenant_id            TEXT NOT NULL,
    key_id               TEXT NOT NULL,
    role                 TEXT NOT NULL,
    epoch                BIGINT NOT NULL DEFAULT 1,
    source_peer_id       TEXT NOT NULL DEFAULT '',
    primary_fingerprint  TEXT NOT NULL DEFAULT '',
    last_applied_at      TIMESTAMPTZ,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, key_id)
);
