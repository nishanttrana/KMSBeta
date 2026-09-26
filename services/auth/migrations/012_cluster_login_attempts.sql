-- Migration 012: cluster-wide login lockout (docs/CLUSTERING.md, slice 3b).
--
-- Every node records each failed and successful login for a lockout key
-- (tenant | username | client IP). The table is shared-append: rows replicate
-- between all cluster nodes, so failures spread across nodes count together.
-- key_hash is SHA-256 of the lockout key, so the table itself holds neither
-- the username nor the address (the audit trail does, as before).
-- chain_node names the writing node ('' while standalone: never replicated).
CREATE TABLE IF NOT EXISTS auth_login_attempts (
    id          TEXT        PRIMARY KEY,
    chain_node  TEXT        NOT NULL DEFAULT '',
    tenant_id   TEXT        NOT NULL,
    key_hash    TEXT        NOT NULL,
    succeeded   BOOLEAN     NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_key ON auth_login_attempts (key_hash, occurred_at DESC);
