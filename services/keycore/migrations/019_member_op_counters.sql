-- Clustering (docs/CLUSTERING.md, slice 3): on a cluster member, per-key
-- operation counters go here instead of the replicated keys row, so crypto
-- operations never write replicated data. Node-local.
CREATE TABLE IF NOT EXISTS key_op_counters (
    tenant_id      TEXT NOT NULL,
    key_id         TEXT NOT NULL,
    ops_total      BIGINT NOT NULL DEFAULT 0,
    ops_encrypt    BIGINT NOT NULL DEFAULT 0,
    ops_decrypt    BIGINT NOT NULL DEFAULT 0,
    ops_sign       BIGINT NOT NULL DEFAULT 0,
    ops_last_reset TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, key_id)
);
