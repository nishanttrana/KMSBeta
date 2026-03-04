-- Merkle tree epoch tables for O(log N) audit event inclusion proofs

CREATE TABLE IF NOT EXISTS audit_merkle_epochs (
    id          TEXT        NOT NULL,
    tenant_id   TEXT        NOT NULL,
    epoch_number INTEGER    NOT NULL,
    seq_from    BIGINT      NOT NULL,
    seq_to      BIGINT      NOT NULL,
    leaf_count  INTEGER     NOT NULL,
    tree_root   TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, epoch_number)
);

CREATE INDEX IF NOT EXISTS idx_merkle_epochs_tenant_epoch
    ON audit_merkle_epochs (tenant_id, epoch_number DESC);

CREATE TABLE IF NOT EXISTS audit_merkle_leaves (
    epoch_id    TEXT        NOT NULL,
    tenant_id   TEXT        NOT NULL,
    leaf_index  INTEGER     NOT NULL,
    event_id    TEXT        NOT NULL,
    sequence    BIGINT      NOT NULL,
    leaf_hash   TEXT        NOT NULL,
    PRIMARY KEY (tenant_id, epoch_id, leaf_index)
);

CREATE INDEX IF NOT EXISTS idx_merkle_leaves_event
    ON audit_merkle_leaves (tenant_id, event_id);
