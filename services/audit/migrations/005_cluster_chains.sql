-- Migration 005: per-node audit chains for cluster replication
-- (docs/CLUSTERING.md, slice 3b).
--
-- In a cluster every node appends its own hash chain and the chains replicate
-- to every other node (shared-append). chain_node identifies the chain:
--   ''        this node's chain from before it was clustered (never replicated);
--   <node id> the chain of that cluster node (replicated, insert-only).
-- A node continues its own chain across the switch: its first clustered event
-- links to its last '' event.
--
-- hmac_key_id names the audit signing key that produced hmac_sig, so any node
-- can verify any chain once the cluster key has been transferred at join.

ALTER TABLE audit_events        ADD COLUMN IF NOT EXISTS chain_node  TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events        ADD COLUMN IF NOT EXISTS hmac_key_id TEXT;
ALTER TABLE audit_merkle_epochs ADD COLUMN IF NOT EXISTS chain_node  TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_merkle_leaves ADD COLUMN IF NOT EXISTS chain_node  TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_audit_chain_node ON audit_events (tenant_id, chain_node, sequence);

-- Epoch numbers are per chain.
ALTER TABLE audit_merkle_epochs DROP CONSTRAINT IF EXISTS audit_merkle_epochs_tenant_id_epoch_number_key;
CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_merkle_epoch_chain
    ON audit_merkle_epochs (tenant_id, chain_node, epoch_number);

-- Where the primary has relayed a member's events to its own consumers
-- (compliance triggers). Node-local.
CREATE TABLE IF NOT EXISTS audit_relay_cursor (
    tenant_id     TEXT   NOT NULL,
    chain_node    TEXT   NOT NULL,
    last_sequence BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, chain_node)
);
