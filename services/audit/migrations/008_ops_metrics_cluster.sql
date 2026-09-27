-- Operations metrics per node and cluster-wide. Each row now names the node
-- whose service ran the operations (the event's chain_node; '' before the
-- node joined a cluster). A member counts its own operations; the primary
-- also counts every member's, from the events replication brings in, in the
-- same transaction as its relay cursor, so each is counted once. The table
-- stays node-local (pkg/clustercatalog).

ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS node TEXT NOT NULL DEFAULT '';
ALTER TABLE ops_metrics_hourly DROP CONSTRAINT IF EXISTS ops_metrics_hourly_pkey;
CREATE UNIQUE INDEX IF NOT EXISTS uq_ops_metrics_hourly_node
    ON ops_metrics_hourly (tenant_id, hour, node, service, op_type);
