-- Threshold trigger counts (2.6.0-beta).
--
-- A playbook with a threshold ("5 failed logins for one account within 5
-- minutes") counts matching events per group_by value. Counts were kept in
-- memory on the primary, so a restart or failover started them again from
-- zero. They are stored here instead: only the primary's trigger listener
-- writes them, and the table is replicated, so a new primary continues the
-- count. Rows older than the playbook's window are pruned as events arrive,
-- and a playbook's rows go when it is edited, deleted or fires.
--
-- Schema only: the table is replicated (pkg/clustercatalog).
CREATE TABLE IF NOT EXISTS compliance_playbook_threshold_hits (
    tenant_id   TEXT NOT NULL,
    playbook_id TEXT NOT NULL,
    group_key   TEXT NOT NULL,
    id          TEXT NOT NULL,
    at_ms       BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, playbook_id, group_key, id)
);
