-- 015: where signed checkpoints are timestamped (13.47.0-beta).
--
-- One platform-wide row: whether each signed checkpoint is sent to an
-- RFC 3161 time-stamp authority, and which credential (a "tsa" connection
-- in Playbooks → Credentials, root tenant) names it. The tokens themselves
-- are audit events (audit.audit.checkpoint_timestamped) in the chain they
-- anchor. Replicated (pkg/clustercatalog, audit); written by the primary.
CREATE TABLE IF NOT EXISTS audit_anchor_settings (
    id             SMALLINT PRIMARY KEY CHECK (id = 1),
    enabled        BOOLEAN NOT NULL DEFAULT FALSE,
    connection_id  TEXT NOT NULL DEFAULT '',
    updated_by     TEXT NOT NULL DEFAULT '',
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
