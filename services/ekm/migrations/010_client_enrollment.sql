-- EKM database clients: enrolment and check-in history (11.6.0-beta).
--
-- A client (an ekm_agents row) is created by an administrator as "pending".
-- The agent on the database host presents a one-time registration token and
-- receives its own credential; only then is the client "registered". Only
-- the SHA-256 of the token and of the credential are stored.
--
-- Rows from earlier releases were created by the register call and are
-- "registered" from the time they were created. They hold no credential and
-- keep checking in with an auth-service token.
--
-- Schema only: both tables are replicated (pkg/clustercatalog). Check-ins
-- are written on the primary with the client row they update.
ALTER TABLE ekm_agents ADD COLUMN IF NOT EXISTS registration TEXT NOT NULL DEFAULT 'registered';
ALTER TABLE ekm_agents ADD COLUMN IF NOT EXISTS registered_at TIMESTAMP;
ALTER TABLE ekm_agents ADD COLUMN IF NOT EXISTS source_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE ekm_agents ADD COLUMN IF NOT EXISTS enroll_token_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE ekm_agents ADD COLUMN IF NOT EXISTS enroll_token_expires_at TIMESTAMP;
ALTER TABLE ekm_agents ADD COLUMN IF NOT EXISTS credential_hash TEXT NOT NULL DEFAULT '';

UPDATE ekm_agents SET registered_at = created_at WHERE registered_at IS NULL AND registration = 'registered';

-- One row per verified contact from a client. The newest 120 per client are
-- kept (pruned on insert).
CREATE TABLE IF NOT EXISTS ekm_agent_checkins (
    tenant_id   TEXT NOT NULL,
    id          TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    at          TIMESTAMP NOT NULL,
    source_ip   TEXT NOT NULL DEFAULT '',
    version     TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_ekm_agent_checkins_agent
    ON ekm_agent_checkins (tenant_id, agent_id, at DESC);
