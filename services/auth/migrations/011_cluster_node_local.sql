-- Clustering (docs/CLUSTERING.md): identities that belong to one KMS node are
-- flagged node_local and excluded from replication by publication row filters:
-- the bootstrap admin and CLI accounts, and the internal service identities
-- (derived from each node's own INTERNAL_SERVICE_BOOTSTRAP_SECRET). Auth sets
-- the flag at every start, which also backfills existing deployments.
ALTER TABLE auth_users ADD COLUMN IF NOT EXISTS node_local BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE auth_client_registrations ADD COLUMN IF NOT EXISTS node_local BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE auth_api_keys ADD COLUMN IF NOT EXISTS node_local BOOLEAN NOT NULL DEFAULT FALSE;

-- A publication row filter on UPDATE/DELETE needs its column in the replica
-- identity.
ALTER TABLE auth_users REPLICA IDENTITY FULL;
ALTER TABLE auth_client_registrations REPLICA IDENTITY FULL;
ALTER TABLE auth_api_keys REPLICA IDENTITY FULL;
