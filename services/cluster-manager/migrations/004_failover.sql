-- Failover (docs/CLUSTERING.md, slice 4). Every table here is node-local.

-- epoch counts promotions; writable_until is a primary's lease when the
-- cluster has three or more voters; peer_secret authenticates node-to-node
-- calls (votes, status, announcements), given out by the primary.
ALTER TABLE cluster_local_state ADD COLUMN IF NOT EXISTS epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE cluster_local_state ADD COLUMN IF NOT EXISTS writable_until TIMESTAMP;
ALTER TABLE cluster_local_state ADD COLUMN IF NOT EXISTS peer_secret TEXT NOT NULL DEFAULT '';

-- The cluster as this node last heard it from its primary: who can vote,
-- where to reach them, and each member's forwarding-credential hash, so a
-- promoted node accepts the members' forwarded writes.
CREATE TABLE IF NOT EXISTS cluster_peers (
    node_id         TEXT PRIMARY KEY,
    url             TEXT NOT NULL DEFAULT '',
    fingerprint     TEXT NOT NULL DEFAULT '',
    credential_hash TEXT NOT NULL DEFAULT '',
    components_json TEXT NOT NULL DEFAULT '[]',
    is_primary      BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One vote per epoch, kept across restarts.
CREATE TABLE IF NOT EXISTS cluster_votes (
    epoch      BIGINT PRIMARY KEY,
    voted_for  TEXT NOT NULL,
    voted_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
