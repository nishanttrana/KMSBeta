-- Write forwarding (docs/CLUSTERING.md, slice 3). Both tables are node-local.

-- This node's cluster role. A member (follower) records its primary here when
-- it joins; every service reads it (pkg/clusterstate) to decide whether to
-- forward lifecycle writes. The credential authenticates this member to the
-- primary's cluster-manager.
CREATE TABLE IF NOT EXISTS cluster_local_state (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    node_id             TEXT NOT NULL,
    role                TEXT NOT NULL,
    primary_node_id     TEXT NOT NULL DEFAULT '',
    primary_url         TEXT NOT NULL DEFAULT '',
    primary_fingerprint TEXT NOT NULL DEFAULT '',
    forward_credential  TEXT NOT NULL DEFAULT '',
    updated_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- On a primary: the forwarding credential of each member (SHA-256 only).
CREATE TABLE IF NOT EXISTS cluster_member_credentials (
    node_id         TEXT PRIMARY KEY,
    credential_hash TEXT NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at      TIMESTAMP
);
