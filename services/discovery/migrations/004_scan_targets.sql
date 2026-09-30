-- 004: TLS endpoints a tenant adds for the network scan.
--
-- Until 7.11.0-beta the network scan read only DISCOVERY_TLS_ENDPOINTS, an
-- operator environment variable, so a tenant could not name the host:port it
-- wanted inventoried. Each row is one host and port; the scan dials it
-- through a guard that refuses loopback, link-local (cloud metadata) and
-- other non-routable addresses (services/discovery/scanners.go).

CREATE TABLE IF NOT EXISTS discovery_scan_targets (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, host, port)
);
