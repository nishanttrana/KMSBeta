-- 006: git repositories and scan schedules (7.20.0-beta).
--
-- discovery_repositories: repositories a tenant adds for the "git" scan
-- source. The scan downloads a snapshot of the ref over HTTPS and reads it
-- in memory. A private repository names a sealed compliance connection
-- (type git) that holds its access token; no credential is stored here, and
-- a URL carrying one is refused.
--
-- discovery_schedules: one schedule per tenant. authorized_by is the user
-- who saved it; their discovery.write is re-checked with auth before every
-- unattended run (docs/PLATFORM_CONTRACT.md). paused_reason is set when
-- that check says the authority is gone.

CREATE TABLE IF NOT EXISTS discovery_repositories (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    url TEXT NOT NULL,
    ref TEXT NOT NULL DEFAULT '',
    provider TEXT NOT NULL,
    connection_id TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, url, ref)
);

CREATE TABLE IF NOT EXISTS discovery_schedules (
    tenant_id TEXT PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    interval_hours INTEGER NOT NULL DEFAULT 24,
    sources TEXT NOT NULL DEFAULT '',
    authorized_by TEXT NOT NULL DEFAULT '',
    next_run_at TIMESTAMP,
    last_run_at TIMESTAMP,
    last_scan_id TEXT NOT NULL DEFAULT '',
    paused_reason TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
