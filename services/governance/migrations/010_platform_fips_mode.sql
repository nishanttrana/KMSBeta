-- Platform FIPS 140-3 runtime mode (docs/SECURITY/FIPS.md, "Changing the mode").
-- Set by a root administrator in the KMS UI; every service reads it at startup
-- (pkg/config.RequireFIPSRuntime) and restarts itself when it changes.
CREATE TABLE IF NOT EXISTS platform_fips_mode (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    mode         TEXT NOT NULL,
    previous     TEXT NOT NULL DEFAULT '',
    reason       TEXT NOT NULL DEFAULT '',
    requested_by TEXT NOT NULL,
    requested_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- The mode each service instance actually runs, reported at startup, so the UI
-- shows rollout progress from the real runtime rather than the request.
CREATE TABLE IF NOT EXISTS platform_fips_observed (
    service        TEXT NOT NULL,
    instance       TEXT NOT NULL,
    mode           TEXT NOT NULL,
    module_version TEXT NOT NULL DEFAULT '',
    validated      BOOLEAN NOT NULL DEFAULT FALSE,
    started_at     TIMESTAMP NOT NULL,
    updated_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (service, instance)
);
