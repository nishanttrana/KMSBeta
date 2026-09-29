-- Algorithm-swap drills: each row is one real rehearsal run in memory on a
-- keycore node (key generation and round trips through the key engine),
-- with the measured medians and sizes. Throwaway keys are never stored.
CREATE TABLE IF NOT EXISTS agility_drills (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    from_algorithm TEXT NOT NULL,
    to_algorithm TEXT NOT NULL,
    iterations INT NOT NULL,
    result TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    measurements TEXT NOT NULL DEFAULT '{}',
    run_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX IF NOT EXISTS idx_agility_drills_tenant_created ON agility_drills (tenant_id, created_at DESC);
