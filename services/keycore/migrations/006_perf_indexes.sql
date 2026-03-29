BEGIN;

-- -------------------------------------------------------------------------
-- keys — additional lookup indexes
-- The existing indexes cover single-column filters well.
-- These cover the composite patterns that appear in catalog queries.
-- -------------------------------------------------------------------------

-- Dashboard "active keys near expiry" panel (status + expiry range scan)
-- Replaces the existing idx_keys_expiry which only filters active keys but
-- doesn't include status in the index prefix for the ORDER BY.
CREATE INDEX IF NOT EXISTS idx_keys_status_expiry
    ON keys (tenant_id, status, expiry_date)
    WHERE expiry_date IS NOT NULL;

-- Ops counter queries — keys exceeding their ops_limit
CREATE INDEX IF NOT EXISTS idx_keys_ops_limit
    ON keys (tenant_id, ops_total, ops_limit)
    WHERE ops_limit > 0;

-- HSM-backed key lookup (filters keys on specific HSM slots)
CREATE INDEX IF NOT EXISTS idx_keys_hsm_label
    ON keys (tenant_id, hsm_key_label)
    WHERE hsm_key_label IS NOT NULL;

-- Recently created keys (dashboard "new keys" widget, audit feed)
-- The cursor-pagination index (005) covers DESC order; this covers ASC.
CREATE INDEX IF NOT EXISTS idx_keys_created_asc
    ON keys (tenant_id, created_at ASC, id ASC);

-- -------------------------------------------------------------------------
-- key_versions — additional lookup
-- -------------------------------------------------------------------------

-- Fetch the current version of a key (most common: version = current_version)
CREATE INDEX IF NOT EXISTS idx_key_versions_status
    ON key_versions (tenant_id, key_id, status);

-- Rotation history — list all versions for a key ordered by version number
CREATE INDEX IF NOT EXISTS idx_key_versions_ordered
    ON key_versions (tenant_id, key_id, version DESC);

-- -------------------------------------------------------------------------
-- key_iv_log — IV uniqueness enforcement lookup
-- Already has idx_iv_log_key; add a covering index for the duplicate-IV
-- detection query (tenant_id, key_id, key_version, iv).
-- -------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_iv_log_dedup
    ON key_iv_log (tenant_id, key_id, key_version, iv);

COMMIT;
