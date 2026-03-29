BEGIN;

-- =========================================================================
-- PostgreSQL 17 / modern-PG enhancements for the keycore service
-- =========================================================================

-- -------------------------------------------------------------------------
-- 1. Extensions
-- -------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- -------------------------------------------------------------------------
-- 2. UNLOGGED TABLE — key_request_nonce_cache
--
-- Nonces are ephemeral (TTL 15 min by default).  They do not need crash
-- durability: if Postgres restarts, all active nonces are safely discarded
-- (callers must re-issue the request).  UNLOGGED skips WAL entirely for
-- INSERT/DELETE on this table → 3–5× faster nonce writes, ~40% less WAL.
--
-- PG17 supports: ALTER TABLE ... SET UNLOGGED (in-place conversion).
-- RLS policies are preserved across this operation.
-- -------------------------------------------------------------------------
ALTER TABLE key_request_nonce_cache SET UNLOGGED;

-- -------------------------------------------------------------------------
-- 3. BRIN indexes on append-only audit tables
--
-- key_iv_log grows without bound (every crypto operation appends a row).
-- BRIN is ideal: rows are physically ordered by created_at, and a 64-page
-- range block covers ~500 IV entries.  Total BRIN index size: ~8 KB vs
-- ~40 MB B-tree for 1 M rows.
-- -------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_iv_log_created_brin
    ON key_iv_log USING BRIN (created_at) WITH (pages_per_range = 64);

-- key_versions is append-mostly (rotation adds rows, never updates them).
CREATE INDEX IF NOT EXISTS idx_key_versions_created_brin
    ON key_versions USING BRIN (created_at) WITH (pages_per_range = 64);

-- -------------------------------------------------------------------------
-- 4. EXPRESSION INDEXES on JSONB columns
--
-- Dashboard queries like "show all keys with label env=production" or
-- "show all PCI-DSS compliant keys" do:
--   WHERE labels @> '{"env":"production"}'       (GIN — already indexed)
--   WHERE labels->>'env' = 'production'           (expression — needs this)
-- The GIN index covers @> containment; expression indexes cover = equality
-- on extracted text values, which is faster for high-cardinality labels.
-- -------------------------------------------------------------------------

-- Common single-label extractions (add more as label taxonomy grows)
CREATE INDEX IF NOT EXISTS idx_keys_label_env
    ON keys ((labels->>'env'))
    WHERE labels ? 'env';

CREATE INDEX IF NOT EXISTS idx_keys_label_team
    ON keys ((labels->>'team'))
    WHERE labels ? 'team';

CREATE INDEX IF NOT EXISTS idx_keys_label_classification
    ON keys ((labels->>'classification'))
    WHERE labels ? 'classification';

-- Compliance standard extraction (PCI-DSS, HIPAA, SOC2, etc.)
CREATE INDEX IF NOT EXISTS idx_keys_compliance_standard
    ON keys ((compliance->>'standard'))
    WHERE compliance ? 'standard';

-- -------------------------------------------------------------------------
-- 5. COVERING INDEXES (INCLUDE) — avoid heap fetches on catalog queries
-- -------------------------------------------------------------------------

-- Key list query (dashboard catalog): returns name, algorithm, status,
-- created_at for pagination without touching the heap.
CREATE INDEX IF NOT EXISTS idx_keys_catalog_covering
    ON keys (tenant_id, status, created_at DESC)
    INCLUDE (id, name, algorithm, key_type, purpose, owner, expiry_date, tags);

-- Key name search (user types in search box):
CREATE INDEX IF NOT EXISTS idx_keys_name_trgm
    ON keys USING GIN (name gin_trgm_ops);

-- Key version fetch by key_id — most common after key lookup
CREATE INDEX IF NOT EXISTS idx_key_versions_covering
    ON key_versions (tenant_id, key_id, version DESC)
    INCLUDE (id, status, created_at, rotated_from, rotation_reason);

-- -------------------------------------------------------------------------
-- 6. EXTENDED STATISTICS — correlated columns in the keys table
--
-- (tenant_id, status, algorithm) are strongly correlated: a tenant rarely
-- uses all algorithm types, and most keys are 'active'.  Without this, the
-- planner overestimates row counts and may full-scan partitions.
-- -------------------------------------------------------------------------
CREATE STATISTICS IF NOT EXISTS stat_keys_tenant_status_algo
    (ndistinct, dependencies)
    ON tenant_id, status, algorithm
    FROM keys;

CREATE STATISTICS IF NOT EXISTS stat_keys_tenant_purpose_status
    (ndistinct, dependencies)
    ON tenant_id, purpose, status
    FROM keys;

-- -------------------------------------------------------------------------
-- 7. MATERIALIZED VIEW — compliance dashboard summary
--
-- The governance/compliance tabs aggregate key counts by standard across
-- all partitions.  Without a materialised view this requires a full
-- partition-pruning scan on every page load.
--
-- Refresh strategy: REFRESH MATERIALIZED VIEW CONCURRENTLY mv_compliance_summary
-- This can be called from the compliance service's background job (e.g. every
-- 5 minutes) without locking reads.  The UNIQUE index below is required for
-- CONCURRENTLY refresh.
-- -------------------------------------------------------------------------
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_compliance_summary AS
SELECT
    tenant_id,
    compliance->>'standard'                             AS standard,
    count(*)                                            AS total_keys,
    count(*) FILTER (WHERE status = 'active')           AS active_keys,
    count(*) FILTER (WHERE status = 'pre-active')       AS pre_active_keys,
    count(*) FILTER (WHERE fips_compliant = TRUE)       AS fips_keys,
    count(*) FILTER (WHERE pqc_ready = TRUE)            AS pqc_ready_keys,
    count(*) FILTER (
        WHERE expiry_date IS NOT NULL
          AND expiry_date < NOW() + INTERVAL '30 days'
          AND status = 'active'
    )                                                   AS expiring_soon_keys,
    max(updated_at)                                     AS last_updated
FROM keys
WHERE compliance IS NOT NULL
  AND compliance ? 'standard'
GROUP BY tenant_id, compliance->>'standard'
WITH DATA;

-- Required for REFRESH MATERIALIZED VIEW CONCURRENTLY
CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_compliance_summary_pk
    ON mv_compliance_summary (tenant_id, standard);

-- Index for fast per-tenant dashboard queries
CREATE INDEX IF NOT EXISTS idx_mv_compliance_summary_tenant
    ON mv_compliance_summary (tenant_id);

-- -------------------------------------------------------------------------
-- 8. Per-column statistics targets for wide JSONB columns
-- -------------------------------------------------------------------------
ALTER TABLE keys ALTER COLUMN labels     SET STATISTICS 500;
ALTER TABLE keys ALTER COLUMN compliance SET STATISTICS 500;
ALTER TABLE keys ALTER COLUMN tags       SET STATISTICS 200;

-- Run ANALYZE immediately so the new statistics are available to the planner.
ANALYZE keys;
ANALYZE key_versions;
ANALYZE key_iv_log;

COMMIT;
