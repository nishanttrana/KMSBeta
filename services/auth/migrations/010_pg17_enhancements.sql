BEGIN;

-- =========================================================================
-- PostgreSQL 17 / modern-PG enhancements for the auth service
-- =========================================================================

-- -------------------------------------------------------------------------
-- 1. Extensions
-- pg_stat_statements: every query's execution count, total/mean time.
--    SELECT * FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 20;
-- pgcrypto: server-side digest functions (used for verification checks).
-- pg_trgm: trigram similarity — fuzzy username / email search.
-- -------------------------------------------------------------------------
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- -------------------------------------------------------------------------
-- 2. GENERATED COLUMN — case-insensitive username lookup
--
-- Currently, login requires an exact-case match on username.  A stored
-- generated column + unique index lets the application do:
--   WHERE tenant_id = $1 AND username_lower = lower($2)
-- without a function-based index (which can't use UNIQUE) and without
-- changing the stored username casing.
-- PG12+ feature; PG17 materialises it more efficiently with SIMD lower().
-- -------------------------------------------------------------------------
ALTER TABLE auth_users
    ADD COLUMN IF NOT EXISTS username_lower TEXT
        GENERATED ALWAYS AS (lower(username)) STORED;

-- Unique index enforces case-insensitive uniqueness per tenant.
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_users_username_lower
    ON auth_users (tenant_id, username_lower);

-- Trigram index for partial/fuzzy username search (admin user lookup).
CREATE INDEX IF NOT EXISTS idx_auth_users_username_trgm
    ON auth_users USING GIN (username_lower gin_trgm_ops);

-- -------------------------------------------------------------------------
-- 3. COVERING INDEXES (INCLUDE) — avoid heap fetches on the hottest paths
--
-- When all columns needed by a query are in the index leaf, Postgres never
-- touches the table heap.  On NVMe this saves ~1–3 ms per login; on network
-- storage (EBS, GCS PD) it saves 10–30 ms.
-- -------------------------------------------------------------------------

-- Login path: fetch user by tenant + username — include every column the
-- auth handler reads immediately after the lookup.
CREATE INDEX IF NOT EXISTS idx_auth_users_login_covering
    ON auth_users (tenant_id, username_lower)
    INCLUDE (id, pwd_hash, role, status, must_change_password, totp_secret);

-- Token validation: resolve session by hash — include user_id and expiry
-- so the handler can validate in one index scan.
CREATE INDEX IF NOT EXISTS idx_auth_sessions_token_covering
    ON auth_sessions (token_hash)
    INCLUDE (tenant_id, user_id, expires_at);

-- API-key validation: resolve by hash — include everything needed to gate
-- the request without touching the heap.
CREATE INDEX IF NOT EXISTS idx_auth_api_keys_covering
    ON auth_api_keys (key_hash)
    INCLUDE (tenant_id, user_id, client_id, permissions, expires_at);

-- -------------------------------------------------------------------------
-- 4. BRIN (Block Range INdex) on append-only timestamp columns
--
-- auth_sessions and auth_api_keys are append-only (rows are only ever
-- INSERTed, never UPDATEd in place).  BRIN tracks min/max created_at per
-- 128-page block.  A time-range query for audit reports scans only relevant
-- blocks — the BRIN index is ~300 × smaller than an equivalent B-tree.
-- -------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_auth_sessions_created_brin
    ON auth_sessions USING BRIN (created_at) WITH (pages_per_range = 64);

CREATE INDEX IF NOT EXISTS idx_auth_api_keys_created_brin
    ON auth_api_keys USING BRIN (created_at) WITH (pages_per_range = 64);

-- -------------------------------------------------------------------------
-- 5. EXTENDED STATISTICS — multi-column correlation
--
-- The query planner assumes column values are independent by default.
-- auth_users has a strong correlation between (tenant_id, role, status):
-- most tenants have few super-admins and many regular users.  Without
-- extended stats the planner overestimates result size and may choose a
-- seq scan instead of an index scan.
-- -------------------------------------------------------------------------
CREATE STATISTICS IF NOT EXISTS stat_auth_users_tenant_role_status
    (ndistinct, dependencies)
    ON tenant_id, role, status
    FROM auth_users;

CREATE STATISTICS IF NOT EXISTS stat_auth_sessions_tenant_user
    (ndistinct, dependencies)
    ON tenant_id, user_id, expires_at
    FROM auth_sessions;

-- Force immediate statistics collection (runs at commit time).
-- Subsequent ANALYZE will keep them updated automatically.
ANALYZE auth_users;
ANALYZE auth_sessions;
ANALYZE auth_api_keys;

-- -------------------------------------------------------------------------
-- 6. Per-column statistics targets for JSONB columns
--
-- The planner uses 200 histogram buckets for scalar types but only collects
-- shallow statistics on JSONB by default.  Raising the per-column target
-- gives the planner better cardinality estimates for GIN index decisions.
-- -------------------------------------------------------------------------
ALTER TABLE auth_api_keys      ALTER COLUMN permissions     SET STATISTICS 500;
ALTER TABLE auth_tenant_roles  ALTER COLUMN permissions     SET STATISTICS 500;

COMMIT;
