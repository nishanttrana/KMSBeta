BEGIN;

-- -------------------------------------------------------------------------
-- auth_sessions — lookup indexes
-- The most frequent DB operation in auth is token validation:
--   SELECT * FROM auth_sessions WHERE token_hash = $1
-- Without an index this is a full table scan on every API request.
-- -------------------------------------------------------------------------

-- Token validation: point-lookup by hash (covers logout, refresh, validation)
CREATE INDEX IF NOT EXISTS idx_auth_sessions_token_hash
    ON auth_sessions (token_hash);

-- List sessions by user (used in revoke-all and admin UI)
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user
    ON auth_sessions (tenant_id, user_id);

-- Expired-session cleanup job — plain index; the query's WHERE clause
-- handles the expiry filter.  Partial predicates cannot use NOW() since
-- it is STABLE not IMMUTABLE.
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires
    ON auth_sessions (expires_at);

-- -------------------------------------------------------------------------
-- auth_api_keys — lookup indexes
-- API key validation: SELECT * FROM auth_api_keys WHERE key_hash = $1
-- -------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_auth_api_keys_hash
    ON auth_api_keys (key_hash);

-- List API keys by user (admin UI, key management tab)
CREATE INDEX IF NOT EXISTS idx_auth_api_keys_user
    ON auth_api_keys (tenant_id, user_id);

-- Expired API key cleanup
CREATE INDEX IF NOT EXISTS idx_auth_api_keys_expires
    ON auth_api_keys (expires_at)
    WHERE expires_at IS NOT NULL;

-- -------------------------------------------------------------------------
-- auth_users — role and status filtering
-- -------------------------------------------------------------------------

-- List users by role (admin queries like "who has super-admin?")
CREATE INDEX IF NOT EXISTS idx_auth_users_role
    ON auth_users (tenant_id, role);

-- List active users only (the 99 % query — status = 'active')
CREATE INDEX IF NOT EXISTS idx_auth_users_status
    ON auth_users (tenant_id, status);

-- -------------------------------------------------------------------------
-- auth_client_registrations — status filtering
-- -------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_auth_clients_status
    ON auth_client_registrations (tenant_id, status);

-- -------------------------------------------------------------------------
-- auth_tenants — status (filter inactive tenants on every auth path)
-- -------------------------------------------------------------------------

CREATE INDEX IF NOT EXISTS idx_auth_tenants_status
    ON auth_tenants (status);

COMMIT;
