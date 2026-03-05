-- Cursor-based pagination index for high-scale key listing
CREATE INDEX IF NOT EXISTS idx_keys_tenant_created_id
ON keys (tenant_id, created_at DESC, id DESC);
