-- 009: incremental, resumable bucket scans (7.38.0-beta).
--
-- A bucket larger than one run's budget is read over several scans. The
-- bucket row records where the pass in progress continues (scan_cursor),
-- and when the last complete pass started and ended. An asset found in a
-- bucket is called missing only when a complete pass did not find it.
--
-- discovery_bucket_objects: one row per object the scan read, with its ETag
-- when read and the assets found in it. An object listed again with the
-- same ETag is not downloaded again; its assets are marked seen. No object
-- content is stored.

ALTER TABLE discovery_buckets ADD COLUMN IF NOT EXISTS scan_cursor TEXT NOT NULL DEFAULT '';
ALTER TABLE discovery_buckets ADD COLUMN IF NOT EXISTS pass_started_at TIMESTAMP;
ALTER TABLE discovery_buckets ADD COLUMN IF NOT EXISTS pass_objects INTEGER NOT NULL DEFAULT 0;
ALTER TABLE discovery_buckets ADD COLUMN IF NOT EXISTS last_pass_started_at TIMESTAMP;
ALTER TABLE discovery_buckets ADD COLUMN IF NOT EXISTS last_pass_at TIMESTAMP;
ALTER TABLE discovery_buckets ADD COLUMN IF NOT EXISTS last_pass_objects INTEGER NOT NULL DEFAULT 0;
ALTER TABLE discovery_buckets ADD COLUMN IF NOT EXISTS scanned_at TIMESTAMP;

CREATE TABLE IF NOT EXISTS discovery_bucket_objects (
    tenant_id TEXT NOT NULL,
    bucket_id TEXT NOT NULL,
    object_key TEXT NOT NULL,
    etag TEXT NOT NULL DEFAULT '',
    size_bytes BIGINT NOT NULL DEFAULT 0,
    asset_ids TEXT NOT NULL DEFAULT '',
    rules INTEGER NOT NULL DEFAULT 0,
    seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, bucket_id, object_key)
);
