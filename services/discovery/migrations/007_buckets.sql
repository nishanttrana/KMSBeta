-- 007: object storage buckets (7.34.0-beta).
--
-- discovery_buckets: buckets a tenant adds for the "storage" scan source.
-- provider is "s3" (S3 or a service that speaks its API) or "azure" (a Blob
-- container). The scan lists the objects under the prefix over HTTPS and
-- reads each source, config, key or certificate file in memory. A private
-- bucket names a sealed compliance connection (type s3 or azure_blob) that
-- holds its credential; no credential is stored here, and an endpoint
-- carrying one is refused.

CREATE TABLE IF NOT EXISTS discovery_buckets (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    provider TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    bucket TEXT NOT NULL,
    prefix TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL DEFAULT '',
    connection_id TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, endpoint, bucket, prefix)
);
