-- Operations metrics are built from the audit.key.<op> events keycore emits
-- for every key operation (success, refusal, failure), never from a caller
-- posting numbers. Crypto operations are mostly sub-millisecond, so latency
-- is summed in microseconds, and each sample is counted in a fixed latency
-- bucket so percentiles are measured bucket bounds, not guesses from the
-- average. Bucket upper bounds (ms): 0.1 0.25 0.5 1 2.5 5 10 25 50 100 250
-- 1000, then lat_b12 for anything slower. Node-local (see
-- pkg/clustercatalog). The old total_latency_ms column is no longer read.

ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS total_latency_us BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS lat_b00 BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS lat_b01 BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS lat_b02 BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS lat_b03 BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS lat_b04 BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS lat_b05 BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS lat_b06 BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS lat_b07 BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS lat_b08 BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS lat_b09 BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS lat_b10 BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS lat_b11 BIGINT NOT NULL DEFAULT 0;
ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS lat_b12 BIGINT NOT NULL DEFAULT 0;
