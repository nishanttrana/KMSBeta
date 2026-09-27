-- Values processed by metered operations. A batch call (tokenize,
-- detokenize) is one operation carrying its value count in details.count;
-- every other operation processes one value.
ALTER TABLE ops_metrics_hourly ADD COLUMN IF NOT EXISTS value_count BIGINT NOT NULL DEFAULT 0;
