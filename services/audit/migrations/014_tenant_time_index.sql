-- 014: index events by tenant and time (7.16.0-beta).
--
-- The Audit Log's Activity charts aggregate a tenant's events over a window
-- of up to a year or since the first event (GET /audit/stats, stats.go), and
-- the event list reads a tenant newest first. Partitions prune by time; this
-- index finds one tenant's rows inside each partition. Declared on the
-- partitioned parent, so Postgres creates it on every partition, including
-- ones created later.

CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_events(tenant_id, timestamp DESC);
