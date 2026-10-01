-- 005: posture baseline (7.19.0-beta, docs/SECURITY/POSTURE_BASELINE.md).
--
-- posture_signal_daily holds one signal summary per tenant and complete UTC
-- day. A row is written only after the audit sync has read that day in full,
-- so a row's existence means the day is a valid baseline observation.
--
-- The audit sync follows a cursor (audit_cursor) forward from baseline_from
-- and records how far it has read everything (synced_through). Before this
-- it took the newest 500 events a minute and dropped the rest.
--
-- A risk snapshot is assessed only once the baseline has 14 days. Snapshots
-- taken before this migration had no baseline behind them and stay
-- assessed = FALSE.

CREATE TABLE IF NOT EXISTS posture_signal_daily (
    tenant_id TEXT NOT NULL,
    day TEXT NOT NULL,
    summary_json TEXT NOT NULL DEFAULT '{}',
    computed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, day)
);

ALTER TABLE posture_engine_state ADD COLUMN audit_cursor TIMESTAMP;
ALTER TABLE posture_engine_state ADD COLUMN baseline_from TIMESTAMP;
ALTER TABLE posture_engine_state ADD COLUMN synced_through TIMESTAMP;

ALTER TABLE posture_risk_snapshots ADD COLUMN assessed BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE posture_risk_snapshots ADD COLUMN baseline_days INTEGER NOT NULL DEFAULT 0;
