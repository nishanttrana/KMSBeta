-- Restart-safe audit markers for FIPS mode rollouts: governance emits one audit
-- event per service instance start in a mode, and one when a rollout
-- converges, and records that it did so here.
ALTER TABLE platform_fips_observed ADD COLUMN IF NOT EXISTS audited_started_at TIMESTAMP;
ALTER TABLE platform_fips_mode ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP;
