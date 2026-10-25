-- Scheduled reports run on the authority of the person who saved them
-- (13.66.0-beta, schedule.go, docs/SCHEDULING.md), re-checked with auth
-- before each run, and record their last result. Schedules saved before
-- this have no one on record and pause at their next run until saved again.
ALTER TABLE reporting_scheduled_reports ADD COLUMN IF NOT EXISTS authorized_by TEXT NOT NULL DEFAULT '';
ALTER TABLE reporting_scheduled_reports ADD COLUMN IF NOT EXISTS paused_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE reporting_scheduled_reports ADD COLUMN IF NOT EXISTS last_result TEXT NOT NULL DEFAULT '';
ALTER TABLE reporting_scheduled_reports ADD COLUMN IF NOT EXISTS last_error TEXT NOT NULL DEFAULT '';
ALTER TABLE reporting_scheduled_reports ADD COLUMN IF NOT EXISTS last_job_id TEXT NOT NULL DEFAULT '';
