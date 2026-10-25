-- The assessment schedule runs on the authority of the person who last
-- saved it, re-checked with auth before each run, and records its last
-- result (13.66.0-beta, assessment_schedule.go, docs/SCHEDULING.md). A
-- schedule saved before this has no one on record and pauses at its next
-- run until someone saves it again.
ALTER TABLE compliance_assessment_schedules ADD COLUMN IF NOT EXISTS authorized_by TEXT NOT NULL DEFAULT '';
ALTER TABLE compliance_assessment_schedules ADD COLUMN IF NOT EXISTS paused_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE compliance_assessment_schedules ADD COLUMN IF NOT EXISTS last_result TEXT NOT NULL DEFAULT '';
ALTER TABLE compliance_assessment_schedules ADD COLUMN IF NOT EXISTS last_error TEXT NOT NULL DEFAULT '';
ALTER TABLE compliance_assessment_schedules ADD COLUMN IF NOT EXISTS last_assessment_id TEXT NOT NULL DEFAULT '';
