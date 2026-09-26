-- 023: remove the DR drill feature.
--
-- A "drill" ran nothing: every step was marked passed ("step completed
-- successfully in simulated drill") with 10/10 keys restored, RPO 0 and a
-- made-up RTO, and nothing executed the schedules. Dropping the tables also
-- purges those fabricated runs. Real recovery evidence comes from verifying
-- a governance backup (POST /governance/backups/verify).

DROP TABLE IF EXISTS dr_drill_runs;
DROP TABLE IF EXISTS dr_drill_schedules;
