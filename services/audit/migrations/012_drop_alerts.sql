-- 012: remove audit's own alert store (2.16.0-beta).
--
-- Alerts live in reporting (/svc/reporting/alerts): it raises them from every
-- audit event, and the Alert Center, the header bell, incidents and playbooks
-- read them there. Audit wrote a second alert row for every event it
-- ingested; no screen has read that table since 2.12.0-beta, and its routes,
-- dedup/escalation settings and alert stream are removed with it.

DROP TABLE IF EXISTS alerts;
