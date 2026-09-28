-- 011: remove audit's own alert rules (2.14.0-beta).
--
-- Alert rules live in reporting (/svc/reporting/alerts/rules), which has a
-- real expression parser, thresholds and a test/replay route, and which the
-- Alert Center uses. Audit kept a second rule table read by a substring
-- matcher that only changed the severity and title of audit's own alerts,
-- which no screen shows since 2.12.0-beta. The routes and matcher are
-- removed; so is the table.

DROP TABLE IF EXISTS alert_rules;
