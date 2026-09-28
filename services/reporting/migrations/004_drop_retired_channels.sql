-- 004: delete retired notification channels (2.11.0-beta).
--
-- Reporting delivers alerts only to the dashboard ("screen"). Rows for
-- PagerDuty, email, Slack, Teams, webhook and SIEM channels came from
-- releases that marked alerts "sent" to them without sending anything. They
-- were already hidden and never used; their config may hold a PagerDuty
-- routing key or a webhook URL in plaintext, so they are removed. There is
-- no PagerDuty integration (owner, 2026-09-28). Outbound notification goes
-- through compliance connections (docs/SECURITY/CONNECTIONS.md).

DELETE FROM reporting_notification_channels WHERE LOWER(TRIM(name)) <> 'screen';
