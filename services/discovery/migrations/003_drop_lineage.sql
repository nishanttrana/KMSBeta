-- 003: remove the source-traceability (lineage) store.
--
-- Its only writer was the dashboard's manual "record event" form, so the
-- lineage graph, provenance and chain-of-custody views showed what users
-- typed, not what happened to a key. Its "tamper check" compared a hash with
-- itself and always passed (learning.md, 1.38.0-beta). A key's history now
-- comes from its audit events, verified by GET /audit/targets/{id}/integrity,
-- and its callers from keycore key_usage_events (Keys > History & usage).

DROP TABLE IF EXISTS lineage_events;
