-- Playbooks run on the authority of the person who saved them (2.4.0-beta).
--
-- authorized_by is the verified caller who last saved the playbook while
-- holding every permission its actions need. Automatic runs are refused while
-- it is empty, so every playbook saved before this release stays inert until
-- someone with those permissions saves it again: they were accepted from any
-- authenticated caller, for any tenant named in the request body.
--
-- category was accepted and shown by the dashboard but never stored.
-- actor records on whose authority each run acted.
--
-- Schema only: the tables are replicated (pkg/clustercatalog), and a data
-- rewrite here would also run on cluster members. Legacy action names are
-- mapped when rows are read (legacyActionNames).
ALTER TABLE compliance_playbooks ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT 'incident_response';
ALTER TABLE compliance_playbooks ADD COLUMN IF NOT EXISTS authorized_by TEXT NOT NULL DEFAULT '';
ALTER TABLE compliance_playbook_runs ADD COLUMN IF NOT EXISTS actor TEXT NOT NULL DEFAULT '';
