-- 010: credentials (8.0.0-beta).
--
-- Connections become the platform's one store of external credentials:
-- cloud accounts, Azure Key Vault, SMTP and PKCS#11 HSMs join the
-- notification, ticketing, SIEM and scan-source types. A credential now
-- records when its secret fields last changed, an optional expiry and
-- rotation interval, and the result of its last real test.
--
-- notified holds the reminders already raised for the current secret (JSON
-- array of "expiring_30", "expiring_7", "expired", "rotation_due"), so the
-- sweep raises each once; replacing the secret clears it.
--
-- Schema only: the table is replicated (pkg/clustercatalog).
ALTER TABLE compliance_playbook_connections ADD COLUMN IF NOT EXISTS credentials_changed_at TIMESTAMPTZ;
ALTER TABLE compliance_playbook_connections ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE compliance_playbook_connections ADD COLUMN IF NOT EXISTS rotate_after_days INTEGER NOT NULL DEFAULT 0;
ALTER TABLE compliance_playbook_connections ADD COLUMN IF NOT EXISTS last_tested_at TIMESTAMPTZ;
ALTER TABLE compliance_playbook_connections ADD COLUMN IF NOT EXISTS last_test_ok BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE compliance_playbook_connections ADD COLUMN IF NOT EXISTS last_test_error TEXT NOT NULL DEFAULT '';
ALTER TABLE compliance_playbook_connections ADD COLUMN IF NOT EXISTS notified TEXT NOT NULL DEFAULT '[]';

UPDATE compliance_playbook_connections SET credentials_changed_at = updated_at WHERE credentials_changed_at IS NULL;

-- attributes holds the values of the fields a type marks public (an HSM's
-- slot, token label and topology, a cloud region), as a JSON object. They
-- are shown in lists and pickers; every other field value stays sealed.
ALTER TABLE compliance_playbook_connections ADD COLUMN IF NOT EXISTS attributes TEXT NOT NULL DEFAULT '{}';
