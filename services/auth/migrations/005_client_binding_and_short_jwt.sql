BEGIN;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS interface_name TEXT;

ALTER TABLE auth_client_registrations
  ADD COLUMN IF NOT EXISTS subject_id TEXT;

UPDATE auth_client_registrations
SET interface_name = 'rest'
WHERE interface_name IS NULL OR btrim(interface_name) = '';

UPDATE auth_client_registrations
SET subject_id = client_name
WHERE subject_id IS NULL OR btrim(subject_id) = '';

ALTER TABLE auth_client_registrations
  ALTER COLUMN interface_name SET DEFAULT 'rest';

ALTER TABLE auth_client_registrations
  ALTER COLUMN subject_id SET DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_auth_clients_tenant_interface_subject
  ON auth_client_registrations (tenant_id, interface_name, subject_id);

CREATE INDEX IF NOT EXISTS idx_auth_api_keys_tenant_hash
  ON auth_api_keys (tenant_id, key_hash);

COMMIT;

