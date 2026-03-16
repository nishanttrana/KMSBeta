BEGIN;

ALTER TABLE key_interface_ports
    ADD COLUMN IF NOT EXISTS protocol TEXT NOT NULL DEFAULT '';

ALTER TABLE key_interface_ports
    ADD COLUMN IF NOT EXISTS certificate_source TEXT NOT NULL DEFAULT '';

ALTER TABLE key_interface_ports
    ADD COLUMN IF NOT EXISTS ca_id TEXT;

ALTER TABLE key_interface_ports
    ADD COLUMN IF NOT EXISTS certificate_id TEXT;

COMMIT;
