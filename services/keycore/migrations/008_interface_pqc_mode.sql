BEGIN;

ALTER TABLE key_interface_ports
    ADD COLUMN IF NOT EXISTS pqc_mode TEXT NOT NULL DEFAULT 'inherit';

COMMIT;
