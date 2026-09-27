-- Attested key release (1.30.0-beta): the recipient key the evidence bound
-- and whether keycore released the key sealed to it.
ALTER TABLE confidential_release_history ADD COLUMN IF NOT EXISTS recipient_key_binding TEXT NOT NULL DEFAULT '';
ALTER TABLE confidential_release_history ADD COLUMN IF NOT EXISTS released BOOLEAN NOT NULL DEFAULT FALSE;
