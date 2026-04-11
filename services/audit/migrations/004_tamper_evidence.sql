BEGIN;

-- ── Migration 004: Enhanced Tamper-Evidence & Category Groups ─────────────────
--
-- Adds:
--   1. hmac_sig       – HMAC-SHA256(chain_hash, service_signing_key) per event
--                       for event authenticity (not just integrity).
--   2. category_group – FIPS 140-3 aligned functional category
--                       (authentication, key_management, cryptographic_operations,
--                        data_protection, certificate_management,
--                        policy_and_governance, system_administration,
--                        network_and_access, financial, supply_chain,
--                        quantum, cloud_integration)
--   3. previous_epoch_root / epoch_hash – cross-epoch Merkle linkage so every
--        epoch cryptographically anchors the prior epoch's root.
--
-- All new columns are nullable so existing rows are not affected (new inserts
-- will always populate them; backfill is optional via ops tooling).
-- ─────────────────────────────────────────────────────────────────────────────

-- 1. Event HMAC signature (per-event authenticity)
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS hmac_sig      TEXT;
ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS category_group TEXT;

-- Index for category-group queries (compliance dashboards, FIPS reports)
CREATE INDEX IF NOT EXISTS idx_audit_category_group
    ON audit_events(tenant_id, category_group, timestamp DESC);

-- 2. Cross-epoch Merkle linking
ALTER TABLE audit_merkle_epochs ADD COLUMN IF NOT EXISTS previous_epoch_root TEXT;
ALTER TABLE audit_merkle_epochs ADD COLUMN IF NOT EXISTS epoch_hash          TEXT;
-- epoch_hash = SHA256(previous_epoch_root || tree_root)
-- Allows a linear proof chain: epoch 0 → epoch 1 → epoch N

CREATE INDEX IF NOT EXISTS idx_merkle_epochs_chain
    ON audit_merkle_epochs(tenant_id, epoch_number);

-- 3. Extend monthly partitions forward (2026-04 through 2028-12)
-- Create only if they don't already exist (idempotent via IF NOT EXISTS)
DO $$
DECLARE
    y  INT;
    m  INT;
    ds TEXT;
    de TEXT;
    tn TEXT;
BEGIN
    FOR y IN 2026..2028 LOOP
        FOR m IN 1..12 LOOP
            -- Skip months that already have a partition
            tn := format('audit_events_%s_%s', y, lpad(m::text,2,'0'));
            IF NOT EXISTS (
                SELECT 1 FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relname = tn AND n.nspname = 'public'
            ) THEN
                ds := format('%s-%s-01', y, lpad(m::text,2,'0'));
                IF m = 12 THEN
                    de := format('%s-01-01', y+1);
                ELSE
                    de := format('%s-%s-01', y, lpad((m+1)::text,2,'0'));
                END IF;
                EXECUTE format(
                    'CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_events
                     FOR VALUES FROM (%L) TO (%L)',
                    tn, ds, de
                );
            END IF;
        END LOOP;
    END LOOP;
END$$;

COMMIT;
