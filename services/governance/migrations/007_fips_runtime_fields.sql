ALTER TABLE governance_system_state
    ADD COLUMN IF NOT EXISTS fips_mode_policy TEXT NOT NULL DEFAULT 'strict',
    ADD COLUMN IF NOT EXISTS fips_crypto_library TEXT NOT NULL DEFAULT 'go-boringcrypto',
    ADD COLUMN IF NOT EXISTS fips_library_validated BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS fips_tls_profile TEXT NOT NULL DEFAULT 'tls12_fips_suites',
    ADD COLUMN IF NOT EXISTS fips_rng_mode TEXT NOT NULL DEFAULT 'ctr_drbg';
