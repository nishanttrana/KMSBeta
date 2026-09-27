-- System Administration stored a TLS certificate, private key and CA bundle
-- and a license key in governance_system_state that nothing ever read or
-- applied (1.27.0-beta). A private key must not sit unused in a table, so
-- clear them; the columns stay for older binaries during a rolling upgrade.
UPDATE governance_system_state
SET tls_key_pem = NULL,
    tls_cert_pem = NULL,
    tls_ca_bundle_pem = NULL,
    license_key = NULL;
