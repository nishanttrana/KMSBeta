-- Per-service internal mTLS policy (docs/SECURITY/INTERNAL_TLS.md, slice 3).
-- Set by a root administrator on the Service mTLS page; the certs service
-- publishes it to the trust volume (mtls-policy.json) and each service applies
-- it by restarting. generation increases on every change or rotation.
-- Replicated (certs component): every node applies the same policy.
CREATE TABLE IF NOT EXISTS cert_internal_mtls_policy (
    identity           TEXT PRIMARY KEY,
    key_algorithm      TEXT NOT NULL,
    kx_profile         TEXT NOT NULL,
    generation         BIGINT NOT NULL DEFAULT 0,
    restart_mode       TEXT NOT NULL DEFAULT 'graceful',
    apply_after        TIMESTAMP,
    reason             TEXT NOT NULL DEFAULT '',
    updated_by         TEXT NOT NULL DEFAULT '',
    updated_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    audited_generation BIGINT NOT NULL DEFAULT 0
);

-- What each running instance actually uses, reported by the instance itself
-- (pkg/config.reportMTLS) or, for the certificate files certs writes for
-- Envoy, the dashboard and the infrastructure daemons, by certs. Node-local.
CREATE TABLE IF NOT EXISTS platform_mtls_observed (
    identity             TEXT NOT NULL,
    instance             TEXT NOT NULL,
    serial               TEXT NOT NULL DEFAULT '',
    not_after            TIMESTAMP,
    key_algorithm        TEXT NOT NULL DEFAULT '',
    kx_profile           TEXT NOT NULL DEFAULT '',
    server_groups        TEXT NOT NULL DEFAULT '[]',
    generation           BIGINT NOT NULL DEFAULT 0,
    last_handshake_group TEXT NOT NULL DEFAULT '',
    last_handshake_at    TIMESTAMP,
    started_at           TIMESTAMP,
    updated_at           TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (identity, instance)
);
