-- The external HTTPS edge's certificate source (docs/SECURITY/INTERNAL_TLS.md,
-- "Edge certificate"). One row ('edge'), set by a root administrator:
--   runtime  - issued by vecta-runtime-root (the default);
--   ca       - issued by a software CA from the PKI tab and renewed by certs;
--   external - each node's own key and a certificate signed by an external
--              CA from that node's CSR (the key never leaves the node).
-- Replicated (certs component): every node's materializer applies it.
CREATE TABLE IF NOT EXISTS cert_edge_certificate (
    id            TEXT PRIMARY KEY,
    source        TEXT NOT NULL,
    ca_id         TEXT NOT NULL DEFAULT '',
    key_algorithm TEXT NOT NULL DEFAULT '',
    reason        TEXT NOT NULL DEFAULT '',
    updated_by    TEXT NOT NULL DEFAULT '',
    updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
