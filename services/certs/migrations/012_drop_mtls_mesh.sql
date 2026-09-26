-- 012: remove the "mTLS Mesh" feature.
--
-- It never gave a service a certificate: "renew" generated a self-signed
-- cert and key, discarded both and stored metadata; the topology marked
-- every edge mTLS-verified from a hardcoded list while services talked plain
-- HTTP. Real internal mTLS is issued by the internal services Sub CA
-- (docs/SECURITY/INTERNAL_TLS.md).

DROP TABLE IF EXISTS mesh_topology;
DROP TABLE IF EXISTS mesh_trust_anchors;
DROP TABLE IF EXISTS mesh_certificates;
DROP TABLE IF EXISTS mesh_services;
