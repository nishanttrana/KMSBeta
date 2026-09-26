# Consul

Consul is the platform's service catalogue: services register themselves
(`pkg/consul`) and auth and cluster-manager read it.

It speaks only HTTPS with mutual TLS (`consul.hcl`, port 8501). Clients must
present a certificate from the internal-services Sub CA. Its own certificate
is written by the certs service and installed by `infra/tls/tls-entry.sh`
(docs/SECURITY/INTERNAL_TLS.md).

- Plain HTTP (8500), gRPC (8502) and DNS (8600) are off.
- Connect is disabled. The service-to-service mTLS is the platform's own, not
  a Consul mesh. The former `bootstrap-mesh.sh` wrote allow-all Connect
  intentions that no service used; it was removed in 1.9.0-beta.
