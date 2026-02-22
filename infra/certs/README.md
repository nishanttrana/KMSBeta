# Inter-service mTLS Certificates

Generate internal CA + per-service certs:

```bash
./infra/certs/generate-mtls.sh
```

Generate a KMIP client cert (CN must be `tenant:role`, for example `bank-alpha:kmip-client`):

```bash
./infra/certs/generate-kmip-client.sh infra/certs/out/kmip-client bank-alpha:kmip-client
```

Output layout:

- `infra/certs/out/ca/ca.crt`, `ca.key`
- `infra/certs/out/<service>/tls.crt`, `tls.key`, `tls-chain.crt`
- `infra/certs/out/trust/ca-bundle.pem`

Envoy TLS termination expects:

- `infra/certs/out/envoy/tls.crt`
- `infra/certs/out/envoy/tls.key`
