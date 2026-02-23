# KMIP Service

This service runs a real KMIP-over-TLS endpoint backed by `keycore` for key lifecycle and cryptographic operations.

## Policy and Key-Role Enforcement

- `OperationPolicyName` from KMIP attributes is persisted and enforced server-side per operation.
- `CryptographicUsageMask` is enforced for cryptographic operations.
- `CryptographicParameters.KeyRoleType` is persisted and validated during Encrypt/Decrypt/Sign/Verify requests.

## mTLS Client Identity

Client certificates must use CN format:

`tenant_id:role`

Supported roles:

- `kmip-client`
- `kmip-admin`
- `kmip-service`

## Certificate Setup

Generate internal service certs and CA:

```bash
./infra/certs/generate-mtls.sh
```

Generate a KMIP client cert:

```bash
./infra/certs/generate-kmip-client.sh infra/certs/out/kmip-client root:kmip-client
```

## Compose Deployment

`docker-compose.yml` configures KMIP to use fixed TLS files:

- `/etc/vecta-certs/kmip/tls.crt`
- `/etc/vecta-certs/kmip/tls.key`
- `/etc/vecta-certs/ca/ca.crt`

Bring KMIP up/rebuild:

```bash
docker compose up -d --build kmip
```

## pykmip Smoke Test

`pykmip` currently supports protocol versions up to KMIP `2.0`.

Run the interoperability smoke test from a Python container:

```bash
docker run --rm --network vecta-kms_kms_net \
  -v "$PWD/infra/certs/out/kmip-client:/certs/client:ro" \
  -v "$PWD/infra/certs/out/ca:/certs/ca:ro" \
  -v "$PWD/services/kmip/scripts:/scripts:ro" \
  python:3.11-slim sh -lc \
  "pip install -q pykmip && python /scripts/pykmip_smoke.py \
   --host envoy --port 5696 \
   --cert /certs/client/tls.crt --key /certs/client/tls.key --ca /certs/ca/ca.crt \
   --version 1.4"
```

Or use the wrappers:

```bash
./services/kmip/scripts/run_pykmip_smoke.sh
```

```powershell
.\services\kmip\scripts\run_pykmip_smoke.ps1
```

## KMIP 3.x Smoke Test

Use the native `kmip-go` client to validate protocol negotiation at `3.x` and roundtrip crypto:

```bash
go run ./services/kmip/scripts/kmip_v3_smoke.go
```
