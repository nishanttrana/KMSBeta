# PKCS#11 Provider Samples

| Sample | Description |
|--------|-------------|
| `01-list-slots.sh` | List available PKCS#11 slots via pkcs11-tool |
| `02-list-objects.sh` | List KMS keys as PKCS#11 objects |
| `03-encrypt-decrypt.sh` | Encrypt/decrypt data using AES-GCM |
| `04-openssl-engine.conf` | OpenSSL engine config for PKCS#11 integration |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VECTA_BASE_URL` | KMS base URL (default: `https://localhost/svc/ekm`) |
| `VECTA_TENANT_ID` | Tenant identifier |
| `VECTA_AUTH_TOKEN` | Bearer token for authentication |
| `VECTA_MTLS_CERT` | Path to mTLS client certificate |
| `VECTA_MTLS_KEY` | Path to mTLS client private key |
| `VECTA_MTLS_CA` | Path to CA bundle |
| `VECTA_API_KEY` | API key for JWT exchange |
| `VECTA_JWT_ENDPOINT` | JWT token exchange endpoint |
| `VECTA_KEY_CACHE_TTL` | Key cache TTL in seconds (0 = disabled) |

## Build

```bash
# Linux
make build-linux

# macOS
make build-macos

# Windows (requires mingw cross-compiler)
make build-windows
```
