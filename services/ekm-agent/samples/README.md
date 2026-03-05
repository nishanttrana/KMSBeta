# EKM Agent Samples

Demonstrations of agent registration, authentication, and cryptographic operations.

| Sample | Description |
|--------|-------------|
| `01-register-and-heartbeat.sh` | Register + heartbeat using Bearer token |
| `02-register-mtls.sh` | Register using mutual TLS certificates |
| `03-check-agent-status.sh` | List agents, get status, check health |
| `04-rotate-key.sh` | Trigger TDE key rotation |
| `05-export-key-local-crypto.go` | Export key, cache locally, AES-GCM encrypt/decrypt |

## Authentication Methods

The agent supports four authentication methods (in priority order):

1. **mTLS** — Client certificate at transport layer (`--cert`, `--key`, `--cacert`)
2. **JWT** — Auto-exchanged from API key via JWT endpoint
3. **API Key** — Sent as `X-API-Key` header
4. **Bearer Token** — Static token in `Authorization: Bearer` header

## Environment Variables

| Variable | Description |
|----------|-------------|
| `EKM_API_BASE_URL` | Base URL of the EKM service |
| `EKM_AUTH_TOKEN` | Static bearer token |
| `TENANT_ID` | Tenant identifier |
| `AGENT_ID` | Agent identifier |
| `MTLS_CERT_PATH` | Path to client certificate |
| `MTLS_KEY_PATH` | Path to client private key |
| `MTLS_CA_PATH` | Path to CA bundle |
| `API_KEY` | API key for JWT exchange |
| `JWT_ENDPOINT` | JWT token exchange endpoint |
