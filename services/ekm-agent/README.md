# Vecta EKM Agent (Windows-first)

This agent registers to `services/ekm`, sends heartbeat + OS health metrics, and reports TDE state for:

- MSSQL (`db_engine: mssql`)
- Oracle (`db_engine: oracle`)
- BitLocker (`agent_mode: bitlocker`)

It is packaged as a single Windows binary with PowerShell install script.

## Authentication

The agent supports four authentication methods (in priority order):

| Method | Config Fields | Description |
|--------|--------------|-------------|
| **mTLS** | `mtls_cert_path`, `mtls_key_path`, `mtls_ca_path` | Mutual TLS at transport layer |
| **JWT** | `api_key` + `jwt_endpoint` | Auto-exchanged short-lived JWT |
| **API Key** | `api_key` | Sent as `X-API-Key` header |
| **Bearer** | `auth_token` | Static token (fallback) |

## Key Cache (Local Crypto)

When `key_cache_enabled: true`, the agent attempts to export the active TDE key
(if `export_allowed` on the KMS side) and caches it in locked memory (`mlock`).
Subsequent encrypt/decrypt operations use local AES-GCM instead of round-tripping
to the KMS server. Non-exportable keys always proxy to KMS.

- `key_cache_ttl_sec`: How long cached keys are valid (default: 300s)
- Memory is securely zeroized on eviction or agent shutdown

## BitLocker Mode

Set `agent_mode: bitlocker` to enable BitLocker management. The agent will:
- Register as a BitLocker client
- Poll for jobs every 10 seconds
- Execute operations: `enable`, `disable`, `suspend`, `resume`, `rotate_recovery`, `status`, `tpm_status`
- Report results back to KMS

## Build Windows package

```powershell
powershell -ExecutionPolicy Bypass -File .\services\ekm-agent\scripts\package-windows-agent.ps1 -Version 1.0.0 -Arch amd64
```

Output zip is generated under `dist/ekm-agent-windows/`.

## Install on Windows host

1. Extract package.
2. Open elevated PowerShell in extracted folder.
3. Run:

```powershell
.\install-ekm-agent.ps1 `
  -TenantId root `
  -AgentId mssql-prod-01 `
  -AgentName MSSQL-Prod-01 `
  -DbEngine mssql `
  -HostIP 10.0.0.15 `
  -ApiBaseUrl https://kms.example.com/svc/ekm `
  -DbVersion "SQL Server 2022" `
  -DbDsn "sqlserver://user:pass@10.0.0.15?database=master" `
  -Pkcs11ModulePath "C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
```

For Oracle:

```powershell
.\install-ekm-agent.ps1 `
  -TenantId root `
  -AgentId oracle-prod-01 `
  -AgentName ORACLE-Prod-01 `
  -DbEngine oracle `
  -HostIP 10.0.0.16 `
  -ApiBaseUrl https://kms.example.com/svc/ekm `
  -DbVersion "Oracle 19c" `
  -DbDsn "oracle://user:pass@10.0.0.16:1521/ORCLPDB1"
```

The installer creates a Windows service `VectaEKMAgent`.

## Samples

See `samples/` directory for curl and Go examples demonstrating each auth method and local crypto operations.
