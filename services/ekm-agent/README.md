# Vecta EKM Agent (Windows-first)

This agent registers to `services/ekm`, sends heartbeat + OS health metrics, and reports TDE state for:

- MSSQL (`db_engine: mssql`)
- Oracle (`db_engine: oracle`)

It is packaged as a single Windows binary with PowerShell install script.

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
  -TenantId bank-alpha `
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
  -TenantId bank-alpha `
  -AgentId oracle-prod-01 `
  -AgentName ORACLE-Prod-01 `
  -DbEngine oracle `
  -HostIP 10.0.0.16 `
  -ApiBaseUrl https://kms.example.com/svc/ekm `
  -DbVersion "Oracle 19c" `
  -DbDsn "oracle://user:pass@10.0.0.16:1521/ORCLPDB1"
```

The installer creates a Windows service `VectaEKMAgent`.
