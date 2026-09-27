#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install and register a Vecta EKM Agent as a Windows service.

.DESCRIPTION
  Installs ekm-agent.exe, writes the agent config, and registers it as a Windows
  service in TDE-monitoring or BitLocker mode (the only modes the agent has).

.EXAMPLE
  # SQL Server TDE
  .\install-ekm-agent.ps1 `
    -TenantId root -AgentId sql01 -AgentName "SQL Server 01" `
    -DbEngine mssql -HostIP 10.0.0.10 -ApiBaseUrl https://kms.acme.com

  # MySQL TDE
  .\install-ekm-agent.ps1 -DbEngine mysql -TenantId root ...

  # PostgreSQL TDE
  .\install-ekm-agent.ps1 -DbEngine postgresql -TenantId root ...

  # Oracle TDE
  .\install-ekm-agent.ps1 -DbEngine oracle -TenantId root ...

  # BitLocker key management mode
  .\install-ekm-agent.ps1 -Mode bitlocker -TenantId root ...

#>
param(
  [Parameter(Mandatory=$true)][string]$TenantId,
  [Parameter(Mandatory=$true)][string]$AgentId,
  [Parameter(Mandatory=$true)][string]$AgentName,

  # Operation mode: tde (default) or bitlocker
  [ValidateSet("tde","bitlocker")][string]$Mode = "tde",

  # TDE mode: target database engine
  [ValidateSet("mssql","mysql","postgresql","oracle","mariadb")][string]$DbEngine = "mssql",

  [string]$HostIP       = "127.0.0.1",
  [Parameter(Mandatory=$true)][string]$ApiBaseUrl,
  [string]$AuthToken    = "",

  # Optional TDE settings
  [string]$DbVersion    = "",
  [string]$DbDsn        = "",
  [string]$DbUser       = "",
  [string]$DbPassword   = "",
  [string]$DbName       = "",
  [int]$DbPort          = 0,
  [int]$HeartbeatIntervalSec = 30,
  [int]$RotationCycleDays    = 90,
  [switch]$AutoProvisionTDE  = $true,

  [string]$InstallDir = "C:\ProgramData\Vecta\EKMAgent"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step([string]$msg) {
  Write-Host "  -> $msg" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Vecta EKM Agent Installer" -ForegroundColor Green
Write-Host "  Mode:   $Mode"
Write-Host "  Agent:  $AgentId ($AgentName)"
Write-Host "  Tenant: $TenantId"
Write-Host "  URL:    $ApiBaseUrl"
Write-Host ""

# ── Validate binary ──────────────────────────────────────────────
if (-not (Test-Path ".\ekm-agent.exe")) {
  throw "ekm-agent.exe not found in current directory. Download the agent package first."
}

# ── Create install dir ───────────────────────────────────────────
Write-Step "Creating install directory: $InstallDir"
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item ".\ekm-agent.exe" (Join-Path $InstallDir "ekm-agent.exe") -Force

# ── Resolve default DB port ──────────────────────────────────────
if ($DbPort -le 0) {
  $DbPort = switch ($DbEngine) {
    "mssql"      { 1433 }
    "mysql"      { 3306 }
    "mariadb"    { 3306 }
    "postgresql" { 5432 }
    "oracle"     { 1521 }
    default      { 1433 }
  }
}

# ── Build config ─────────────────────────────────────────────────
Write-Step "Writing agent config"
$cfg = [ordered]@{
  tenant_id              = $TenantId
  agent_id               = $AgentId
  agent_name             = $AgentName
  agent_mode             = $Mode
  role                   = "ekm-agent"
  db_engine              = $DbEngine
  host                   = $HostIP
  version                = $DbVersion
  api_base_url           = $ApiBaseUrl
  auth_token             = $AuthToken
  tls_skip_verify        = $false
  heartbeat_interval_sec = $HeartbeatIntervalSec
  rotation_cycle_days    = $RotationCycleDays
  auto_provision_tde     = [bool]$AutoProvisionTDE
  db_dsn                 = $DbDsn
  db_user                = $DbUser
  db_password            = $DbPassword
  db_name                = $DbName
  db_port                = $DbPort
  active_key_id          = ""
  active_key_version     = "v1"
  config_version_ack     = 0
}

# BitLocker mode: the agent reads these two keys; endpoint paths default
# per mode inside the agent.
if ($Mode -eq "bitlocker") {
  $cfg["bitlocker_mount_point"]    = "C:"
  $cfg["bitlocker_protector_type"] = "tpm"
}

$cfgPath = Join-Path $InstallDir "agent-config.json"
$cfg | ConvertTo-Json -Depth 6 | Set-Content -Path $cfgPath -Encoding UTF8

# ── Install Windows service ───────────────────────────────────────
$svcName = "VectaEKMAgent"
$svcExe  = Join-Path $InstallDir "ekm-agent.exe"

Write-Step "Registering Windows service: $svcName"
if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
  Write-Step "Stopping and removing existing service"
  Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
  & $svcExe -service uninstall -config $cfgPath | Out-Null
}
& $svcExe -service install -config $cfgPath
& $svcExe -service start   -config $cfgPath

# ── Verify ────────────────────────────────────────────────────────
Start-Sleep -Seconds 2
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
  Write-Host ""
  Write-Host "Vecta EKM Agent installed and running." -ForegroundColor Green
} else {
  Write-Host ""
  Write-Host "WARNING: service may not have started. Check Event Viewer for details." -ForegroundColor Yellow
}

Write-Host "  Service : $svcName"
Write-Host "  Config  : $cfgPath"
Write-Host "  Mode    : $Mode"
Write-Host ""
