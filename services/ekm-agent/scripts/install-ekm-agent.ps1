param(
  [Parameter(Mandatory=$true)][string]$TenantId,
  [Parameter(Mandatory=$true)][string]$AgentId,
  [Parameter(Mandatory=$true)][string]$AgentName,
  [Parameter(Mandatory=$true)][ValidateSet("mssql","oracle")][string]$DbEngine,
  [Parameter(Mandatory=$true)][string]$HostIP,
  [Parameter(Mandatory=$true)][string]$ApiBaseUrl,
  [string]$DbVersion = "",
  [int]$HeartbeatIntervalSec = 30,
  [int]$RotationCycleDays = 90,
  [string]$DbDsn = "",
  [string]$Pkcs11ModulePath = "C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
  [string]$InstallDir = "C:\ProgramData\Vecta\EKMAgent"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -Path ".\ekm-agent.exe")) {
  throw "ekm-agent.exe not found in current directory."
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item ".\ekm-agent.exe" (Join-Path $InstallDir "ekm-agent.exe") -Force

$cfgPath = Join-Path $InstallDir "agent-config.json"
$cfg = @{
  tenant_id = $TenantId
  agent_id = $AgentId
  agent_name = $AgentName
  role = "ekm-agent"
  db_engine = $DbEngine
  host = $HostIP
  version = $DbVersion
  api_base_url = $ApiBaseUrl
  register_path = "/ekm/agents/register"
  heartbeat_path = "/ekm/agents/{agent_id}/heartbeat"
  rotate_path = "/ekm/agents/{agent_id}/rotate"
  auth_token = ""
  tls_skip_verify = $false
  heartbeat_interval_sec = $HeartbeatIntervalSec
  rotation_cycle_days = $RotationCycleDays
  auto_provision_tde = $true
  db_dsn = $DbDsn
  db_user = ""
  db_password = ""
  db_name = ""
  db_port = $(if ($DbEngine -eq "oracle") { 1521 } else { 1433 })
  pkcs11_module_path = $Pkcs11ModulePath
  pkcs11_slot_id = 0
  pkcs11_pin_env = "PKCS11_PIN"
  active_key_id = ""
  active_key_version = "v1"
  config_version_ack = 0
}
$cfg | ConvertTo-Json -Depth 5 | Set-Content -Path $cfgPath -Encoding UTF8

$svcName = "VectaEKMAgent"
$svcExe = Join-Path $InstallDir "ekm-agent.exe"

if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
  & $svcExe -service stop -config $cfgPath | Out-Null
  & $svcExe -service uninstall -config $cfgPath | Out-Null
}

& $svcExe -service install -config $cfgPath
& $svcExe -service start -config $cfgPath

Write-Host "Vecta EKM Agent installed and started."
Write-Host "Service: $svcName"
Write-Host "Config : $cfgPath"
