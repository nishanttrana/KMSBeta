#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install and register a Vecta BitLocker Client as a Windows service.

.DESCRIPTION
  Installs ekm-agent.exe in BitLocker mode, configures volume protection policy,
  registers the Vecta KMS as recovery key escrow, and starts the service.

.EXAMPLE
  .\install-bitlocker-client.ps1 `
    -TenantId root -ClientId wks01 -ClientName "Workstation 01" `
    -ApiBaseUrl https://kms.acme.com -ProtectOsVolume -ProtectDataVolumes

.NOTES
  Requires: Windows 10/11 Pro or Enterprise, TPM 2.0 recommended.
  BitLocker must be available on this edition of Windows.
#>
param(
  [Parameter(Mandatory=$true)][string]$TenantId,
  [Parameter(Mandatory=$true)][string]$ClientId,
  [Parameter(Mandatory=$true)][string]$ClientName,
  [Parameter(Mandatory=$true)][string]$ApiBaseUrl,
  [string]$AuthToken = "",

  # Protection scope
  [switch]$ProtectOsVolume    = $true,
  [switch]$ProtectDataVolumes = $true,
  [switch]$RequireTPM         = $true,

  # Policy
  [int]$HeartbeatIntervalSec = 60,
  [int]$KeyRotationDays      = 180,
  [switch]$EscrowRecoveryKey = $true,

  # Mount points to protect (empty = all fixed volumes)
  [string[]]$MountPoints = @(),

  [string]$InstallDir = "C:\ProgramData\Vecta\BitLockerClient"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Write-Step([string]$msg) {
  Write-Host "  -> $msg" -ForegroundColor Cyan
}

# ── Pre-flight checks ─────────────────────────────────────────────
Write-Host ""
Write-Host "Vecta BitLocker Client Installer" -ForegroundColor Green
Write-Host "  Client: $ClientId ($ClientName)"
Write-Host "  Tenant: $TenantId"
Write-Host "  URL:    $ApiBaseUrl"

# Check BitLocker feature
$blFeature = Get-WindowsOptionalFeature -Online -FeatureName BitLocker -ErrorAction SilentlyContinue
if ($blFeature -and $blFeature.State -ne "Enabled") {
  throw "BitLocker feature is not enabled on this system. Enable it via Windows Features and reboot."
}

# Check TPM
if ($RequireTPM) {
  $tpm = Get-Tpm -ErrorAction SilentlyContinue
  if (-not $tpm -or -not $tpm.TpmPresent) {
    Write-Host "  WARNING: TPM not detected. Proceeding with password-only protection." -ForegroundColor Yellow
    $RequireTPM = $false
  } elseif (-not $tpm.TpmReady) {
    Write-Host "  WARNING: TPM present but not ready. Initialize TPM before enabling BitLocker." -ForegroundColor Yellow
  } else {
    Write-Host "  TPM:  Present and ready" -ForegroundColor Green
  }
}

if (-not (Test-Path ".\ekm-agent.exe")) {
  throw "ekm-agent.exe not found in current directory."
}

# ── Install agent ─────────────────────────────────────────────────
Write-Step "Installing agent to: $InstallDir"
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $InstallDir "recovery") -Force | Out-Null
Copy-Item ".\ekm-agent.exe" (Join-Path $InstallDir "ekm-agent.exe") -Force

# ── Discover volumes ──────────────────────────────────────────────
$volumeList = @()
if ($MountPoints.Count -gt 0) {
  $volumeList = $MountPoints
} else {
  # Auto-discover fixed volumes
  Get-Volume | Where-Object { $_.DriveType -eq "Fixed" -and $_.DriveLetter } | ForEach-Object {
    $volumeList += "$($_.DriveLetter):\"
  }
}
Write-Step "Volumes to protect: $($volumeList -join ', ')"

# ── Enable BitLocker on each volume ───────────────────────────────
foreach ($vol in $volumeList) {
  $blStatus = Get-BitLockerVolume -MountPoint $vol -ErrorAction SilentlyContinue
  if (-not $blStatus) {
    Write-Host "  Skipping $vol — not a BitLocker-capable volume" -ForegroundColor Yellow
    continue
  }

  if ($blStatus.EncryptionPercentage -lt 100 -and $blStatus.VolumeStatus -ne "FullyEncrypted") {
    Write-Step "Enabling BitLocker on $vol"
    $blArgs = @{ MountPoint = $vol; EncryptionMethod = "XtsAes256" }
    if ($RequireTPM) {
      $blArgs["TpmProtector"] = $true
    } else {
      # Prompt for recovery password as fallback protector
      $blArgs["RecoveryPasswordProtector"] = $true
    }
    Enable-BitLocker @blArgs -ErrorAction SilentlyContinue | Out-Null
  }

  # Add recovery password protector for escrow
  if ($EscrowRecoveryKey) {
    $existing = (Get-BitLockerVolume -MountPoint $vol).KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
    if (-not $existing) {
      Write-Step "Adding recovery key protector on $vol"
      Add-BitLockerKeyProtector -MountPoint $vol -RecoveryPasswordProtector | Out-Null
    }

    # Export recovery key to escrow directory
    $protectors = (Get-BitLockerVolume -MountPoint $vol).KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
    foreach ($p in $protectors) {
      $escrowFile = Join-Path $InstallDir "recovery" ("$ClientId-$($vol.Replace(':','').Replace('\',''))-$($p.KeyProtectorId.Trim('{}')).txt")
      $p.RecoveryPassword | Set-Content -Path $escrowFile -Encoding UTF8
    }
    Write-Step "Recovery keys saved to: $(Join-Path $InstallDir 'recovery')"
  }
}

# ── Write agent config ────────────────────────────────────────────
Write-Step "Writing agent config"
$cfg = [ordered]@{
  tenant_id              = $TenantId
  agent_id               = $ClientId
  agent_name             = $ClientName
  mode                   = "bitlocker"
  role                   = "bitlocker-client"
  host                   = $env:COMPUTERNAME
  api_base_url           = $ApiBaseUrl
  register_path          = "/ekm/bitlocker/clients/register"
  heartbeat_path         = "/ekm/bitlocker/clients/{client_id}/heartbeat"
  auth_token             = $AuthToken
  tls_skip_verify        = $false
  heartbeat_interval_sec = $HeartbeatIntervalSec
  bitlocker = [ordered]@{
    protect_os_volume    = [bool]$ProtectOsVolume
    protect_data_volumes = [bool]$ProtectDataVolumes
    require_tpm          = [bool]$RequireTPM
    key_rotation_days    = $KeyRotationDays
    escrow_to_vecta      = [bool]$EscrowRecoveryKey
    recovery_key_path    = Join-Path $InstallDir "recovery"
    protected_volumes    = $volumeList
    encryption_method    = "XtsAes256"
  }
}
$cfgPath = Join-Path $InstallDir "bitlocker-config.json"
$cfg | ConvertTo-Json -Depth 6 | Set-Content -Path $cfgPath -Encoding UTF8

# ── Register Windows service ──────────────────────────────────────
$svcName = "VectaBitLockerClient"
$svcExe  = Join-Path $InstallDir "ekm-agent.exe"

Write-Step "Registering Windows service: $svcName"
if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
  Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
  & $svcExe -service uninstall -config $cfgPath | Out-Null
}
& $svcExe -service install -config $cfgPath
& $svcExe -service start   -config $cfgPath

# ── Summary ───────────────────────────────────────────────────────
Start-Sleep -Seconds 2
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
Write-Host ""
if ($svc -and $svc.Status -eq "Running") {
  Write-Host "Vecta BitLocker Client installed and running." -ForegroundColor Green
} else {
  Write-Host "WARNING: service may not have started. Check Event Viewer for $svcName." -ForegroundColor Yellow
}
Write-Host "  Service  : $svcName"
Write-Host "  Config   : $cfgPath"
Write-Host "  Volumes  : $($volumeList -join ', ')"
Write-Host "  Recovery : $(Join-Path $InstallDir 'recovery')"
Write-Host ""
Write-Host "IMPORTANT: Upload recovery keys to Vecta KMS before discarding them." -ForegroundColor Yellow
Write-Host ""
