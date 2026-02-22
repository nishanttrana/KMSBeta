param(
    [string]$PackerPath = "",
    [string]$Template = "infra/packer/kms-appliance-virtualbox.pkr.hcl",
    [string]$IsoPath = "C:\Users\NishantRana\Downloads\KMS\ubuntu.iso",
    [string]$IsoChecksum = "none",
    [string]$VarFile = "",
    [string]$VBoxManagePath = ""
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$templatePath = Join-Path $root $Template

function Resolve-ToolPath {
    param(
        [string]$PreferredPath,
        [string]$CommandName,
        [string[]]$FallbackPaths
    )

    if (![string]::IsNullOrWhiteSpace($PreferredPath)) {
        if (Test-Path -LiteralPath $PreferredPath) {
            return (Resolve-Path -LiteralPath $PreferredPath).Path
        }
        throw "$CommandName not found at $PreferredPath"
    }

    $cmd = Get-Command $CommandName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $cmd) {
        return $cmd.Source
    }

    foreach ($candidate in $FallbackPaths) {
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw "$CommandName was not found in PATH. Install it or pass -$($CommandName -replace '[- ]','')Path."
}

$PackerPath = Resolve-ToolPath `
    -PreferredPath $PackerPath `
    -CommandName "packer" `
    -FallbackPaths @(
        "C:\Users\NishantRana\AppData\Local\Microsoft\WinGet\Packages\Hashicorp.Packer_Microsoft.Winget.Source_8wekyb3d8bbwe\packer.exe"
    )

if (!(Test-Path -LiteralPath $templatePath)) {
    throw "template not found at $templatePath"
}

$isoUrl = $IsoPath
if ($IsoPath -notmatch '^(https?|file)://') {
    if (!(Test-Path -LiteralPath $IsoPath)) {
        throw "ISO not found at $IsoPath"
    }
    $resolvedIso = (Resolve-Path -LiteralPath $IsoPath).Path
    $isoUrl = "file:///" + ($resolvedIso -replace '\\', '/')
}

$VBoxManagePath = Resolve-ToolPath `
    -PreferredPath $VBoxManagePath `
    -CommandName "VBoxManage" `
    -FallbackPaths @(
        "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
    )

$varFilePath = $null
if (![string]::IsNullOrWhiteSpace($VarFile)) {
    if (Test-Path -LiteralPath $VarFile) {
        $varFilePath = (Resolve-Path -LiteralPath $VarFile).Path
    } else {
        $candidate = Join-Path $root $VarFile
        if (!(Test-Path -LiteralPath $candidate)) {
            throw "var-file not found at $VarFile or $candidate"
        }
        $varFilePath = (Resolve-Path -LiteralPath $candidate).Path
    }
}

$vboxDir = Split-Path -Path $VBoxManagePath -Parent
if ($env:PATH -notlike "*$vboxDir*") {
    $env:PATH = "$vboxDir;$env:PATH"
}

Write-Host "Using packer: $PackerPath"
Write-Host "Using VBoxManage: $VBoxManagePath"
Write-Host "Using ISO: $isoUrl"

& $PackerPath init $templatePath
if ($LASTEXITCODE -ne 0) { throw "packer init failed ($LASTEXITCODE)" }

& $PackerPath fmt $templatePath
if ($LASTEXITCODE -ne 0) { throw "packer fmt failed ($LASTEXITCODE)" }

$buildArgs = @()
if ($null -ne $varFilePath) {
    $buildArgs += @("-var-file", $varFilePath)
}
$buildArgs += @(
    "-var", "iso_url=$isoUrl",
    "-var", "iso_checksum=$IsoChecksum",
    "-var", "source_directory=$root",
    "-var", "output_directory=$root\infra\packer\output",
    $templatePath
)

& $PackerPath build @buildArgs
if ($LASTEXITCODE -ne 0) { throw "packer build failed ($LASTEXITCODE)" }

Write-Host "OVA build completed. Check: $root\infra\packer\output"
