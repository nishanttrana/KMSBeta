param(
  [string]$OutputRoot = ".\dist\ekm-agent-windows",
  [string]$Version = "1.0.0",
  [ValidateSet("amd64","arm64")][string]$Arch = "amd64"
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$outDir = Join-Path $repoRoot $OutputRoot
$pkgDir = Join-Path $outDir "package"
$zipPath = Join-Path $outDir ("vecta-ekm-agent-windows-" + $Arch + "-v" + $Version + ".zip")

if (Test-Path $outDir) {
  Remove-Item $outDir -Recurse -Force
}
New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null

Push-Location $repoRoot
try {
  $env:CGO_ENABLED = "0"
  $env:GOOS = "windows"
  $env:GOARCH = $Arch
  go build -trimpath -ldflags "-s -w" -o (Join-Path $pkgDir "ekm-agent.exe") ./services/ekm-agent
} finally {
  Pop-Location
}

Copy-Item (Join-Path $PSScriptRoot "install-ekm-agent.ps1") (Join-Path $pkgDir "install-ekm-agent.ps1") -Force
Copy-Item (Join-Path $PSScriptRoot "agent-config.template.json") (Join-Path $pkgDir "agent-config.template.json") -Force

Compress-Archive -Path (Join-Path $pkgDir "*") -DestinationPath $zipPath -Force

Write-Host "Windows EKM agent package created:"
Write-Host "  $zipPath"
Write-Host ""
Write-Host "Contains:"
Write-Host "  - ekm-agent.exe"
Write-Host "  - install-ekm-agent.ps1"
Write-Host "  - agent-config.template.json"
