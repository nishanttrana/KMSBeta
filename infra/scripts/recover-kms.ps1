param(
    [string]$DeploymentFile = "infra/deployment/deployment.yaml",
    [int]$DockerWaitSeconds = 90,
    [switch]$SkipHealthChecks
)

$ErrorActionPreference = "Stop"

$stopScript = Join-Path $PSScriptRoot "stop-kms.ps1"
$startScript = Join-Path $PSScriptRoot "start-kms.ps1"

if (!(Test-Path -LiteralPath $stopScript)) {
    throw "missing script: $stopScript"
}
if (!(Test-Path -LiteralPath $startScript)) {
    throw "missing script: $startScript"
}

Write-Host "running forced KMS recovery"
& $stopScript -DeploymentFile $DeploymentFile -Force -DockerWaitSeconds $DockerWaitSeconds
if ($LASTEXITCODE -ne 0) {
    Write-Warning "stop step returned exit code $LASTEXITCODE, continuing recovery"
}

& $startScript -DeploymentFile $DeploymentFile -DockerWaitSeconds $DockerWaitSeconds -SkipHealthChecks:$SkipHealthChecks
if ($LASTEXITCODE -ne 0) {
    throw "recovery start failed with exit code $LASTEXITCODE"
}

Write-Host "KMS recovery completed"
