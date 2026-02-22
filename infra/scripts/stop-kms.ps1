param(
    [string]$DeploymentFile = "infra/deployment/deployment.yaml",
    [switch]$Force,
    [switch]$SkipDockerCheck,
    [int]$DockerWaitSeconds = 45
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$composeFile = Join-Path $root "docker-compose.yml"
$parser = Join-Path $PSScriptRoot "parse-deployment.ps1"
$projectName = "vecta-kms"
$networkName = "${projectName}_kms_net"

function Wait-DockerDaemon {
    param([int]$TimeoutSeconds = 45)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        docker info *> $null
        if ($LASTEXITCODE -eq 0) {
            return
        }
        Start-Sleep -Seconds 2
    }

    throw "docker daemon is not reachable after ${TimeoutSeconds}s"
}

function Resolve-DeploymentPath {
    param([string]$InputPath)

    if (Test-Path -LiteralPath $InputPath) {
        return (Resolve-Path -LiteralPath $InputPath).Path
    }

    $fallback = Join-Path $root "infra\deployment\deployment.yaml"
    if (Test-Path -LiteralPath $fallback) {
        return (Resolve-Path -LiteralPath $fallback).Path
    }

    return $null
}

function Set-ComposeProfiles {
    param([string]$DeploymentPath)

    if ([string]::IsNullOrWhiteSpace($DeploymentPath)) {
        Write-Warning "deployment file not found; using existing COMPOSE_PROFILES from environment if present"
        return
    }

    $profiles = (& $parser -File $DeploymentPath).Trim()
    if (![string]::IsNullOrWhiteSpace($profiles)) {
        $env:COMPOSE_PROFILES = $profiles
    }
}

function Remove-StaleProjectResources {
    $prevErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    $ids = @(docker ps -aq --filter "label=com.docker.compose.project=$projectName")
    $ids = $ids | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($ids.Count -gt 0) {
        Write-Host "removing stale project containers ($($ids.Count))"
        docker rm -f $ids *> $null
    }

    docker network rm $networkName *> $null

    $ErrorActionPreference = $prevErrorPreference
}

if (-not $SkipDockerCheck) {
    Wait-DockerDaemon -TimeoutSeconds $DockerWaitSeconds
}

$resolvedDeploymentFile = Resolve-DeploymentPath -InputPath $DeploymentFile
Set-ComposeProfiles -DeploymentPath $resolvedDeploymentFile

Write-Host "stopping KMS stack"
$prevErrorPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
docker compose -f $composeFile down --remove-orphans
$downExit = $LASTEXITCODE
$ErrorActionPreference = $prevErrorPreference
if ($downExit -ne 0) {
    Write-Warning "docker compose down returned exit code $downExit"
}

if ($Force -or $downExit -ne 0) {
    Remove-StaleProjectResources
}

if ($downExit -ne 0 -and -not $Force) {
    throw "docker compose down failed with exit code $downExit"
}

Write-Host "KMS stack stopped"
exit 0
