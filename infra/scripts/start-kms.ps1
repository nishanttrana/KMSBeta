param(
    [string]$DeploymentFile = "infra/deployment/deployment.yaml",
    [int]$DockerWaitSeconds = 90,
    [switch]$SkipHealthChecks
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$parser = Join-Path $PSScriptRoot "parse-deployment.ps1"
$healthScript = Join-Path $PSScriptRoot "healthcheck-enabled-services.ps1"
$stopScript = Join-Path $PSScriptRoot "stop-kms.ps1"
$composeHelper = Join-Path $PSScriptRoot "compose-kms.ps1"
$projectName = "vecta-kms"

function Wait-DockerDaemon {
    param([int]$TimeoutSeconds = 90)

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

    throw "deployment file not found"
}

function Set-ComposeEnvironment {
    param([string]$DeploymentPath)

    $profiles = (& $parser -File $DeploymentPath).Trim()
    if ([string]::IsNullOrWhiteSpace($profiles)) {
        throw "no compose profiles resolved from deployment file: $DeploymentPath"
    }
    $env:COMPOSE_PROFILES = $profiles

    $hsmLine = Get-Content -LiteralPath $DeploymentPath | Where-Object { $_ -match '^\s*hsm_mode:' } | Select-Object -First 1
    if ($hsmLine) {
        $env:HSM_MODE = (($hsmLine -replace '#.*$', '') -replace '^\s*hsm_mode:\s*', '').Trim().ToLowerInvariant()
    }

    if (-not $env:HSM_ENDPOINT) {
        switch ($env:HSM_MODE) {
            "hardware" { $env:HSM_ENDPOINT = "hsm-connector:18430" }
            "software" { $env:HSM_ENDPOINT = "software-vault:18440" }
            "auto" { $env:HSM_ENDPOINT = "hsm-connector:18430" }
            default { $env:HSM_ENDPOINT = "software-vault:18440" }
        }
    }
}

function Invoke-ComposeUp {
    $args = @("up", "-d")
    $removeOrphans = $true
    if ($env:START_KMS_REMOVE_ORPHANS -and $env:START_KMS_REMOVE_ORPHANS.Trim().ToLowerInvariant() -eq "false") {
        $removeOrphans = $false
    }
    if ($removeOrphans) {
        $args += "--remove-orphans"
    }
    & $composeHelper @args
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose up failed with exit code $LASTEXITCODE"
    }
}

function Prepare-CertVolumes {
    $certsVolume = "${projectName}_certs-key-data"
    $runtimeVolume = "${projectName}_runtime-certs"
    $passphrasePath = if ($env:CERTS_CRWK_PASSPHRASE_FILE) {
        $env:CERTS_CRWK_PASSPHRASE_FILE
    } else {
        "/var/lib/vecta/certs/bootstrap.passphrase"
    }
    $bootstrapSecret = if ($env:CERTS_CRWK_BOOTSTRAP_PASSPHRASE) {
        $env:CERTS_CRWK_BOOTSTRAP_PASSPHRASE
    } else {
        "vecta-dev-passphrase"
    }

    docker volume create $certsVolume *> $null
    docker volume create $runtimeVolume *> $null

    foreach ($helperImage in @("postgres:16.13-alpine", "alpine:3.20", "busybox:1.36")) {
        docker run --rm `
            --volume "${certsVolume}:/data" `
            --volume "${runtimeVolume}:/runtime" `
            --env "CERTS_CRWK_PASSPHRASE_FILE=$passphrasePath" `
            --env "BOOTSTRAP_SECRET=$bootstrapSecret" `
            $helperImage `
            sh -lc 'set -eu; mkdir -p /data /runtime; chown -R 100:101 /data /runtime; chmod 700 /data /runtime; case "${CERTS_CRWK_PASSPHRASE_FILE:-/var/lib/vecta/certs/bootstrap.passphrase}" in /var/lib/vecta/certs/*) target="/data/${CERTS_CRWK_PASSPHRASE_FILE#/var/lib/vecta/certs/}"; mkdir -p "$(dirname "$target")"; if [ ! -s "$target" ]; then printf %s "${BOOTSTRAP_SECRET:-vecta-dev-passphrase}" > "$target"; fi; chown 100:101 "$target"; chmod 600 "$target";; esac' *> $null
        if ($LASTEXITCODE -eq 0) {
            return
        }
    }

    throw "unable to prepare certificate bootstrap volumes"
}

function Recover-Once {
    param([string]$DeploymentPath)

    if (Test-Path -LiteralPath $stopScript) {
        & $stopScript -DeploymentFile $DeploymentPath -Force -SkipDockerCheck
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "forced stop completed with warnings (exit code $LASTEXITCODE)"
        }
        return
    }

    $prevErrorPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    $ids = @(docker ps -aq --filter "label=com.docker.compose.project=$projectName")
    $ids = $ids | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if ($ids.Count -gt 0) {
        docker rm -f $ids *> $null
    }

    $networkName = "${projectName}_kms_net"
    docker network rm $networkName *> $null

    $ErrorActionPreference = $prevErrorPreference
}

$resolvedDeploymentFile = Resolve-DeploymentPath -InputPath $DeploymentFile
Wait-DockerDaemon -TimeoutSeconds $DockerWaitSeconds
Set-ComposeEnvironment -DeploymentPath $resolvedDeploymentFile
Prepare-CertVolumes

Write-Host "starting KMS with COMPOSE_PROFILES=$($env:COMPOSE_PROFILES)"
try {
    Invoke-ComposeUp
} catch {
    Write-Warning "initial startup failed, attempting one forced recovery pass"
    Recover-Once -DeploymentPath $resolvedDeploymentFile
    Start-Sleep -Seconds 2
    Invoke-ComposeUp
}

if (-not $SkipHealthChecks) {
    if (!(Test-Path -LiteralPath $healthScript)) {
        throw "health check script not found: $healthScript"
    }
    & $healthScript -DeploymentFile $resolvedDeploymentFile
    if ($LASTEXITCODE -ne 0) {
        throw "health checks failed with exit code $LASTEXITCODE"
    }
}

Write-Host "KMS startup completed"
