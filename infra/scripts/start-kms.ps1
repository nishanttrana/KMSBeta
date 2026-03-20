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

    $inCertSecurity = $false
    $inAcmeRenewal = $false
    foreach ($rawLine in (Get-Content -LiteralPath $DeploymentPath)) {
        $line = ($rawLine -replace '#.*$', '').TrimEnd()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        if ($line -match '^\s*cert_security:\s*$') {
            $inCertSecurity = $true
            $inAcmeRenewal = $false
            continue
        }
        if ($inCertSecurity -and $line -notmatch '^\s{4,}') {
            $inCertSecurity = $false
            $inAcmeRenewal = $false
        }
        if (-not $inCertSecurity) { continue }

        if ($line -match '^\s{8,}acme_renewal:\s*$') {
            $inAcmeRenewal = $true
            continue
        }
        if ($inAcmeRenewal -and $line -notmatch '^\s{12,}') {
            $inAcmeRenewal = $false
        }
        if (-not $inAcmeRenewal) { continue }

        if ($line -match '^\s{12,}enable_ari:\s*(true|false)') {
            $env:CERTS_ENABLE_ARI = $matches[1].ToLowerInvariant()
        } elseif ($line -match '^\s{12,}ari_poll_hours:\s*([0-9]+)') {
            $env:CERTS_ARI_POLL_HOURS = $matches[1]
        } elseif ($line -match '^\s{12,}ari_window_bias_percent:\s*([0-9]+)') {
            $env:CERTS_ARI_WINDOW_BIAS_PERCENT = $matches[1]
        } elseif ($line -match '^\s{12,}emergency_rotation_threshold_hours:\s*([0-9]+)') {
            $env:CERTS_EMERGENCY_ROTATION_THRESHOLD_HOURS = $matches[1]
        } elseif ($line -match '^\s{12,}mass_renewal_risk_threshold:\s*([0-9]+)') {
            $env:CERTS_MASS_RENEWAL_RISK_THRESHOLD = $matches[1]
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

function Apply-ACMERenewalPolicy {
    $config = @{
        challenge_types = @("http-01", "dns-01", "tls-alpn-01")
        auto_renew = $true
        enable_ari = if ($env:CERTS_ENABLE_ARI) { $env:CERTS_ENABLE_ARI.Trim().ToLowerInvariant() -eq "true" } else { $true }
        ari_poll_hours = if ($env:CERTS_ARI_POLL_HOURS) { [int]$env:CERTS_ARI_POLL_HOURS } else { 24 }
        ari_window_bias_percent = if ($env:CERTS_ARI_WINDOW_BIAS_PERCENT) { [int]$env:CERTS_ARI_WINDOW_BIAS_PERCENT } else { 35 }
        emergency_rotation_threshold_hours = if ($env:CERTS_EMERGENCY_ROTATION_THRESHOLD_HOURS) { [int]$env:CERTS_EMERGENCY_ROTATION_THRESHOLD_HOURS } else { 48 }
        mass_renewal_risk_threshold = if ($env:CERTS_MASS_RENEWAL_RISK_THRESHOLD) { [int]$env:CERTS_MASS_RENEWAL_RISK_THRESHOLD } else { 8 }
        require_eab = $false
        allow_wildcard = $true
        allow_ip_identifiers = $false
        max_sans = 100
        default_validity_days = 397
        rate_limit_per_hour = 1000
    }
    $body = @{
        enabled = $true
        updated_by = "start-kms"
        config_json = ($config | ConvertTo-Json -Depth 4 -Compress)
    } | ConvertTo-Json -Depth 4 -Compress

    for ($attempt = 1; $attempt -le 20; $attempt++) {
        try {
            Invoke-RestMethod -Method Put -Uri "http://127.0.0.1:8030/certs/protocols/acme?tenant_id=root" -ContentType "application/json" -Body $body | Out-Null
            return
        } catch {
            Start-Sleep -Seconds 2
        }
    }

    Write-Warning "unable to apply ACME renewal policy from deployment config"
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

Apply-ACMERenewalPolicy

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
