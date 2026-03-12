param(
    [string]$DeploymentFile = "infra/deployment/deployment.yaml",
    [int]$Retries = 20,
    [int]$RetryDelaySeconds = 3
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$parser = Join-Path $PSScriptRoot "parse-deployment.ps1"
$composeHelper = Join-Path $PSScriptRoot "compose-kms.ps1"

if (!(Test-Path -LiteralPath $DeploymentFile)) {
    $DeploymentFile = Join-Path $root "infra\deployment\deployment.yaml"
}
if (!(Test-Path -LiteralPath $DeploymentFile)) {
    throw "deployment file not found"
}

$profileToService = @{
    "secrets" = @("secrets")
    "certs" = @("certs")
    "governance" = @("governance")
    "cloud_byok" = @("cloud")
    "hyok_proxy" = @("hyok")
    "kmip_server" = @("kmip")
    "qkd_interface" = @("qkd")
    "qrng_generator" = @("qrng")
    "ekm_database" = @("ekm")
    "payment_crypto" = @("payment")
    "compliance_dashboard" = @("compliance")
    "sbom_cbom" = @("sbom")
    "reporting_alerting" = @("reporting")
    "posture_management" = @("posture")
    "ai_llm" = @("ai")
    "pqc_migration" = @("pqc")
    "crypto_discovery" = @("discovery")
    "mpc_engine" = @("mpc")
    "data_protection" = @("dataprotect")
    "clustering" = @("cluster-manager", "etcd")
    "hsm_hardware" = @("hsm-connector")
    "hsm_software" = @("software-vault")
}

$enabledServices = New-Object System.Collections.Generic.List[string]
$enabledServices.AddRange([string[]]@("auth", "keycore", "audit", "policy"))

$profiles = (& $parser -File $DeploymentFile).Trim()
if (-not [string]::IsNullOrWhiteSpace($profiles)) {
    foreach ($profile in $profiles.Split(",")) {
        $p = $profile.Trim()
        if ([string]::IsNullOrWhiteSpace($p)) {
            continue
        }
        if ($profileToService.ContainsKey($p)) {
            $enabledServices.AddRange([string[]]$profileToService[$p])
        }
    }
}

$uniqueServices = New-Object System.Collections.Generic.List[string]
$seen = @{}
foreach ($service in $enabledServices) {
    if (-not $seen.ContainsKey($service)) {
        $seen[$service] = $true
        $uniqueServices.Add($service)
    }
}

function Get-ComposeServiceStatusMap {
    $lines = @(& $composeHelper ps --format "{{.Service}}|{{.State}}|{{.Health}}")
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose ps failed with exit code $LASTEXITCODE"
    }

    $statusMap = @{}
    foreach ($line in $lines) {
        $raw = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($raw)) {
            continue
        }
        $parts = $raw.Split("|")
        if ($parts.Count -lt 2) {
            continue
        }

        $svc = $parts[0].Trim()
        $state = $parts[1].Trim().ToLowerInvariant()
        $health = ""
        if ($parts.Count -ge 3) {
            $health = $parts[2].Trim().ToLowerInvariant()
        }
        $statusMap[$svc] = @{
            State = $state
            Health = $health
        }
    }

    return $statusMap
}

function Test-HealthcheckMissingRuntime {
    param([string]$Service)

    $containerId = & $composeHelper ps -q $Service | Select-Object -First 1
    $containerId = [string]$containerId
    if ([string]::IsNullOrWhiteSpace($containerId)) {
        return $false
    }
    $containerId = $containerId.Trim()

    $healthLog = docker inspect --format '{{if .State.Health}}{{range .State.Health.Log}}{{println .Output}}{{end}}{{end}}' $containerId 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    return [regex]::IsMatch(($healthLog -join "`n"), 'stat /bin/sh: no such file or directory|executable file not found in \$PATH|: not found')
}

for ($attempt = 1; $attempt -le $Retries; $attempt++) {
    $statusMap = Get-ComposeServiceStatusMap
    $unhealthy = @()
    $healthy = @()

    foreach ($service in $uniqueServices) {
        if (-not $statusMap.ContainsKey($service)) {
            $unhealthy += "${service} (missing)"
            continue
        }

        $state = $statusMap[$service].State
        $health = $statusMap[$service].Health

        if ($state -ne "running") {
            $unhealthy += "${service} (state=$state)"
            continue
        }

        if (-not [string]::IsNullOrWhiteSpace($health) -and $health -ne "healthy") {
            if ($state -eq "running" -and (Test-HealthcheckMissingRuntime -Service $service)) {
                $healthy += "${service} (running; health command unavailable)"
                continue
            }
            $unhealthy += "${service} (health=$health)"
            continue
        }

        $healthy += $service
    }

    if ($unhealthy.Count -eq 0) {
        foreach ($svc in $healthy) {
            Write-Host "healthy: $svc"
        }
        exit 0
    }

    if ($attempt -lt $Retries) {
        Start-Sleep -Seconds $RetryDelaySeconds
    } else {
        throw "health checks failed for: $($unhealthy -join ', ')"
    }
}
