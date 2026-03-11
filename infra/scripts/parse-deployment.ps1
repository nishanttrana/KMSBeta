param(
    [string]$File = "infra/deployment/deployment.yaml"
)

if (!(Test-Path -LiteralPath $File)) {
    throw "deployment file not found: $File"
}

$featureOrder = @(
    "secrets",
    "certs",
    "governance",
    "cloud_byok",
    "hyok_proxy",
    "kmip_server",
    "qkd_interface",
    "qrng_generator",
    "ekm_database",
    "payment_crypto",
    "compliance_dashboard",
    "sbom_cbom",
    "reporting_alerting",
    "posture_management",
    "ai_llm",
    "pqc_migration",
    "crypto_discovery",
    "mpc_engine",
    "data_protection",
    "clustering"
)

$enabled = @{}
$hsmMode = "software"
$inFeatures = $false

Get-Content -LiteralPath $File | ForEach-Object {
    $line = ($_ -replace '#.*$', '').TrimEnd()
    if ([string]::IsNullOrWhiteSpace($line)) { return }

    if ($line -match '^\s*hsm_mode:\s*([A-Za-z_]+)') {
        $hsmMode = $matches[1].ToLowerInvariant()
    }

    if ($line -match '^\s*features:\s*$') {
        $inFeatures = $true
        return
    }

    if ($inFeatures) {
        if ($line -match '^\s{4,}([a-z0-9_]+):\s*(true|false)') {
            $k = $matches[1]
            $v = $matches[2]
            if ($v -eq "true") {
                $enabled[$k] = $true
            } else {
                $enabled.Remove($k) | Out-Null
            }
            return
        }
        if ($line -notmatch '^\s{4,}') {
            $inFeatures = $false
        }
    }
}

$profiles = New-Object System.Collections.Generic.List[string]
foreach ($f in $featureOrder) {
    if ($enabled.ContainsKey($f)) {
        $profiles.Add($f)
    }
}

switch ($hsmMode) {
    "hardware" { $profiles.Add("hsm_hardware") }
    "software" { $profiles.Add("hsm_software") }
    "auto" {
        $profiles.Add("hsm_hardware")
        $profiles.Add("hsm_software")
    }
    default { throw "invalid hsm_mode in ${File}: $hsmMode" }
}

$seen = @{}
$ordered = New-Object System.Collections.Generic.List[string]
foreach ($p in $profiles) {
    if (-not $seen.ContainsKey($p)) {
        $seen[$p] = $true
        $ordered.Add($p)
    }
}

[string]::Join(",", $ordered)
