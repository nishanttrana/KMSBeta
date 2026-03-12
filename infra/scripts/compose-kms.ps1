param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ComposeArgs
)

$ErrorActionPreference = "Stop"

$root = if ($env:KMS_ROOT_DIR) {
    $env:KMS_ROOT_DIR
} else {
    (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

$composeFile = Join-Path $root "docker-compose.yml"
$staticOverrideFile = Join-Path $root "docker-compose.override.yml"
$platformOverrideFile = Join-Path $root ".tmp_compose.platform.override.yml"

function Get-DockerCommandSpec {
    if ([string]::IsNullOrWhiteSpace($env:KMS_DOCKER_BIN)) {
        return @("docker")
    }

    return @($env:KMS_DOCKER_BIN -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
}

$dockerSpec = Get-DockerCommandSpec
$dockerExe = $dockerSpec[0]
$dockerPrefix = @()
if ($dockerSpec.Count -gt 1) {
    $dockerPrefix = $dockerSpec[1..($dockerSpec.Count - 1)]
}

function Invoke-DockerCapture {
    param([string[]]$Args)

    $output = & $dockerExe @dockerPrefix @Args 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    return ($output -join "`n")
}

function Get-HostPlatform {
    switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()) {
        "arm64" { return "linux/arm64/v8" }
        "x64" { return "linux/amd64" }
        default {
            $detected = Invoke-DockerCapture -Args @("version", "--format", "{{.Server.Os}}/{{.Server.Arch}}")
            if ([string]::IsNullOrWhiteSpace($detected)) {
                return "linux/amd64"
            }
            return $detected.Trim()
        }
    }
}

function Normalize-Platform {
    param([string]$Platform)

    if ([string]::IsNullOrWhiteSpace($Platform) -or $Platform -eq "/") {
        return Get-HostPlatform
    }

    if ($Platform -eq "linux/arm64" -or $Platform -eq "linux/aarch64") {
        return "linux/arm64/v8"
    }

    return $Platform.Trim()
}

function Get-ImagePlatform {
    param([string]$Image)

    $detected = Invoke-DockerCapture -Args @("image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", $Image)
    return Normalize-Platform -Platform $detected
}

function Update-PlatformOverride {
    if (!(Test-Path -LiteralPath $composeFile)) {
        return
    }

    $composeConfigArgs = @("compose", "-f", $composeFile)
    if (Test-Path -LiteralPath $staticOverrideFile) {
        $composeConfigArgs += @("-f", $staticOverrideFile)
    }

    $configText = Invoke-DockerCapture -Args ($composeConfigArgs + @("config"))
    if ([string]::IsNullOrWhiteSpace($configText)) {
        Remove-Item -LiteralPath $platformOverrideFile -Force -ErrorAction SilentlyContinue
        return
    }

    $serviceImageMap = [ordered]@{}
    $inServices = $false
    $currentService = $null
    foreach ($line in $configText -split "`r?`n") {
        if ($line -match '^services:\s*$') {
            $inServices = $true
            $currentService = $null
            continue
        }
        if ($inServices -and $line -match '^[^\s]') {
            $inServices = $false
            $currentService = $null
        }
        if (-not $inServices) {
            continue
        }
        if ($line -match '^  ([A-Za-z0-9_.-]+):\s*$') {
            $currentService = $Matches[1]
            continue
        }
        if ($currentService -and $line -match '^    image:\s*(.+)\s*$') {
            $imageRef = $Matches[1].Trim()
            $imageRef = $imageRef.Trim("'")
            $imageRef = $imageRef.Trim('"')
            $serviceImageMap[$currentService] = $imageRef
        }
    }

    $hostPlatform = Get-HostPlatform
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($entry in $serviceImageMap.GetEnumerator()) {
        $platform = Get-ImagePlatform -Image $entry.Value
        if ([string]::IsNullOrWhiteSpace($platform) -or $platform -eq $hostPlatform) {
            continue
        }
        if ($lines.Count -eq 0) {
            $lines.Add("services:")
        }
        $lines.Add("  $($entry.Key):")
        $lines.Add("    platform: $platform")
    }

    if ($lines.Count -eq 0) {
        Remove-Item -LiteralPath $platformOverrideFile -Force -ErrorAction SilentlyContinue
        return
    }

    Set-Content -LiteralPath $platformOverrideFile -Value $lines
}

Update-PlatformOverride

$composeInvocationArgs = @("compose", "-f", $composeFile)
if (Test-Path -LiteralPath $staticOverrideFile) {
    $composeInvocationArgs += @("-f", $staticOverrideFile)
}
if (Test-Path -LiteralPath $platformOverrideFile) {
    $composeInvocationArgs += @("-f", $platformOverrideFile)
}
$composeInvocationArgs += $ComposeArgs

& $dockerExe @dockerPrefix @composeInvocationArgs
exit $LASTEXITCODE
