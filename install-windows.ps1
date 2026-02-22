param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$InstallArgs
)

$ErrorActionPreference = "Stop"

function Convert-ToBashSingleQuoted {
    param([string]$Value)
    return "'" + $Value.Replace("'", "'""'""'") + "'"
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$installScript = Join-Path $scriptDir "install.sh"

if (-not (Test-Path $installScript)) {
    throw "install.sh not found in $scriptDir"
}

if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
    Write-Host "[INFO] Using WSL to run install.sh with the same prompt flow..."
    $wslDir = (& wsl.exe wslpath -a $scriptDir).Trim()
    if ([string]::IsNullOrWhiteSpace($wslDir)) {
        throw "Unable to resolve WSL path for $scriptDir"
    }

    $quotedDir = Convert-ToBashSingleQuoted -Value $wslDir
    $argString = ""
    if ($InstallArgs -and $InstallArgs.Count -gt 0) {
        $argString = ($InstallArgs | ForEach-Object { Convert-ToBashSingleQuoted -Value $_ }) -join " "
    }

    $cmd = "cd $quotedDir && chmod +x ./install.sh && ./install.sh $argString"
    & wsl.exe bash -lc $cmd
    exit $LASTEXITCODE
}

$gitBashCandidates = @(
    "C:\Program Files\Git\bin\bash.exe",
    "C:\Program Files (x86)\Git\bin\bash.exe"
)

$gitBash = $gitBashCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($gitBash) {
    Write-Host "[INFO] Using Git Bash to run install.sh with the same prompt flow..."
    & $gitBash $installScript @InstallArgs
    exit $LASTEXITCODE
}

throw "No compatible shell found. Install WSL (recommended) or Git for Windows (Git Bash), then run install-windows.ps1 again."
