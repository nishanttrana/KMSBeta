param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$InstallArgs
)

$ErrorActionPreference = "Stop"

function Convert-ToBashSingleQuoted {
    param([string]$Value)
    return "'" + $Value.Replace("'", "'""'""'") + "'"
}

function Convert-ToMsysPath {
    param([string]$Value)

    $normalized = $Value -replace '\\', '/'
    if ($normalized -match '^([A-Za-z]):/(.*)$') {
        return "/$($matches[1].ToLowerInvariant())/$($matches[2])"
    }
    return $normalized
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$installScript = Join-Path $scriptDir "install.sh"

if (-not (Test-Path $installScript)) {
    throw "install.sh not found in $scriptDir"
}

$argString = ""
if ($InstallArgs -and $InstallArgs.Count -gt 0) {
    $argString = ($InstallArgs | ForEach-Object { Convert-ToBashSingleQuoted -Value $_ }) -join " "
}

$gitBashCandidates = @(
    "C:\Program Files\Git\bin\bash.exe",
    "C:\Program Files (x86)\Git\bin\bash.exe"
)
$gitBash = $gitBashCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($gitBash) {
    Write-Host "[INFO] Using Git Bash with Windows host networking detection..."
    $msysDir = Convert-ToMsysPath -Value $scriptDir
    $cmd = "export INSTALLER_FORCE_HOST_OS=windows; cd $(Convert-ToBashSingleQuoted -Value $msysDir); chmod +x ./install.sh; ./install.sh $argString"
    & $gitBash -lc $cmd
    exit $LASTEXITCODE
}

if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
    Write-Host "[INFO] Using WSL with Windows host networking detection..."
    $wslDir = (& wsl.exe wslpath -a $scriptDir).Trim()
    if ([string]::IsNullOrWhiteSpace($wslDir)) {
        throw "Unable to resolve WSL path for $scriptDir"
    }

    $cmd = "export INSTALLER_FORCE_HOST_OS=windows; cd $(Convert-ToBashSingleQuoted -Value $wslDir); chmod +x ./install.sh; ./install.sh $argString"
    & wsl.exe bash -lc $cmd
    exit $LASTEXITCODE
}

throw "No compatible shell found. Install Git for Windows (Git Bash) or WSL, then run install-windows.ps1 again."
