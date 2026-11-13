# Read-only gate for reconkit. Runs the four checks in order, prints
# <name>=PASS / <name>=FAIL, then ALL CHECKS PASS or CHECKS FAILED.
# It installs nothing and modifies nothing.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    $python = "python"
}

$failed = $false

function Invoke-Gate {
    param(
        [string]$Name,
        [string[]]$Arguments
    )
    & $python @Arguments
    if ($LASTEXITCODE -eq 0) {
        Write-Output "$Name=PASS"
    }
    else {
        Write-Output "$Name=FAIL"
        $script:failed = $true
    }
}

Invoke-Gate -Name "pytest" -Arguments @("-m", "pytest", "-q")
Invoke-Gate -Name "ruff-check" -Arguments @("-m", "ruff", "check", ".")
Invoke-Gate -Name "ruff-format" -Arguments @("-m", "ruff", "format", "--check", ".")
Invoke-Gate -Name "mypy" -Arguments @("-m", "mypy", "src/reconkit")

# Regression rule: a fix commit must change at least one test file.
$subject = (git log -1 --format=%s)
$changed = git show --name-only --format= HEAD
if ($subject -like "fix:*" -and -not ($changed | Where-Object { $_ -like "tests/*" })) {
    Write-Output "WARN: fix commit without a test change"
}

if ($failed) {
    Write-Output "CHECKS FAILED"
    exit 1
}

Write-Output "ALL CHECKS PASS"
exit 0
