<#
.SYNOPSIS
  net-audit Web Dashboard Launcher
  Installs Python (if needed), installs Flask, and starts the server.
#>

$ErrorActionPreference = "Stop"
$webappDir = $PSScriptRoot
$netauditDir = Split-Path $webappDir

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  net-audit Web Dashboard" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 1. Find Python
$python = $null
foreach ($candidate in @("python3", "python", "py")) {
    try {
        $ver = & $candidate --version 2>&1
        if ($ver -match "Python 3") { $python = $candidate; break }
    } catch {}
}

# 2. If not found, try to install via winget
if (-not $python) {
    Write-Host "Python not found. Attempting to install via winget..." -ForegroundColor Yellow
    try {
        winget install -e --id Python.Python.3.12 --silent --accept-source-agreements --accept-package-agreements
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH","User")
        $python = "python"
    } catch {
        Write-Host ""
        Write-Host "ERROR: Could not install Python automatically." -ForegroundColor Red
        Write-Host "Please install Python 3.10+ from https://python.org and rerun this script." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Alternatively, open net-audit-standalone.html in your browser for a" -ForegroundColor Cyan
        Write-Host "zero-install viewer that reads saved JSON report files." -ForegroundColor Cyan
        Read-Host "Press Enter to exit"
        exit 1
    }
}

Write-Host "Using: $python $(& $python --version 2>&1)" -ForegroundColor Green

# 3. Install Flask
Write-Host "Installing Flask..." -ForegroundColor Cyan
& $python -m pip install flask --quiet --upgrade

# 4. Build the binary if needed
$binaryName = if ($IsWindows) { "net-audit.exe" } else { "net-audit" }
$binary = Join-Path $netauditDir $binaryName
if (-not (Test-Path $binary)) {
    Write-Host "Building net-audit binary..." -ForegroundColor Yellow
    Push-Location $netauditDir
    $makeResult = & gcc -std=c11 -Wall -Wextra -Werror -pedantic -O2 -Iinclude `
        src/main.c src/common/safe_str.c src/common/model_init.c `
        src/parser/parser_registry.c src/parser/cisco_parser.c `
        src/parser/juniper_parser.c src/parser/fortinet_parser.c `
        src/engine/rule_engine.c src/engine/rules_table.c `
        src/report/report.c src/report/report_text.c `
        src/report/report_csv.c src/report/report_json.c `
        -o $binaryName 2>&1
    Pop-Location
    if (Test-Path $binary) {
        Write-Host "Binary built: $binary" -ForegroundColor Green
    } else {
        Write-Host "Warning: Could not build net-audit binary. Install GCC first." -ForegroundColor Yellow
        Write-Host $makeResult
    }
}

# 5. Open browser and start server
Write-Host ""
Write-Host "Starting server at http://localhost:5000" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop." -ForegroundColor Gray
Write-Host ""

Start-Process "http://localhost:5000"
Set-Location $webappDir
& $python app.py
