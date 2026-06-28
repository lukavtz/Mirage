# Eidos Integration Test Runner
# Run: powershell -ExecutionPolicy Bypass -File scripts/run_integration_tests.ps1

$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptPath\.."
$StealerDir = "$ProjectRoot\Mirage.Stealer"

Write-Host "=== Eidos Integration Test Runner ===" -ForegroundColor Cyan
Write-Host "Project: $ProjectRoot" -ForegroundColor Gray
Write-Host ""

function Run-Test {
    param($Name, $ScriptBlock)
    Write-Host "[RUNNING] $Name..." -ForegroundColor Yellow
    $result = & $ScriptBlock
    if ($LASTEXITCODE -eq 0 -or $?) {
        Write-Host "[PASS] $Name" -ForegroundColor Green
        return $true
    } else {
        Write-Host "[FAIL] $Name" -ForegroundColor Red
        return $false
    }
}

$passed = 0
$failed = 0

# 1. Zig unit tests
Write-Host "`n=== Test Suite 1: Zig Unit Tests ===" -ForegroundColor Magenta
Set-Location $StealerDir
if (Run-Test "zig build test" { zig build test }) { $passed++ } else { $failed++ }

# 2. Release build
Write-Host "`n=== Test Suite 2: Release Build ===" -ForegroundColor Magenta
if (Run-Test "zig build (ReleaseSmall)" { zig build }) { $passed++ } else { $failed++ }

# 3. Size check
Write-Host "`n=== Test Suite 3: Binary Size ===" -ForegroundColor Magenta
$exePath = "$StealerDir\zig-out\bin\Mirage.exe"
if (Test-Path $exePath) {
    $size = (Get-Item $exePath).Length
    $sizeKB = [math]::Round($size / 1KB, 1)
    if ($sizeKB -lt 150) {
        Write-Host "[PASS] Size: $sizeKB KB < 150 KB" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "[FAIL] Size: $sizeKB KB >= 150 KB" -ForegroundColor Red
        $failed++
    }
} else {
    Write-Host "[SKIP] $exePath not found (run 'zig build' first)" -ForegroundColor Gray
}

# 4. Integration tests (build and run)
Write-Host "`n=== Test Suite 4: Integration Tests ===" -ForegroundColor Magenta
Set-Location $StealerDir
if (Run-Test "zig build integration-test" { zig build integration-test }) { $passed++ } else { $failed++ }

# 5. Debug tests (Mirage.exe -- runs assertions)
Write-Host "`n=== Test Suite 5: Debug Tests ===" -ForegroundColor Magenta
Set-Location $StealerDir
if (Run-Test "Mirage.exe debug tests" { & ".\zig-out\bin\Mirage.exe" }) { $passed++ } else { $failed++ }

# 6. Full pipeline test (using the integration test executable)
Write-Host "`n=== Test Suite 6: Integration Test Executable ===" -ForegroundColor Magenta
$intTestExe = "$StealerDir\zig-out\bin\MirageIntegrationTest.exe"
if (Test-Path $intTestExe) {
    if (Run-Test "MirageIntegrationTest.exe" { & $intTestExe }) { $passed++ } else { $failed++ }
} else {
    Write-Host "[SKIP] Integration test EXE not found" -ForegroundColor Gray
}

# Summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Results: $passed passed, $failed failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "========================================" -ForegroundColor Cyan

Set-Location $ProjectRoot
exit $failed
