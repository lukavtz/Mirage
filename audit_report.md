# Mirage v3 — Full Header + Config + Grep Audit Report

## 1. Plaintext DLL Names (`.dll"`) — CRITICAL

All DLL names passed to `mirage_encrypted_hash_module()` are plaintext string literals in the binary's `.rdata` section. The function XOR-encrypts them at runtime before hashing, **but the raw strings are still visible in the binary** to any static scanner.

### Affected locations (ALL files using `mirage_encrypted_hash_module("*.dll")`):

| File | Line(s) | Plaintext DLL |
|------|---------|---------------|
| `src/browsers/browser_paths.c` | 458, 536, 733, 1009 | `kernel32.dll`, `ntdll.dll` |
| `src/browsers/cdp_grabber.c` | 280, 342, 343 | `ntdll.dll`, `kernel32.dll`, `user32.dll` |
| `src/browsers/chromium.c` | 127, 318, 333, 495, 500 | `ntdll.dll`, `rstrtmgr.dll`, `advapi32.dll`, `kernel32.dll` |
| `src/cleanup/persistence.c` | 56, 62, 67 | `kernel32.dll`, `ntdll.dll`, `advapi32.dll` |
| `src/cleanup/self_delete.c` | 45 | `kernel32.dll` |
| `src/cleanup/temp_wipe.c` | 31 | `kernel32.dll` |
| `src/crypto/elevator.c` | 104–107 | `ntdll.dll`, `kernel32.dll`, `user32.dll`, `advapi32.dll` |
| `src/evasion/amsi_bypass.c` | 148 | `ntdll.dll` |
| `src/evasion/detection.c` | 62, 84, 100, 131, 160 | `kernel32.dll`, `user32.dll` |
| `src/evasion/etw_bypass.c` | 101 | `ntdll.dll` |
| `src/messengers/telegram_tdata.c` | 94, 105, 403 | `kernel32.dll`, `ntdll.dll` |
| `src/messengers/telegram_web.c` | 33, 101 | `kernel32.dll` |
| `src/network/schannel.c` | 126 | `kernel32.dll` |
| `src/syscalls/engine.c` | 171, 265 | `ntdll.dll` |

**Severity**: CRITICAL — string-scanning tools (YARA, Detect-It-Easy) will find these immediately.

---

## 2. Direct WinAPI Calls (IAT Imports) — CRITICAL

These bypass PEB-walk entirely and appear in the Import Address Table:

| File | Line | Call | Impact |
|------|------|------|--------|
| `src/crypto/appbound.c` | 179 | `LoadLibraryA("ncrypt.dll")` | Plaintext DLL name + IAT import |
| `src/crypto/appbound.c` | 182–188 | `GetProcAddress()` ×4 | IAT import for `GetProcAddress` |
| `src/system/inject.c` | 115 | `GetModuleHandleA("kernel32.dll")` | Plaintext DLL + IAT import |
| `src/system/inject.c` | 122 | `GetProcAddress(kernel32, "LoadLibraryA")` | IAT import |
| `src/system/system_info.c` | 13 | `GetModuleHandleW(L"ntdll.dll")` | Plaintext DLL + IAT import |
| `src/system/system_info.c` | 16 | `GetProcAddress(ntdll, "RtlGetVersion")` | IAT import |
| `src/evasion/peb_hide.c` | 13 | `GetModuleHandleW(NULL)` | IAT import (own module, lower risk) |
| `src/system/keylogger.c` | 278 | `GetModuleHandleW(NULL)` | IAT import (own module, lower risk) |
| `src/syscalls/engine.c` | 267 | `GetModuleHandleA("ntdll.dll")` | Fallback path, plaintext + IAT |
| `src/syscalls/engine.c` | 347, 355 | `GetModuleHandleA` + `GetProcAddress` | Obfuscated path but still IAT |

**Severity**: CRITICAL — `GetModuleHandleA/W`, `LoadLibraryA`, `GetProcAddress` in the IAT are immediate detection flags.

---

## 3. Direct WinAPI Registry Calls (IAT Imports) — HIGH

| File | Line(s) | Calls |
|------|---------|-------|
| `src/evasion/defender_disable.c` | 19, 24, 30, 35, 49, 57, 62 | `RegOpenKeyExW`, `RegSetValueExW`, `RegCloseKey` |
| `src/evasion/uac_bypass.c` | 34, 45, 51, 73, 75 | `RegCreateKeyExW`, `RegSetValueExW`, `RegDeleteKeyW`, `RegCloseKey` |
| `src/system/gaming.c` | 52 | `RegOpenKeyExA` |

**Severity**: HIGH — should use PEB-walk resolved `NtOpenKey`/`NtSetValueKey` or resolve `RegOpenKeyExW` via hash. `persistence.c` correctly does this; `defender_disable.c`, `uac_bypass.c`, and `gaming.c` do not.

---

## 4. Plaintext Registry Paths — HIGH

| File | Line | Path |
|------|------|------|
| `src/evasion/defender_disable.c` | 20 | `L"SOFTWARE\\Policies\\Microsoft\\Windows Defender"` |
| `src/evasion/defender_disable.c` | 31 | `L"SYSTEM\\CurrentControlSet\\Services\\WinDefend"` |
| `src/evasion/defender_disable.c` | 50 | `L"SOFTWARE\\Policies\\Microsoft\\Windows Defender"` |
| `src/evasion/defender_disable.c` | 58 | `L"SYSTEM\\CurrentControlSet\\Services\\WinDefend"` |
| `src/evasion/uac_bypass.c` | 36 | `L"Software\\Classes\\ms-settings\\Shell\\Open\\Command"` |
| `src/evasion/uac_bypass.c` | 53 | `L"Software\\Classes\\ms-settings\\Shell\\Open\\Command\\DelegateExecute"` |
| `src/evasion/uac_bypass.c` | 74–76 | Same paths (cleanup) |
| `src/system/gaming.c` | 52 | `"Software\\Valve\\Steam"` |
| `src/browsers/cdp_grabber.c` | 286 | `L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\chrome.exe"` |
| `src/browsers/browser_paths.c` | 759 | `"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths"` |
| `src/messengers/telegram_tdata.c` | 407 | `"\\Registry\\Machine\\SOFTWARE\\Classes"` |

**Severity**: HIGH — should be XOR-encrypted static data, decrypted at runtime.

---

## 5. Plaintext Domains/URLs — HIGH

| File | Line | String |
|------|------|--------|
| `src/network/proxy.c` | 11 | `"api.github.com"` — **should be XOR-encrypted** |
| `src/network/proxy.c` | 13 | `"t.me"` — **should be XOR-encrypted** |
| `src/messengers/telegram_web.c` | 465 | `"https://web.telegram.org"` — in JSON output (acceptable) |

**Severity**: HIGH for proxy.c lines 11, 13. The comment on line 8 even says "Placeholder definitions... replace with real XOR blobs" — this was never completed.

---

## 6. Plaintext IP Addresses — LOW (localhost)

| File | Line | IP | Context |
|------|------|-----|---------|
| `include/config.h` | 137 | `"127.0.0.1"` | SOCKS5_HOST (Tor) — placeholder |
| `include/config.h` | 148 | `"127.0.0.1"` | C2_HOST — placeholder |
| `src/browsers/cdp_grabber.c` | 422 | `"127.0.0.1"` | Chrome DevTools localhost |
| `src/cleanup/self_delete.c` | 225 | `"127.0.0.1"` | ping delay trick |
| `src/network/socks5.c` | 209 | `"127.0.0.1"` | Tor proxy |

**Severity**: LOW — all localhost. But `C2_HOST` and `SOCKS5_HOST` are placeholders that must be overridden before deployment.

---

## 7. Hardcoded Ports — LOW (config-driven)

| File | Line | Port | Context |
|------|------|------|---------|
| `include/config.h` | 138 | 9050 | SOCKS5_PORT (Tor default) |
| `include/config.h` | 149 | 9999 | C2_PORT (placeholder) |
| `src/browsers/cdp_grabber.c` | 9222–9230 | Chrome DevTools range | Dynamic, acceptable |

**Severity**: LOW — config-driven. The `#define` values are placeholders.

---

## 8. Debug/TODO Remnants — MEDIUM

| File | Line | Finding |
|------|------|---------|
| `src/browsers/firefox.c` | 210 | `TODO: implement full key3.db decryption` |
| `src/system/wifi.c` | 10 | `TODO: implement WiFi profile enumeration via netsh` |
| `src/system/wifi.c` | 18 | `TODO: implement via WlanEnumInterfaces + WlanGetProfile` |
| `src/parsers/sqlite.c` | 381 | **Bare `printf()`** — not guarded by `dbg_printf` |

**Severity**: MEDIUM — the `printf` in sqlite.c will link against CRT and may cause linker errors with `-nostdlib`, or print to stdout in production. The TODOs indicate unimplemented features.

---

## 9. Plaintext Persistence Artifact Names — MEDIUM

| File | Line | String |
|------|------|--------|
| `src/cleanup/persistence.c` | 37 | `PERSIST_VAL_NAME "MirageUpdate"` |
| `src/cleanup/persistence.c` | 38 | `PERSIST_STARTUP_FILE "WindowsHelper.exe"` |
| `src/cleanup/persistence.c` | 39 | `PERSIST_TASK_NAME "WindowsUpdate"` |
| `include/config.h` | 143 | `INJECT_TARGET "notepad.exe"` |
| `include/config.h` | 150 | `C2_TOKEN "changeme"` |

**Severity**: MEDIUM — these are string literals visible in the binary. Persistence names should be XOR-encrypted. `C2_TOKEN "changeme"` is a default credential.

---

## 10. Plaintext `advapi32.dll` Wide String — MEDIUM

| File | Line | String |
|------|------|--------|
| `src/cleanup/persistence.c` | 77 | `static const WCHAR dllname[] = L"advapi32.dll"` |

This is passed to `LdrLoadDll` via `UNICODE_STRING`. The wide string is in `.data` section.

**Severity**: MEDIUM — should be XOR-encrypted, decrypted at runtime.

---

## 11. Header Guard Inconsistency — LOW

Three naming conventions are mixed:

| Convention | Headers |
|------------|---------|
| `MIRAGE_*_H` | `nt_types.h`, `peb.h`, `hash.h`, `export_resolve.h`, `chrome_key.h`, `peb_hide.h`, `mutex.h`, `mirage_asm.h`, `secure_zero.h`, `amsi_bypass.h`, `etw_bypass.h`, `detection.h`, `evasion.h`, `anti_analysis.h`, `defender_disable.h`, `telegram_web.h`, `telegram_tdata.h` |
| `ZIALFI_*_H` | `ws2.h`, `socks5.h`, `schannel.h`, `chunked.h`, `proxy.h`, `persistence.h`, `self_delete.h`, `temp_wipe.h`, `inject.h` |
| Plain name | `config.h` (`CONFIG_H`), `sqlite.h` (`SQLITE_H`), `browser_paths.h` (`BROWSER_PATHS_H`), `chromium.h` (`CHROMIUM_H`), `wallets.h` (`WALLETS_H`), `messengers.h` (`MESSENGERS_H`), `firefox.h` (`FIREFOX_H`), `firefox_crypto.h` (`FIREFOX_CRYPTO_H`), `wallet_ext.h` (`WALLET_EXT_H`), `wallet_desktop.h` (`WALLET_DESKTOP_H`), `keylogger.h` (`KEYLOGGER_H`), `grabber.h` (`GRABBER_H`), `screenshot.h` (`SCREENSHOT_H`), `clipboard.h` (`CLIPBOARD_H`), `seed_grabber.h` (`SEED_GRABBER_H`), `clipper.h` (`CLIPPER_H`), `vpn.h` (`VPN_H`), `wifi.h` (`WIFI_H`), `gaming.h` (`GAMING_H`), `twofa.h` (`TWOFA_H`), `passman.h` (`PASSMAN_H`), `system_info.h` (`SYSTEM_INFO_H`), `cdp_grabber.h` (`CDP_GRABBER_H`), `appbound.h` (`APPBOUND_H`), `chrome_crypto.h` (`CHROME_CRYPTO_H`), `dpapi_unprotect.h` (`DPAPI_UNPROTECT_H`), `chacha_poly.h` (`CHACHA_POLY_H`), `archive_crypt.h` (`ARCHIVE_CRYPT_H`) |

Also `config.h:1` comment says "zialfi stealer" — should say "Mirage".

**Severity**: LOW — no functional impact, but inconsistent naming.

---

## 12. `gadget_pool` Type Mismatch — LOW

| File | Line | Declaration |
|------|------|-------------|
| `include/engine.h` | 66 | `extern uintptr_t gadget_pool[64]` |
| `include/mirage_asm.h` | 57 | `extern uint64_t gadget_pool[64]` |
| `asm/mirage_stubs_v2.asm` | 98 | `gadget_pool: times 64 dq 0` (64-bit) |

Compatible on x64 (`uintptr_t` = `uint64_t`), but the mismatch is a maintenance hazard.

**Severity**: LOW — no runtime issue on x64, but should be unified.

---

## 13. `#pragma comment(lib, ...)` — LOW

These MSVC pragmas are ignored by MinGW but shouldn't be in a no-CRT binary:

| File | Line | Pragma |
|------|------|--------|
| `src/crypto/chrome_crypto.c` | 20–21 | `crypt32.lib`, `bcrypt.lib` |
| `src/crypto/firefox_crypto.c` | 19 | `bcrypt.lib` |
| `src/network/chunked.c` | 11 | `advapi32.lib` |
| `src/network/panel_http.c` | 13 | `ws2_32.lib` |
| `src/network/socks5.c` | 10 | `ws2_32.lib` |
| `src/network/ws2.c` | 10 | `ws2_32.lib` |

**Severity**: LOW — MinGW ignores these, but they're dead code.

---

## 14. `#include <stdio.h>` in No-CRT Binary — LOW

28 source files include `<stdio.h>`. With `-nostdlib`, MinGW provides its own headers that declare `printf`, `snprintf`, etc. without pulling in msvcrt. The project has custom implementations in `rt/rt_snprintf.c`. This works because MinGW headers are declaration-only, but it's fragile — any accidental use of `fopen`, `fread`, `fwrite` from `<stdio.h>` would pull in CRT symbols.

The project correctly uses its own `rt_snprintf.c` implementations and guards `FILE*` operations behind its own wrappers.

**Severity**: LOW — works correctly with current MinGW, but fragile.

---

## 15. Include Dependency: `<windows.h>` in Headers — LOW

| Header | Line | Issue |
|--------|------|-------|
| `include/engine.h` | 10 | `#include <windows.h>` — pulls in all Win32 types |
| `include/inject.h` | 9 | `#include <windows.h>` — pulls in all Win32 types |
| `include/schannel.h` | 7 | `#include <windows.h>` — pulls in all Win32 types |

These headers pull in the massive `<windows.h>` when included. `nt_types.h` correctly provides minimal type definitions. `engine.h`, `inject.h`, and `schannel.h` should use forward declarations or include `nt_types.h` instead.

**Severity**: LOW — no detection impact, but pulls in unnecessary definitions.

---

## 16. Makefile Audit — OK

The Makefile uses:
- `x86_64-w64-mingw32-gcc` — correct cross-compiler
- `-nostdlib` — correct for no-CRT
- `-Wl,-e,mainCRTStartup` — correct entry point
- `-Wl,--gc-sections` with `-fdata-sections -ffunction-sections` — correct dead code elimination
- Links: `ws2_32`, `kernel32`, `user32`, `advapi32`, `bcrypt`, `crypt32`, `shell32`, `ole32`, `oleaut32`, `gdi32`
- NASM for ASM stubs
- Polymorphic build target
- Unit test targets with native gcc

**No issues found** in the Makefile itself.

---

## 17. ASM File Audit — OK

`asm/mirage_stubs_v2.asm`:
- Correct `bits 64` / `default rel`
- `getPeb` reads from `gs:0x60` (correct for x64 PEB)
- `___chkstk_ms` stack probe (required for `-nostdlib`)
- SSN storage in `.data` section with proper `extern ssn_xor_key`
- All syscall stubs: `mov r10, rcx` → `mov eax, [ssn]` → `xor eax, [xor_key]` → `syscall` → `ret`
- XOR key is `0xA3B5C7D9` (from `config.h:MIRAGE_SSN_XOR_KEY`)
- 31 syscall stubs matching `mirage_asm.h` declarations
- `gadget_pool` allocated but unused by v2 stubs (kept for engine.c compatibility)

**No issues found** in the ASM file.

---

## Summary by Severity

| Severity | Count | Category |
|----------|-------|----------|
| **CRITICAL** | 2 | Plaintext DLL names in binary; Direct WinAPI IAT imports |
| **HIGH** | 3 | Direct registry WinAPI calls; Plaintext registry paths; Plaintext domains |
| **MEDIUM** | 3 | TODO/unimplemented stubs; Bare `printf`; Plaintext persistence names |
| **LOW** | 6 | Header guards; Type mismatch; Pragmas; stdio.h; windows.h in headers; localhost IPs |
