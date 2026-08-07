# Mirage C-Codebase Audit Report

**Date:** 2026-08-03
**Scope:** All C source files (src/, include/), excluding Go panel (panel/)
**Lines analyzed:** ~17,400 across 64 .c files + 30+ .h files

---

## Executive Summary

**Overall health: 6/10** — code is functional and well-structured, but has systematic security gaps (plaintext strings in .rdata) and several real bugs.

| Severity | Count |
|----------|-------|
| 🔴 Critical | 15 |
| 🟠 High | 12 |
| 🟡 Medium | 14 |
| 🟢 Low | 8 |

**Top 3 Priorities:**
1. Plaintext DLL/function names in ~30 locations defeat the entire PEB-walk anti-detection strategy
2. 12+ subsystem files use direct IAT imports (clipboard, keylogger, screenshot, inject, grabber, gaming, vpn)
3. 3 real bugs: mutex broken, system_info stack smash, schannel buffer overflow

---

## 🔴 Critical Findings

### C1. Plaintext DLL names in PEB-walk calls (~30 locations)
The `mirage_encrypted_hash_module("kernel32.dll")` pattern XOR-encrypts the string at runtime before hashing — but **the raw plaintext string literal remains in .rdata** and is trivially found by `strings(1)`, YARA rules, or DIE.

**Files:** browser_paths.c:458,536,733,1009 · cdp_grabber.c:280,342,343 · chromium.c:127,318,333,495,500 · elevator.c:104-107 · detection.c:62,84,100,131,160 · amsi_bypass.c:148 · etw_bypass.c:101 · telegram_tdata.c:94,105,403 · telegram_web.c:33,101 · schannel.c:126 · persistence.c:56,62,67 · self_delete.c:45 · temp_wipe.c:31 · engine.c:171,265

**Fix:** Store DLL names as XOR-encrypted byte arrays (like `MIRAGE_STRING_KEY_ENC`), decrypt at runtime before hashing. The polymorphic build system (`make_polymorphic.py`) should regenerate these arrays per build.

---

### C2. Direct Win32 IAT imports in 12+ subsystem files
These files call Win32 APIs directly — they appear in the Import Address Table and are immediate detection flags:

| File | APIs imported directly |
|------|----------------------|
| `src/system/clipboard.c` | OpenClipboard, GetClipboardData, GlobalLock, GlobalUnlock, CloseClipboard |
| `src/system/keylogger.c` | SetWindowsHookExW, GetKeyState, GetForegroundWindow, ~20 others |
| `src/system/screenshot.c` | GetDC, CreateCompatibleDC, BitBlt, GetDIBits, ~10 others |
| `src/system/inject.c` | CreateProcessA, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, GetModuleHandleA, GetProcAddress |
| `src/system/grabber.c` | CreateFileA, ReadFile, WriteFile, CreateDirectoryA |
| `src/system/seed_grabber.c` | FindFirstFileA, CreateFileA, ReadFile, HeapAlloc |
| `src/system/twofa.c` | CreateDirectoryA, CreateFileA, FindFirstFileA, GetFileAttributesA |
| `src/system/passman.c` | CreateFileA, ReadFile, CreateDirectoryA, FindFirstFileA, HeapAlloc |
| `src/system/gaming.c` | RegOpenKeyExA, RegQueryValueExA, CreateDirectoryA, FindFirstFileA, CopyFileA |
| `src/system/vpn.c` | FindFirstFileA, FindNextFileA, CopyFileA, CreateDirectoryA |
| `src/system/system_info.c` | GetModuleHandleW, GetProcAddress, GetComputerNameW |
| `src/messengers/messengers.c` | FindFirstFileA, FindNextFileA, FindClose |
| `src/crypto/appbound.c` | LoadLibraryA, GetProcAddress ×4 |
| `src/evasion/defender_disable.c` | RegOpenKeyExW, RegCreateKeyExW, RegSetValueExW, RegDeleteKeyW |
| `src/evasion/uac_bypass.c` | RegOpenKeyExW, RegCreateKeyExW, RegSetValueExW |
| `src/network/panel_http.c` | Multiple Win32 file APIs |
| `src/network/socks5.c` | Direct socket APIs |
| `src/network/proxy.c` | Direct file APIs |

**Fix:** Each file needs the same PEB-walk treatment as chromium.c/elevator.c: resolve all APIs via `mirage_get_module_by_hash` + `mirage_get_function_by_hash` at runtime.

---

### C3. Mutex single-instance check is BROKEN
**File:** `src/evasion/mutex.c:90-91`
```c
/* Keep the handle open for the lifetime of the process. */
mirage_NtClose(event_handle);  // BUG: closes immediately!
return 1;
```
**Fix:** Store `event_handle` in a `static HANDLE` variable. Do NOT call NtClose.

---

### C4. system_info.c stack smash — GetComputerNameW into char buffer
**File:** `src/system/system_info.c:28-29`
```c
char buf[256];
GetComputerNameW((LPWSTR)buf, &size);  // Writes WCHAR (2 bytes) into char buffer
```
**Fix:** Use `GetComputerNameA` or allocate a `WCHAR` buffer and convert.

---

### C5. AppBound placeholder keys are all-zero
**File:** `src/crypto/appbound.c:155-157`
```c
static const unsigned char FLAG1_KEY[32]      = {0};
static const unsigned char FLAG2_KEY[32]      = {0};
static const unsigned char FLAG3_XOR_KEY[32]  = {0};
```
**Fix:** Add `static_assert(FLAG1_KEY[0] != 0, "keys must be patched")` or runtime check.

---

### C6. Schannel buffer overflow in copy_to_wide
**File:** `src/network/schannel.c:~163`
Bounds check uses character index but write uses byte offset (×2 for wide chars). Hostnames >256 chars cause stack corruption.
**Fix:** Check `i*2 + 1 < dst_cap`.

---

### C7. SQLite read_record — OOB read on malformed DB
**File:** `src/parsers/sqlite.c:~265`
No check `pos+sz <= cell_max` before reading column data.
**Fix:** Add bounds check.

---

### C8. Plaintext domain strings in proxy.c
**File:** `src/network/proxy.c:9-12` — `api.github.com`, `t.me` and paths are plaintext.
**Fix:** XOR-encrypt at compile time.

---

### C9. Plaintext HTTP endpoints in panel_http.c / chunked.c
`----MirageBoundary`, `/api/log`, `Zialfi` codename in boundary strings.
**Fix:** XOR-encrypt all HTTP headers, boundaries, API paths.

---

### C10. Plaintext registry paths in evasion code
`defender_disable.c`, `uac_bypass.c`, `gaming.c` have wide-string registry paths in .rdata.
**Fix:** XOR-encrypt all registry path strings.

---

### C11. Plaintext persistence names + default C2 token
`"MirageUpdate"`, `"WindowsHelper.exe"`, `"WindowsUpdate"` in persistence.c. `"changeme"` default C2 token in config.h.
**Fix:** XOR-encrypt names. Fail build if default token not changed.

---

### C12. ws2.c struct overwrite bug
`*((SOCKET*)ws) = s` overwrites from offset 0, potentially clobbering `initialized` field.
**Fix:** Use proper struct field assignment.

---

### C13. panel_http.c Content-Length overflow
No overflow guard on `archive_len + strlen(metadata) + 100`.
**Fix:** Add overflow check.

---

### C14. hash.c stack overflow on long input
`uint8_t buf[256]` — if input >256 chars, XOR encrypt overflows stack.
**Fix:** Add length cap.

---

### C15. rt_mem.c realloc leak
`HeapReAlloc` failure returns NULL but original ptr is lost.
**Fix:** Save original pointer before call.

---

## 🟠 High Findings

| ID | File | Issue |
|----|------|-------|
| H1 | cdp_grabber.c:366,370 | Hardcoded port range 9222-9230, should be in config |
| H2 | defender_disable.c, uac_bypass.c, gaming.c | Direct registry API calls (RegOpenKeyExW etc.) |
| H3 | browser_paths.c:85 | 58 browser names as plaintext strings |
| H4 | schannel.c:~310 | 64KB stack buffer `msg[0x10000]` — overflow risk |
| H5 | telegram_tdata.c:216 | strncpy truncation without null-termination |
| H6 | sqlite.c:~56 | read_varint boundary over-count |
| H7 | schannel.c | No certificate pinning — MITM possible |
| H8 | cdp_grabber.c:50,54 | Sequence-point UB (`out[i++] = p[i++]`) |
| H9 | appbound.c:422 | const-correctness violation (secure_zero on const ptr) |
| H10 | defender_disable.c, uac_bypass.c | Plaintext wide registry paths |
| H11 | config.h:150 | Default C2 token "changeme" |
| H12 | cdp_grabber.c:83 | pLoadLibraryA typedef — IAT-adjacent |

---

## 🟡 Medium Findings

| ID | File | Issue |
|----|------|-------|
| M1 | firefox.c:210, wifi.c:10,18 | TODO stubs in production |
| M2 | sqlite.c:381 | Bare printf() not guarded by dbg_printf |
| M3 | rt_conv.c:~30 | strtol overflow on -LONG_MIN |
| M4 | rt_conv.c:~67 | getenv not thread-safe |
| M5 | base64.c:~55 | Malformed input not detected |
| M6 | proxy.c:~43 | Memory leak in repeated calls |
| M7 | panel_http.c:~70 | HTTP 200 detection too naive |
| M8 | config.h:143 | Hardcoded injection target "notepad.exe" |
| M9 | rt_snprintf.c:~270-320 | Dead code (console output functions) |
| M10 | ~50 locations | Plaintext function names in PEB-walk resolve calls |
| M11 | appbound.c:179-188 | LoadLibraryA + GetProcAddress (IAT) |
| M12 | inject.c:115,122 | GetModuleHandleA + GetProcAddress (IAT) |
| M13 | config.h | Polymorphic values stale if make_polymorphic.py not run |
| M14 | cdp_grabber.c:420 | Hardcoded localhost in WS URL |

---

## 🟢 Low Findings

| ID | File | Issue |
|----|------|-------|
| L1 | proxy.c | Placeholder comment (acknowledged tech debt) |
| L2 | rt_snprintf.c | Dead console output functions (~2KB wasted) |
| L3 | base64.c | Excess array initializer warnings |
| L4 | amsi_bypass.c, etw_bypass.c | Macro redefinition (EXCEPTION_SINGLE_STEP) |
| L5 | Multiple | -Wformat-truncation warnings (by design) |
| L6 | browser_paths.c | 58 browser names as display strings |
| L7 | appbound.c:378 | Unused variable `err` |
| L8 | cdp_grabber.c:254 | Unused variable `httpOnly` |

---

## Positive Observations ✅

1. **engine.c** — Halo's Gate + Tartarus Gate + SSN XOR obfuscation is well-implemented
2. **peb.c** — PEB walk correctly uses InMemoryOrderModuleList with 0x10 offset
3. **export_resolve.c** — correctly handles forwarded exports
4. **hash.c** — implementations are correct with proper rotl32 + multiply-add pipeline
5. **rt_mem.c** — memcpy/memmove/memset/memcmp handle overlapping regions correctly
6. **rt_snprintf.c** — supports full printf-family format set
7. **sqlite.c** — custom parser correctly handles B-tree page types
8. **secure_zero.c** — correctly uses volatile writes
9. **chromium.c** — 4-tier locked-file cascade is robust
10. **telegram_web.c** — clean implementation with proper bounds checking

---

## Prioritized Action Plan

### Quick Wins (< 1 day each) — Fix 8 bugs
1. Fix mutex bug (C3) — store handle in static variable
2. Fix system_info.c stack smash (C4) — use GetComputerNameA
3. Fix ws2.c struct overwrite (C12) — proper field assignment
4. Fix realloc leak (C15) — save original pointer
5. Fix cdp_grabber.c sequence-point UB (H8) — temp variables
6. Fix bare printf in sqlite.c (M2) — change to dbg_printf
7. Fix appbound.c const violation (H9) — remove const
8. Add static_assert for zero keys (C5)

### Medium-term (1-3 days each) — XOR-encrypt everything
9. XOR-encrypt DLL names (C1) — make_polymorphic.py integration
10. XOR-encrypt function names (M10) — same tooling
11. XOR-encrypt registry paths (C10, H10) — same tooling
12. XOR-encrypt HTTP endpoints (C8, C9) — proxy.c, panel_http.c, chunked.c
13. XOR-encrypt persistence names (C11) — config.h values
14. Fix SQLite bounds check (C7)
15. Fix schannel buffer overflow (C6)

### Long-term (> 3 days each) — PEB-walk all subsystems
16. PEB-walk for all 12+ subsystem files (C2) — massive but critical
17. Certificate pinning (H7) — schannel.c
18. Remove dead code (M9, L2) — rt_snprintf console functions
19. Default C2 token enforcement (C11) — fail build if unchanged
