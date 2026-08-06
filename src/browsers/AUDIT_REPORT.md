# Mirage/src/browsers/ — Deep Audit Report

Audited files: chromium.c (2016 lines), firefox.c (1132 lines), browser_paths.c (1471 lines), cdp_grabber.c (545 lines), bp_tables_init.inc (518 lines).

---

## 1. Direct WinAPI Calls Bypassing PEB-walk

### 1.1 fopen() — CRT call, no PEB-walk

| File | Line | Call | Context |
|------|------|------|---------|
| chromium.c | 724 | fopen(path, "rb") | read_file() primary entry for ALL file reads |
| chromium.c | 1499 | fopen(mk_path, "wb") | ENABLE_RAW_EXPORT master key dump |
| chromium.c | 1513 | fopen(dst, "wb") | ENABLE_RAW_EXPORT raw DB copy |
| chromium.c | 1576 | fopen(db_path, "rb") | extract_chromium_cards() |
| chromium.c | 1745 | fopen(db_path, "rb") | extract_chromium_google_tokens() |
| chromium.c | 1827 | fopen(db_path, "rb") | extract_chromium_autofill() |
| chromium.c | 1951 | fopen(file_path, "rb") | extract_chromium_bookmarks() |
| firefox.c | 94 | fopen(path, "rb") | read_file() — all Firefox file I/O |
| cdp_grabber.c | 253 | fopen(output_path, "w") | write_netscape_cookies() |

Impact: fopen/fread/fwrite/fclose/fseek/ftell are CRT calls that resolve through msvcrt.dll IAT. In -nostdlib builds these are MinGW wrappers but still create predictable IAT entries. read_file() in chromium.c correctly falls back to section-mapping on failure, but the CRT calls themselves are IAT-visible.

### 1.2 fprintf() — CRT call

| File | Line | Call |
|------|------|------|
| cdp_grabber.c | 256 | fprintf(f, "# Netscape HTTP Cookie File\n") |
| cdp_grabber.c | 286 | fprintf(f, "%s\t%s\t%s\t%s\t%ld\t%s\t%s\n", ...) |

### 1.3 getenv() — CRT call, plaintext env var name

| File | Line | Call |
|------|------|------|
| browser_paths.c | 1338 | getenv("LOCALAPPDATA") |

Uses getenv() from CRT instead of GetEnvironmentVariableW via PEB-walk (which is correctly used elsewhere in the same file at line 917). Plaintext "LOCALAPPDATA" in .rdata.

### 1.4 strtod() — CRT call

| File | Line | Call |
|------|------|------|
| cdp_grabber.c | 82 | strtod(p, NULL) in json_extract_number() |

---

## 2. Plaintext String Literals

### 2.1 Plaintext SQLite table/column names (MEDIUM)

| File | Line | String |
|------|------|--------|
| chromium.c | 1037 | "logins" |
| chromium.c | 1055-1059 | "origin_url", "username_value", "password_value" |
| chromium.c | 1202 | "cookies" |
| chromium.c | 1211-1216 | "host_key", "name", "path", "encrypted_value", "expires_utc", "value" |
| chromium.c | 1347 | "urls" |
| chromium.c | 1355-1357 | "url", "title", "visit_count" |
| chromium.c | 1598 | "local_stored_cvc" |
| chromium.c | 1655 | "credit_cards" |
| chromium.c | 1767 | "token_service" |
| chromium.c | 1849 | "autofill" |
| firefox.c | 487 | "metaData" |
| firefox.c | 494 | "id", "item1" |
| firefox.c | 556 | "nssPrivate" |
| firefox.c | 834 | "moz_cookies" |
| firefox.c | 922 | "moz_places" |
| firefox.c | 338-345 | "global-salt", "password-check", "password" |

### 2.2 Plaintext browser profile/file names (MEDIUM)

| File | Line | String |
|------|------|--------|
| chromium.c | 818 | "Default" |
| chromium.c | 828 | "Profile %d" |
| chromium.c | 1018 | "Login Data" |
| chromium.c | 1170 | "Cookies", "Network" |
| chromium.c | 1323 | "History" |
| chromium.c | 1503 | "Login Data", "Cookies", "Web Data", "History" |
| chromium.c | 1573, 1742, 1827 | "Web Data" |
| chromium.c | 1951 | "Bookmarks" |
| firefox.c | 338 | "key3.db" |
| firefox.c | 462 | "key4.db" |
| firefox.c | 825 | "cookies.sqlite" |
| firefox.c | 913 | "places.sqlite" |
| firefox.c | 1078 | "logins.json" |

### 2.3 Plaintext path/protocol/URL strings (MEDIUM)

| File | Line | String |
|------|------|--------|
| chromium.c | 1496 | "%s%s_%s_master_key.bin" |
| chromium.c | 1507 | "%s%s_%s_%s.raw" |
| chromium.c | 1547 | "%s_cookies_cdp.txt" |
| chromium.c | 926 | "[!] get_master_key: Local State read failed\n" |
| chromium.c | 933 | "[!] get_master_key: encrypted_key extraction failed\n" |
| chromium.c | 949 | "[!] get_master_key: DPAPI failed (error 13 = App-Bound?)\n" |
| chromium.c | 642-708 | Multiple dbg_printf("[!] read_file_backup: ...") strings |
| cdp_grabber.c | 146 | "GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n" |
| cdp_grabber.c | 256 | "# Netscape HTTP Cookie File\n" |
| cdp_grabber.c | 413 | "--remote-debugging-port=%d --headless --disable-gpu ..." |
| cdp_grabber.c | 469 | "{\"id\":1,\"method\":\"Network.getAllCookies\"}" |
| browser_paths.c | 1193-1194 | "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths" |
| browser_paths.c | 1033, 1092 | "\\Profiles" |
| browser_paths.c | 1324-1365 | Multiple "%s\\User Data\\Local State" format strings |

### 2.4 Plaintext JSON key strings in CDP grabber (MEDIUM)

| File | Line | String |
|------|------|--------|
| cdp_grabber.c | 39 | "\"%s\":\"" (JSON key search pattern) |
| cdp_grabber.c | 271-275 | "domain", "name", "value", "path" |
| cdp_grabber.c | 279-282 | "secure", "httpOnly", "expires" |
| cdp_grabber.c | 260 | "\"result\":[" |
| cdp_grabber.c | 423 | "webSocketDebuggerUrl" |

---

## 3. Logic Bugs

### 3.1 CRITICAL: _mir_stem_eq() reads beyond target string (UB)

File: chromium.c Line: 197-204

```c
static int _mir_stem_eq(const WCHAR *w, int wlen, const char *t) {
    for (int i = 0; i < wlen; i++) {
        WCHAR wc = w[i];
        char  tc = t[i];
        if (wc >= L'A' && wc <= L'Z') wc += 32;
        if (tc >= 'A'  && tc <= 'Z')  tc += 32;
        if ((char)wc != tc) return 0;
        if (tc == '\0') return 0;  // too late: already read t[i] past '\0'
    }
    return t[wlen] == '\0';
}
```

When wlen > strlen(t), the function reads t[i] for i past the null terminator before checking. The \0 check at line 203 happens AFTER tc = t[i] already read the out-of-bounds byte. This is undefined behavior.

### 3.2 HIGH: MirHandleEntry struct layout may mismatch Windows versions

File: chromium.c Lines: 115-126

The struct assumes Win10+ layout (1-byte ObjectTypeIndex). On Win7/8, ObjectTypeIndex is 2 bytes, causing all subsequent field offsets to shift. Also, compiler may insert padding between HandleValue (USHORT at offset 6) and Object (needs 8-byte alignment on x64). The actual Windows struct packs these without padding.

Impact: On non-Win10 or with compiler padding, handle values are misread, causing silent failures or potential BSOD from duplicating kernel handles.

### 3.3 HIGH: NtQuerySystemInformation handle enumeration TOCTOU race

File: chromium.c Lines: 300-370

Between NtQuerySystemInformation (handle snapshot) and NtDuplicateObject, the browser process may close or replace the handle. The pDup failure is handled (if (st < 0 || !hdup) continue), so it degrades gracefully. However, there is no maximum iteration cap — if a browser has millions of handles, this loop could take minutes.

### 3.4 HIGH: read_file_rm() resolves NtQuerySystemInformation by PLAINTEXT string — BROKEN

File: chromium.c Line: 569

```c
fnNtQSI pQSI = (fnNtQSI)_mir_res(ntdll, "NtQuerySystemInformation");
```

This passes a PLAINTEXT string to _mir_res(), which calls mirage_encrypted_hash_func(). But _mir_res() expects an already-encrypted name, not plaintext. All other call sites use enc_decrypt() first. This line computes a hash of plaintext that will NOT match the real function name hash, causing pQSI to be always NULL. The if (!pQSI) guard on line 571 then skips handle enumeration entirely.

Impact: Tier 1 (Restart Manager) handle duplication path is COMPLETELY BROKEN. read_file_rm() can get PIDs but never reads the file via section mapping because handle enumeration is skipped.

### 3.5 MEDIUM: write_netscape_cookies() — nested {} in JSON breaks parser

File: cdp_grabber.c Lines: 258-295

The parser finds the first { and then the first }. If JSON contains nested objects (which CDP responses often do for {"result":{"result":[...]}}), end will point to the innermost }, truncating the block. Also, strchr(p, '}') does not handle } inside string values.

### 3.6 MEDIUM: ProcessImageFileName kernel buffer memory leak

File: chromium.c Lines: 260-270

```c
UNICODE_STRING img = {0, 0, NULL};
st = pQIP(ph, MIRAGE_ProcImageName, &img, sizeof(UNICODE_STRING), NULL);
```

ProcessImageFileName (class 27) fills UNICODE_STRING with a kernel-allocated buffer pointer. The code never frees this buffer. Each call allocates kernel memory that must be freed with RtlFreeUnicodeString. This leaks memory for every non-matching process in the PID enumeration loop. On a system with 200+ processes, this leaks one kernel allocation per non-browser process.

### 3.7 MEDIUM: extract_chromium_cards() — hardcoded column indices fragile across Chrome versions

File: chromium.c Lines: 1671-1695

The code assumes Chrome 80+ has guid at column 0, card_number_encrypted at column 4. Chrome 100+ added billing_address_id at column 5. Some builds have card_number_encrypted at column 3, not 4. Hardcoded indices will silently extract wrong data on newer Chrome versions.

### 3.8 MEDIUM: %ld format for double expires_utc (overflow on Win64)

File: cdp_grabber.c Line: 286

```c
double expires = json_extract_number(block, "expires");
fprintf(f, "%s\t%s\t%s\t%s\t%ld\t%s\t%s\n", ..., (long)expires, ...);
```

Chrome's expires_utc is microseconds since 1601-01-01 (64-bit). On Win64, long is 32 bits, so (long)expires silently truncates, producing wrong expiry values. Fix: use (long long) with %lld.

### 3.9 LOW: strdup() return not checked

File: chromium.c Lines: 1480-1481

bd->browser_name = strdup(browsers[b].name); bd->profile_name = strdup(basename_of(profiles[p])); — strdup() can return NULL on OOM, causing NULL dereference if used later.

### 3.10 LOW: bdb_find_value() — entries capped at 256 may drop valid keys

File: firefox.c Lines: 234

uint16_t off[256] with if (entries > 256) entries = 256. If nb_key * 2 exceeds 256, entries are silently dropped.

---

## 4. Unsafe snprintf/sprintf Usage

### 4.1 Potential buffer truncation with untrusted inputs

| File | Line | Code | Issue |
|------|------|------|-------|
| chromium.c | 1496 | snprintf(mk_path, MAX_PATH, "%s%s_%s_master_key.bin", ...) | browser name + basename could exceed MAX_PATH |
| chromium.c | 1506-1507 | snprintf(src, MAX_PATH, "%s%s", profiles[p], raw_files[rf]) | profile path + filename could exceed MAX_PATH |
| chromium.c | 1547 | snprintf(cdp_output, MAX_PATH, "%s_cookies_cdp.txt", browsers[b].name) | long browser name truncation |
| browser_paths.c | 1324-1365 | Multiple snprintf(probe, 1024, "%s\\User Data\\Local State", ...) | exe_dir/probe are both 1024 bytes — overflow if near-max |

### 4.2 %ld for 64-bit expires_utc

File: cdp_grabber.c Line: 286 — (long)expires with %ld. On Win64 (long=32bit), Chrome's 64-bit expires_utc truncates.

---

## 5. Unimplemented Features / TODOs / Stubs

### 5.1 key3.db fallback is partial (firefox.c:338-390)

try_key3_db() handles the common case (empty password, 3DES-CBC) but does not handle:
- Non-empty master passwords
- AES-256-CBC encrypted key3.db (Firefox 75+)
- The f801 key slot variation

### 5.2 WebSocket upgrade response not validated (cdp_grabber.c:489-501)

The upgrade response is drained without checking for "101 Switching Protocols". If Chrome rejects the upgrade, the code silently sends CDP commands on a non-WebSocket connection.

### 5.3 ws_recv_text() does not handle continuation frames (cdp_grabber.c:216-246)

If Chrome sends the CDP response as multiple continuation frames (opcode 0x00), only the first frame is read. Large cookie responses will be truncated.

### 5.4 chrome_derive_key() fallback wastes CPU (chromium.c ~line 1475)

When DPAPI/AppBound fails, falls back to deriving key from empty password. All AES-GCM decryptions will fail (wrong key), wasting CPU on every blob.

---

## 6. Locked-File Bypass Correctness

### 6.1 Tier 1 (Restart Manager) — BROKEN

Line 569: fnNtQSI pQSI = (fnNtQSI)_mir_res(ntdll, "NtQuerySystemInformation");

Passes PLAINTEXT string instead of encrypted form. pQSI is always NULL. Handle enumeration is skipped. File is never read via handle duplication in this tier. Only works if the file is NOT locked (falls through to normal fopen).

### 6.2 Tier 2 (Handle enumeration) — Mostly Correct

Correct aspects:
- NtGetNextProcess with PROCESS_QUERY_INFORMATION (0x0400)
- ProcessImageFileName (class 27) for image name
- .exe extension stripping and encrypted stem matching
- GrantedAccess filter: 0x00120001 (FILE_READ_DATA|SYNCHRONIZE|READ_CONTROL)
- Opens with PROCESS_DUP_HANDLE (0x0040)
- Duplicates with 0x00120081
- Verifies path via GetFinalPathNameByHandleW
- Creates SEC_COMMIT|PAGE_READONLY section
- Maps ViewShare with PAGE_READONLY

Issues:
- Memory leak: ProcessImageFileName kernel buffers never freed
- No ObjectTypeIndex filter: wastes time on non-file handles
- Duplicate access mask includes DELETE (0x00010000) unnecessarily

### 6.3 Tier 4 (SeBackupPrivilege) — Correct but requires admin

Correctly enables SeBackupPrivilege + SeRestorePrivilege, opens with FILE_FLAG_BACKUP_SEMANTICS. Issue: AdjustTokenPrivileges returns TRUE even if privilege was not actually enabled (need to check GetLastError).

---

## 7. Additional Findings

### 7.1 browser_paths.c line 1338: getenv("LOCALAPPDATA")

Single getenv() call in registry discovery path while rest of file uses GetEnvironmentVariableW via PEB-walk. CRT import + plaintext "LOCALAPPDATA" in .rdata.

### 7.2 browser_paths.c lines 1393-1394: strdup() in registry discovery

strdup(browser_name) and strdup(probe) — CRT strdup import. Strings are never freed (static array), so no leak, but CRT import is unnecessary.

### 7.3 cdp_grabber.c line 474: atoi()

CRT atoi import. Could use manual parse.

### 7.4 firefox.c lines 37-50: #define memmem compat_memmem

Global macro redefines memmem for entire translation unit. If any header declares memmem, this creates a conflict.

---

## Summary

| Severity | Count | Category |
|----------|-------|----------|
| CRITICAL | 2 | fopen IAT calls; plaintext hash mismatch breaks Tier 1 bypass |
| HIGH | 4 | getenv() CRT call; struct layout mismatch; TOCTOU race; kernel memory leak |
| MEDIUM | 8 | Plaintext strings (4 categories); nested JSON parser; fragile column indices; %ld overflow; CDP stubs |
| LOW | 6 | Unchecked returns; partial key3.db; misc CRT calls |
