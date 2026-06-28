# Mirage Stealer — Operational Security

## 1. Static Detection Risks

### 1.1 Plaintext Strings

| Status | Details |
|--------|---------|
| **FIXED** | No plaintext API names, DLL names, paths, tokens, or configuration in the binary |
| Method | All sensitive strings use `hash.xorEncrypt()` at comptime with `STRING_KEY_ENC` |
| Runtime | `xorDecrypt()` writes to stack buffer → used → `secureZero()` clears it |
| Example | `"NtAllocateVirtualMemory"` → stored as encrypted bytes → resolved to hash at comptime |
| Risk | **Low.** A static scan will see XOR-encrypted byte arrays and CRC32 hashes, not API names |

### 1.2 IAT Entries

| Status | Details |
|--------|---------|
| **FIXED** | No IAT entries for sensitive functions |
| Method | All NT API calls resolved via Halo's Gate syscalls (no ntdll import table) |
| Method | All DLL functions resolved via PEB Ldr walk + export table hash scan |
| Fallback | `LdrLoadDll` resolved by hash → load system DLLs → `LdrGetProcedureAddress` for function addresses |
| Visible IAT | Only `kernel32.dll` (expected for any Windows executable), but sensitive imports like `CreateToolhelp32Snapshot`, `WriteProcessMemory` are absent |
| Risk | **Very Low.** No import table for syscall-dependent functions |

### 1.3 Comptime Configuration

| Item | Storage | Detection |
|------|---------|-----------|
| C2 host | XOR-encrypted in `.rdata` under `MIRAGECFG` signature | XR pattern matching could find config block |
| Telegram token | XOR-encrypted in `.rdata` | Same as above; token format `\d+:[\w-]+` detectable if partial decrypt |
| AES-GCM build config | Encrypted with random key (32B key + 12B nonce + 16B tag + ciphertext) | Key derivation unknown — cannot decrypt without brute-force |
| SEED + STRING_KEY_ENC | Stored in `.rdata` as plain hex literals | Visible as 4 + 16 bytes of seemingly random data |

**Risk:** **Low.** The `MIRAGECFG` signature (9 ASCII bytes) is a static detection surface — a signature-based scanner could flag the pattern. Mitigation: the signature is necessary for the builder to locate the config offset; consider encoding or splitting it.

---

## 2. Runtime Detection Risks

### 2.1 Syscall Hooks (EDR)

| Technique | Status | Details |
|-----------|--------|---------|
| Halo's Gate | ✅ Implemented | Resolves SSN from ntdll export table, walks neighboring syscalls to find unhooked stubs |
| Gadget pool | ✅ Implemented | Scans ntdll `.text` for `0F 05 C3` (`syscall; ret`) — pool of 64 random gadgets |
| Direct syscall | ✅ Implemented | No `ntdll!Nt*` trampoline calls — all syscalls go through stubs.zig → random gadget |
| Win11 24H2 prologue | ✅ Implemented | Detects `48 8B C4` (mov rsp,rbp) or `48 89 5C 24` (mov [rsp+..],rbx) prologue formats |
| **ETW patching** | ❌ NOT IMPLEMENTED | `EtwEventWrite` not called by this code path; syscalls bypass ntdll → no ETW trigger |
| **AMSI patching** | ❌ NOT IMPLEMENTED | Not relevant — no PowerShell/.NET scripting is executed by the stealer itself |

**Risk:** **Low-Moderate.** Halo's Gate + gadget pool evades userland hooks, but kernel callbacks (ETW TI, Kernel APC) still fire. ETW is not patched — currently not needed since no ntdll functions are called that would trigger ETW probes.

### 2.2 Memory Scanning

| Risk | Details |
|------|---------|
| Heap allocations | Collected data stored in page_allocator memory — strings visible in process heap |
| Stack buffers | XOR decrypted strings live on stack temporarily (~frame duration) |
| Module presence | Process has loaded `secur32.dll`, `bcrypt.dll`, `crypt32.dll`, `ole32.dll`, `ws2_32.dll`, `wlanapi.dll` — these are loaded via `LdrLoadDll` at runtime |

**Risk:** **Moderate.** A memory scanner can find decrypted strings in heap buffers, and the loaded DLLs are visible in the PEB module list. The PEB hide only removes ntdll — the dynamically loaded DLLs remain visible.

### 2.3 Process Anomalies

| Anomaly | Detection Risk |
|---------|----------------|
| No CRT | Missing `msvcrt.dll` dependency — unusual for a Zig binary but not unique |
| Console-less | `. subsystem Windows` — normal for GUI applications |
| Single-threaded | No child threads — less suspicious than CreateThread calls |
| Short lifetime | ~5-30 seconds execution — typical for stealers, may trigger behavioral heuristics |
| Network connections | Outbound HTTPS to C2 + Telegram — any EDR monitoring Winsock connections will see |

**Risk:** **Moderate.** The short execution window and outbound connections are the most detectable behavioral patterns.

---

## 3. Network Detection Risks

### 3.1 TLS Fingerprint

| Aspect | Value | Risk |
|--------|-------|------|
| Library | SChannel (Windows built-in) | Blend in with OS traffic |
| JA3 fingerprint | OS default SChannel TLS handshake | Same as any Windows app using WinHTTP/WinINet — no unique fingerprint |
| Server cert validation | **Skipped** for panel (self-signed) | SChannel will connect without verifying — normal for internal tools |
| SNI | Sent in ClientHello | Reveals C2 hostname to network monitors |

**Risk:** **Low.** SChannel traffic is indistinguishable from legitimate Windows TLS traffic.

### 3.2 HTTP Headers

| Header | Value | Notes |
|--------|-------|-------|
| `User-Agent` | Custom (set in HTTP client) | Should mimic Chrome/Edge to blend with browser traffic |
| `Authorization` | `Bearer <token>` | Static token per build — replayable if captured |
| `Content-Type` | `multipart/form-data` | Normal for file uploads |
| POST path | `/api/log` | Custom endpoint — deterministic path if panel is monitored |

**Risk:** **Moderate.** `POST /api/log` to a fixed IP/domain is a strong signature. The path should be configurable per build.

### 3.3 Telegram API

| Aspect | Risk |
|--------|------|
| Destination | `api.telegram.org` — whitelisted in most environments, hard to block |
| Content | Encrypted ZIP sent as document — Telegram encrypts the channel |
| Bot token | Embedded in binary (XOR-encrypted) — if extracted, the bot can be controlled |
| Rate limiting | Telegram allows ~20 messages/min per bot — 1 log per execution is fine |

**Risk:** **Low.** Telegram is rarely blocked on corporate networks; the bot acts as a resilient backup channel.

---

## 4. Recommended OPSEC

### 4.1 Execution

- Run from `%TEMP%` or `%APPDATA%` with a random directory name
- NEVER run from Desktop or Downloads folder
- Single execution per machine — the mutex prevents re-infection of the same host
- No persistence by default (`ENABLE_PERSISTENCE = false`) — reduces exposure
- If persistence is enabled, use a Run key with a benign name (e.g., `WindowsUpdate`, `GoogleUpdate`)
- Delete the archive and working directory after successful exfiltration

### 4.2 Network

- Use a proxy or CDN (Cloudflare, etc.) in front of the panel server
- Rotate C2 domain/IP every 24-48 hours
- Use a different `MIRAGECFG` SEED per build — each build has unique XOR keys
- Regenerate the Bearer auth token per build
- Set `SLEEP_MIN_MS` to 10-30 seconds before network calls to evade fast-connect heuristics

### 4.3 Build Hygiene

- Build on a VM, not the host machine
- Never test builds on the same network as the C2 (your own IP will appear in logs)
- Use `dotnet publish -c Release` for Panel — debug builds leak PDB paths
- Strip the stealer binary (`strip = true` in build.zig)
- Always append MirageDecryptor.dll as overlay (if Chrome v20+ is a target)

---

## 5. Forensic Footprint

### 5.1 Registry

| Key | Created? |
|-----|----------|
| `HKLM\...\Run` | Only if `ENABLE_PERSISTENCE = true` |
| `HKLM\...\CurrentVersion` | Read (OS info) — no write |
| `HKLM\HARDWARE\...\BIOS` | Read (VM detection) — no write |

**Default:** No registry writes. Zero persistent footprint.

### 5.2 Event Logs

| Log | Entry |
|-----|-------|
| `Microsoft-Windows-Kernel-Process` | Process creation (PID, path to EXE) |
| `Sysmon Event ID 1` | Process creation with command line (if Sysmon is installed) |
| `Sysmon Event ID 3` | Network connection (if Sysmon is installed) |
| `Sysmon Event ID 11` | File creation in `%TEMP%` (if Sysmon is installed) |
| `Security 4688` | Process creation (audit policy dependent) |

**Risk:** Process creation is unavoidable. The binary runs once and exits — no second process, service, or scheduled task.

### 5.3 Filesystem

| Path | Content | Status |
|------|---------|--------|
| `%TEMP%\<random_hex>\report.txt` | Collected data (plaintext before ZIP) | Created → deleted |
| `%TEMP%\<random_hex>\data.zip.enc` | Encrypted archive | Created → deleted |
| `%TEMP%\<random_hex>\` | Working directory | Deleted (dir remove) |
| `%TEMP%\<random_hex>\_delete.tmp` | Self-delete batch | Created → exec → deleted |

**Residual Risk:** On crash or power loss, the temp directory persists with plaintext data.

### 5.4 Prefetch / Shimcache

- Execution creates a prefetch file (unless running from a RAM disk)
- Shimcache records the binary path on NTFS volume
- These are unavoidable for any executed PE

---

## 6. Anti-Analysis

### 6.1 Weighted Scoring System

| Check | Weight | Method |
|-------|--------|--------|
| RAM < 2 GB | 20 | `NtQuerySystemInformation(SystemBasicInformation)` |
| CPU cores < 2 | 20 | `NtQuerySystemInformation(SystemBasicInformation)` |
| VM registry artifacts | 25 | `NtOpenKey(BIOS)` → `NtQueryValueKey(SystemManufacturer/SystemProductName)` |
| Timing anomaly (rdtsc delta) | 20 | `rdtsc` → `NtDelayExecution(100ms)` → `rdtsc` — delta > 10M = VM |
| Debugger present | 15 | `NtQueryInformationProcess(ProcessDebugPort)` |
| Screen < 1280x720 | — | `NtUserGetSystemMetrics` via win32u syscall |

**Threshold:** 60 points → abort execution. The scoring is weighted so that 2+ VM indicators alone trigger exit.

### 6.2 Anti-Analysis Weaknesses

- No sandbox-specific checks (Cuckoo, Joe Sandbox, etc.)
- No MAC address prefix check (VMware/VirtualBox OUI)
- No process list enumeration for analysis tools (taskmgr is checked by database scanner, not current version)
- No hardware breakpoint detection (except the App-Bound HWBP path used for COM Elevator)
- No `NtClose` invalid handle crash test (Cuckoo hook detection)

---

## 7. Build OPSEC

| Practice | Implementation |
|----------|---------------|
| Unique SEED per build | Builder generates random `SEED` + `STRING_KEY_ENC` |
| XOR-encrypted config | Comptime: string XOR with `STRING_KEY_ENC` |
| AES-GCM config | Builder encrypts config JSON with random key; stealer decrypts at runtime |
| DLL overlay | MirageDecryptor.dll appended after last section — not written to disk |
| Strip symbols | `strip = true`, `ReleaseSmall`, no PDB |
| No console | `.subsystem = .Windows` — no console window on execution |
| No CRT | `freestanding`, no `msvcrt.dll` import — smaller PE, fewer static IOCs |
