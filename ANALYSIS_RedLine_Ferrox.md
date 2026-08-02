# RedLineStealer & Ferrox Analysis Report

## Executive Summary

Two fundamentally different architectures analyzed: **RedLineStealer** is a mature C#/.NET stealer using WCF-based C2 with a modular, config-driven design. **Ferrox** is a Rust stealer emphasizing anti-analysis, using Telegram as C2 with custom encrypted blob format. Both are production-grade and contain techniques directly applicable to Mirage.

---

## 1. Browser Data Extraction Patterns

### RedLineStealer (C#/.NET)

**Architecture:** Two parallel engines — `ChromiumEngine` and `GeckoEngine` — with separate extraction paths for each browser family.

**Chromium Extraction Flow:**
1. Enumerate browser profiles via `GetProfile()` (scans `LocalAppData` and `RoamingAppData`)
2. Parse SQLite databases directly via custom `SqlConnection` class (no external DB library)
3. Extract: `Login Data` (passwords), `Cookies`, `Web Data` (autofill/credit cards)
4. Decrypt: AES-256-GCM via BouncyCastle (`GcmBlockCipher`) using key from `Local State` JSON → `os_crypt.encrypted_key` → DPAPI-protected → Base64-decoded
5. `DecryptV10()` handles the v10 encryption prefix (newer Chrome)

**Gecko (Firefox) Extraction Flow:**
1. Locate profiles via `profiles.ini` in `%APPDATA%\Mozilla\Firefox`
2. Parse BerkeleyDB format (`GeckoDatabase`) for `key4.db` / `key3.db` → extract private key via ASN.1 (`Asn1Factory`)
3. Decrypt `logins.json` with extracted private key
4. Parse `cookies.sqlite` directly

**Key Pattern — Credential Model:**
```
Credentials.Create(ClientSettings):
  - Defenders (WMI antivirus queries)
  - Languages
  - InstalledSoftwares
  - Processes
  - Hardwares (WMI)
  - Browsers (Chromium + Gecko)
  - FtpConnections (FileZilla, WinSCP)
  - InstalledBrowsers
  - Files (remote file grabber)
```

**Unique Targets:**
- FTP clients (FileZilla XML config, WinSCP registry)
- IM clients (Pidgin)
- Edge Vault (Windows Credential Manager via `VaultEnumerateItems`)
- Remote file grabber with configurable `path|pattern|recursive` format

### Ferrox (Rust)

**Architecture:** Reflective DLL injection into suspended browser processes + named pipe IPC.

**Browser Extraction Flow:**
1. Find browser paths via registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{chrome,brave,edge}.exe`
2. Suspend browser process if running
3. Decrypt embedded reflective DLL (`encrypted.bin`) with ChaCha20
4. Inject DLL into suspended browser via `NtCreateSection` + `NtMapViewOfSection` (Hell's Gate syscalls)
5. Create named pipe (`\\.\pipe\{random_hex}`) for IPC
6. DLL reads browser data via pipe protocol
7. Cleanup: kill suspended browser processes after extraction

**Key Technique — App-Bound Encryption Bypass:**
Ferrox targets Chrome's newer App-Bound Encryption by injecting into the browser process itself (the DLL must run inside Chrome's context to access the encryption keys). This is the most modern approach to Chrome v127+ encryption.

**Unique Targets (app/ module):**
- **Messaging:** Discord, Telegram, Signal, Element, WhatsApp Desktop, Session, Guilded, Revolt, Tox, ICQ, Viber, Matrix, Skype (13 apps)
- **Gaming:** Steam, Epic, Battle.net, Roblox, Minecraft, Riot, Origin/EA, UPlay, NationsGlory, Discord (token extraction)
- **Wallets:** MetaMask, Exodus, Electrum, Atomic, Coinomi, Jaxx, Trust Wallet, Phantom, Solflare, Coinbase, Blockchain.com, Wasabi, Ledger Live, Trezor Suite, Edge Wallet, Guarda, MyCrypto, MyEtherWallet
- **Documents:** User docs, system docs, crypto keys (seed phrases, wallet files)

---

## 2. Anti-Analysis Techniques

### RedLineStealer

**Minimal — focused on VM detection only:**
- `VmDetector.GetMachineType()`: WMI queries for processor manufacturer (`VBoxVBoxVBox`, `VMwareVMware`, `prl hyperv`)
- Baseboard manufacturer check (`Microsoft Corporation` → HyperV)
- Disk drive PNP Device ID scan (`VBOX_HARDDISK`, `VEN_VMWARE`)
- Returns `MachineType` enum: VirtualBox, VMWare, Parallels, HyperV, Unknown

**No anti-debug, no timing checks, no sandbox detection.** RedLine relies on server-side filtering (`BlacklistedCountry` in `ClientSettings`).

### Ferrox

**Comprehensive multi-layer anti-analysis:**

**VM Detection (`detection.rs`):**
- CPUID hypervisor bit check (`cpuid_vm_check`)
- PEB `BeingDebugged` flag + `NtGlobalFlag` check (`peb_check`)
- Timing-based detection via RDTSC (`timing_check`) — measures instruction timing for breakpoints
- Process enumeration for VM tools (`process_vm_check`)
- Registry keys for VM software (`registry_vm_check`)
- MAC address OUI check for VM vendors (`mac_vm_check`)
- WMI hardware queries (`wmi_hardware_check`)
- Combined: `comprehensive_vm_check()` — any single check triggers exit
- `comprehensive_debug_check()` — timing + PEB

**Sandbox Detection (`system_health.rs`):**
- `IsDebuggerPresent` + `CheckRemoteDebugger` via API hashing
- Parent process check (explorer.exe expected)
- Low memory detection (< 4GB = sandbox)
- Low CPU count (< 2 cores = sandbox)
- Recent boot time check (< 10 min = sandbox)
- `detect_sandbox_environment()` — combined check

**Execution Inflation (`padding.rs`):**
- `inflate_execution()` — performs legitimate-looking operations:
  - File system operations (read system files)
  - Registry reads (HKLM\SOFTWARE\Microsoft)
  - Computational work (prime number calculation)
  - System info queries
  - Timing-based delays
- `enhanced_sleep_with_acceleration_check()` — sleep with acceleration detection (sandboxes fast-forward sleeps)

**Polymorphism (`polymorph.rs`):**
- Opaque predicates (always-true/always-false conditions that confuse disassemblers)
- NOP sleds (random and extended)
- Polymorphic arithmetic operations
- Stack junk injection (`stack_junk_small`, `stack_junk_large`)
- Control flow confusion
- `polymorph_guard!`, `polymorph_call!`, `polymorph_heavy!` macros

**Self-Protection (`cleanup.rs`):**
- `corrupt_self_on_vm_detect()` — overwrites own executable with null bytes if VM detected
- Close own file handles via `NtQuerySystemInformation` (handle table enumeration)

---

## 3. C2 Protocol

### RedLineStealer

**Protocol:** WCF (Windows Communication Foundation) over HTTP/HTTPS with `IRemotePanel` service contract.

**Interface:**
```csharp
[ServiceContract]
interface IRemotePanel {
    Task<ClientSettings> GetSettings();      // Fetch config
    Task SendClientInfo(UserLog user);       // Upload stolen data
    Task<IList<RemoteTask>> GetTasks(UserLog user);  // Get commands
    Task CompleteTask(UserLog user, int taskId);     // Report completion
}
```

**Flow:**
1. `ServicePointManager.ServerCertificateValidationCallback = true` (accept any cert)
2. Connect to hardcoded IP (`127.0.0.1` in source — builder replaces)
3. `GetSettings()` → receive `ClientSettings` (what to grab, country blacklist)
4. Collect `Credentials.Create(settings)` based on config
5. `SendClientInfo(credentials)` → upload
6. Poll `GetTasks()` → execute remote tasks (RunPE, file download)
7. `CompleteTask()` → report
8. `InstallManager.RemoveCurrent()` in finally block

**Remote Task System:**
- `RemoteTask` with `RemoteTaskAction` enum
- Supports RunPE (process hollowing) via `LoadExecutor`
- File download/execution
- Self-removal

**Persistence:**
- Task Scheduler: `MicrosoftIIS_CheckInstalledUpdater`
- Install path: `%USERPROFILE%\Documents\IISExpress\Config\MicrosoftIISAdministration_v2.exe`
- Mutex for single instance

### Ferrox

**Protocol:** Telegram Bot API (HTTP REST).

**Flow:**
1. `initialize_communications()` — warmup connection to Telegram API
2. Random 15-45 second delay before first message
3. `send_system_notification()` — random startup message
4. `send_recon_info()` — system recon (IP, adapters, WiFi, Windows key, AV, domain)
5. `run_harvest_and_upload()` — parallel collection + upload

**Upload Mechanism (`telegram.rs`):**
- `TelegramUploader` struct with bot token + chat ID
- Random User-Agent per run
- Gzip compression before upload
- Chunked upload for files > 45MB (Telegram limit is 50MB)
- `HarvestSummary` message with stats

**Blob Format (`blob_format.rs`):**
Custom binary format with fixed offsets:
```
Offset 0:    MAGIC (8 bytes) - "RVNBLOB1"
Offset 8:    VERSION (2 bytes) - 0x0001
Offset 10:   ENCRYPTION_KEY (32 bytes) - ChaCha20 key
Offset 42:   NONCE (12 bytes)
Offset 54:   ZIP_PWD_LEN (2 bytes)
Offset 56:   ZIP_PASSWORD (N bytes)
Offset 56+N: PADDING (to 128 bytes)
Offset 128:  ENCRYPTED_ZIP_DATA (rest)
```
- ChaCha20 encryption of ZIP data
- Random password per blob
- Self-contained: key embedded in blob (server can decrypt without prior knowledge)

**Evasion (`evasion.rs`):**
- `random_legitimate_activity()` — makes requests to google.com/generate_204, cloudflare.com/cdn-cgi/trace, bing.com/favicon.ico, microsoft.com/favicon.ico
- Jitter macros: `jitter!`, `jitter_ms!`, `with_jitter!` — random delays between operations

**Persistence:**
- Registry Run key: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- Value name: polymorphic (`PreviousUpdateScan` / `LastTelemetrySync`)
- Exe name: polymorphic (`SystemDriverUpdate.exe` / `DisplayDriverUpdater.exe`)
- BITS job: `WindowsUpdateBackup`

**Self-Delete (`dissolve.rs`):**
- Create batch file with UUID name in `%TEMP%`
- Batch loops: wait → taskkill → del exe → if exist goto loop → del self → exit
- `CREATE_NO_WINDOW` flag for stealth

---

## 4. Unique Collection Targets

### RedLineStealer Unique Targets
| Target | Method |
|--------|--------|
| FTP clients (FileZilla, WinSCP) | XML config parsing + registry |
| IM clients (Pidgin) | Account XML parsing |
| Edge Vault | Windows Credential Manager API |
| Remote files | Configurable `path\|pattern\|recursive` |
| WMI hardware info | Processor, baseboard, disk, GPU, network adapter |
| WMI security info | Antivirus, antispyware, firewall |
| Installed software | Registry enumeration |
| Running processes | Process enumeration |

### Ferrox Unique Targets
| Target | Method |
|--------|--------|
| WiFi passwords | `netsh wlan show profiles` + `key=clear` |
| Windows product key | Registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DigitalProductId` |
| Domain info | `net config workstation` parsing |
| Network adapters | IP + MAC enumeration |
| 13 messaging apps | File/directory copy from AppData |
| 10+ game platforms | Registry + file extraction |
| 18+ crypto wallets | Browser extensions + desktop apps |
| Documents | User docs, system docs, crypto keys/seed phrases |
| Browser extensions | Chrome/Brave/Edge extension data |

---

## 5. Key Techniques Applicable to Mirage

### From RedLineStealer
1. **Modular config-driven collection** — `ClientSettings` controls what to grab; server decides scope
2. **Custom SQLite parser** — no external dependency, handles locked DBs via temp copies
3. **Gecko (Firefox) full pipeline** — BerkeleyDB → ASN.1 → key extraction → login decryption
4. **Edge Vault enumeration** — Windows Credential Manager access
5. **FTP client extraction** — FileZilla XML + WinSCP registry
6. **Remote task system** — server can push RunPE payloads post-infection
7. **WMI-based system profiling** — hardware, security software, network

### From Ferrox
1. **Reflective DLL injection for browser extraction** — inject into Chrome process to bypass App-Bound Encryption
2. **Named pipe IPC** — clean communication channel between injector and injected DLL
3. **API hashing** — `api_hash!` macro resolves APIs by hash at runtime (avoids IAT detection)
4. **Hell's Gate syscalls** — direct syscall invocation via NTDLL EAT parsing
5. **ChaCha20 encrypted blob format** — self-contained encrypted payload with embedded key
6. **Telegram as C2** — no infrastructure needed, API is trusted by security tools
7. **Polymorphic builder** — Python-based build system that randomizes constants, injects junk code, mutates timing
8. **Volatile strings** — `sprotect!` macro for encrypted strings + `VolatileString` for auto-zeroing after use
9. **Execution inflation** — legitimate-looking operations to evade behavioral analysis
10. **Self-delete via batch** — clean removal with retry loop
11. **Comprehensive VM/debug/sandbox detection** — 8+ independent checks
12. **Opaque predicates + stack junk** — anti-disassembly techniques

### Hybrid Recommendations for Mirage
- **Browser extraction:** Use ferrox's reflective DLL injection approach for Chrome v127+ App-Bound Encryption, fall back to RedLine's direct SQLite parsing for older browsers
- **C2:** Telegram (ferrox style) for simplicity + no infrastructure, or WCF (RedLine style) for full bidirectional control
- **Anti-analysis:** Ferrox's layered approach (VM + debug + sandbox + timing + inflation)
- **String protection:** Ferrox's `sprotect!` + `VolatileString` pattern
- **Syscalls:** Ferrox's Hell's Gate for sensitive operations (process injection, file access)
- **Collection scope:** Combine both — RedLine's FTP/IM + ferrox's messaging/gaming/wallets/documents
- **Build system:** Ferrox's polymorphic builder for per-build uniqueness

---

## Technical Details: Code Patterns

### RedLine — Chromium Decrypt Flow
```
DecryptChromium(cipherText, localStatePath):
  1. Read localStatePath → JSON → os_crypt.encrypted_key
  2. Base64 decode key → strip "DPAPI" prefix (5 bytes)
  3. CryptUnprotectData(keyBlob) → AES key
  4. cipherText starts with "v10" → strip prefix
  5. IV = first 12 bytes of cipherText
  6. AesGcm256.Decrypt(key, IV, cipherText) → plaintext
```

### Ferrox — Browser Injection Flow
```
collect():
  1. cbrowser::find_path() → registry lookup for chrome.exe path
  2. bbrowser::find_path() → registry lookup for brave.exe path
  3. ebrowser::find_path() → registry lookup for edge.exe path
  4. For each browser:
     a. bpipe::generate_pipe_name() → \\.\pipe\{random}
     b. bpipe::create_server(pipeName) → CreateNamedPipeW
     c. bloader::inject_browser(path, pipeName):
        - Decrypt encrypted.bin with ChaCha20
        - Find ReflectiveLoader offset
        - CreateProcessW(suspended)
        - NtCreateSection + NtMapViewOfSection
        - Write shellcode to call ReflectiveLoader
     d. bpipe::run_communication(handle) → IPC for data
  5. cleanup_suspended_browsers() → kill injected processes
```

### Ferrox — API Hashing
```
api_resolve!("kernel32.dll", "CreateFileW"):
  1. const DLL_HASH = api_hash!("kernel32.dll")  // compile-time
  2. const FUNC_HASH = api_hash!("CreateFileW")   // compile-time
  3. Walk PEB → InMemoryOrderModuleList
  4. For each module: hash name → compare DLL_HASH
  5. Parse EAT → hash function names → compare FUNC_HASH
  6. Return function pointer
```

---

## File Inventory

### RedLineStealer Key Files
- `RedLine/Program.cs` — Entry point, C2 connection, task execution
- `RedLine/IRemotePanel.cs` — WCF service contract
- `RedLine/Models/ClientSettings.cs` — Server-pushed configuration
- `RedLine/Models/Credentials.cs` — Stolen data model + collection orchestrator
- `RedLine/Logic/Browsers/Chromium/ChromiumEngine.cs` — Chromium extraction
- `RedLine/Logic/Browsers/Gecko/GeckoEngine.cs` — Firefox extraction
- `RedLine/Logic/Helpers/DecryptHelper.cs` — DPAPI + AES decryption
- `RedLine/Logic/Helpers/Constants.cs` — Paths + crypto constants
- `RedLine/Logic/Others/VmDetector.cs` — WMI-based VM detection
- `RedLine/Logic/Others/InstallManager.cs` — Persistence + self-management
- `RedLine/Logic/Others/RemoteFileGrabber.cs` — Configurable file grabber
- `RedLine/Logic/FtpClients/FileZilla.cs` — FileZilla extraction
- `RedLine/Logic/FtpClients/WinSCP.cs` — WinSCP extraction
- `RedLine/Logic/ImClient/Pidgin.cs` — Pidgin extraction
- `RedLine/Logic/RunPE/LoadExecutor.cs` — Process hollowing
- `RedLine/Client/Logic/Crypto/AesGcm256.cs` — AES-GCM implementation

### Ferrox Key Files
- `src/main.rs` — Entry point, harvest orchestrator, persistence
- `src/lib.rs` — Module declarations, sprotect macro, polymorphic constants
- `src/proc/browser/bmain.rs` — Browser collection orchestrator
- `src/proc/browser/bloader.rs` — Reflective DLL injection
- `src/proc/browser/bpipe.rs` — Named pipe IPC
- `src/proc/browser/cbrowser.rs` — Chrome path finder
- `src/proc/browser/bbrowser.rs` — Brave path finder
- `src/proc/browser/ebrowser.rs` — Edge path finder
- `src/communications/mod.rs` — Telegram C2
- `src/communications/telegram.rs` — Telegram upload with chunking
- `src/communications/blob_format.rs` — Custom encrypted blob format
- `src/detection.rs` — VM + debug + sandbox detection
- `src/evasion.rs` — Jitter + legitimate traffic generation
- `src/stealth.rs` — Same as evasion (duplicate)
- `src/polymorph.rs` — Opaque predicates + anti-disassembly
- `src/ntbridge.rs` — Hell's Gate syscall implementation
- `src/ntcall.rs` — Alternative syscall implementation
- `src/api_hash.rs` — Compile-time API hashing macro
- `src/api_resolve.rs` — Runtime API resolution by hash
- `src/sprotect.rs` — VolatileString (auto-zeroing encrypted strings)
- `src/fingerprint.rs` — Hardware-based device fingerprinting
- `src/recon.rs` — System reconnaissance (IP, WiFi, AV, domain)
- `src/cleanup.rs` — Handle closing + self-corruption
- `src/dissolve.rs` — Self-delete via batch file
- `src/padding.rs` — Sandbox evasion via execution inflation
- `src/system_health.rs` — Defender killer (encrypted DLL injection)
- `src/app/messaging.rs` — 13 messaging apps extraction
- `src/app/gaming.rs` — 10+ game platform extraction
- `src/app/app_wallets.rs` — 18+ crypto wallet extraction
- `src/docs/extraction.rs` — Document/key extraction orchestrator
- `scripts/build.py` — Build system with error filtering
- `scripts/polymorph.py` — Polymorphic code mutation
