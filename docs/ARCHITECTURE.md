# Mirage Stealer — Architecture

## 1. System Overview

Mirage is a two-component Windows x64 information stealer:

| Component | Language | Target | Role |
|-----------|----------|--------|------|
| **Mirage.Stealer** | Zig 0.16 + inline ASM | x86_64-windows, ReleaseSmall | Collects browser/wallet/messenger/gaming data, ZIPs, encrypts, exfiltrates |
| **Mirage.Panel** | Go + React (TypeScript) | Linux/macOS/Windows | Self-hosted Go server + React SPA dashboard + PE builder |

The stealer sends encrypted ZIP archives via HTTPS to the Panel's `/api/log` endpoint, with a Telegram Bot API backup channel.

---

## 2. Stealer Architecture (Mirage.Stealer)

### 2.1 Module Tree

```
src/
├── main.zig                      # Entry: debug test suite OR production pipeline
├── config_decrypt.zig            # Runtime AES-GCM config decryption
│
├── types/                        # Foundation layer — no allocations
│   ├── types.zig                 # NT types, IMAGE_*, PEB, SYSTEM_* structs
│   ├── peb.zig                   # getPeb() via inline asm
│   ├── hash.zig                  # Comptime XOR-encrypted hash (Rotl-XOR-Mul)
│   ├── util.zig                  # secureZero(), trimmedLen(), readU32Le()
│   ├── peb_walk.zig              # getModuleByHash() — PEB Ldr list walk
│   └── export_resolve.zig        # getFunctionByHash() + LdrGetProcedureAddress
│
├── syscalls/                     # Direct NT syscall layer
│   ├── engine.zig                # Halo's Gate SSN resolution + 22 wrappers
│   ├── stubs.zig                 # 22 indirect syscall stubs via global asm
│   ├── gadget.zig                # `syscall; ret` gadget pool from ntdll .text
│   └── dbg.zig                   # Debug output via CONOUT$ (PEB-resolved)
│
├── config/
│   └── config.zig                # Comptime XOR-encrypted config (SEED, C2, TG, flags)
│
├── evasion/
│   ├── anti_analysis.zig         # Weighted scoring gate (RAM, CPU, screen, VM, debugger, timing)
│   ├── evasion.zig               # Low-level check primitives (NtQuerySystemInformation, rdtsc, registry)
│   ├── peb_hide.zig              # unlinkModule() — remove from LDR lists
│   └── mutex.zig                 # NtCreateEvent single-instance mutex
│
├── crypto/
│   ├── dpapi.zig                 # CryptUnprotectData via PEB-resolved crypt32.dll
│   ├── chrome_crypto.zig         # PBKDF2 + AES-256-GCM Chrome password decrypt
│   ├── chrome_key.zig            # Local State JSON parser + Base64 decode
│   ├── aes_gcm_bcrypt.zig        # BCrypt CNG AES-GCM fallback (hash-resolved)
│   ├── chacha_poly.zig           # ChaCha20-Poly1305 AEAD (archive encryption)
│   ├── archive_crypt.zig         # ZIP encrypt/decrypt with seed-derived key
│   └── dll_loader.zig            # LoadLibrary via LdrLoadDll for runtime DLLs
│
├── parsers/
│   ├── sqLoot.zig                # Custom SQLite parser (B-tree, varint, overflow pages)
│   └── file_io.zig               # File mapping via NtCreateFile + NtCreateSection + NtMapViewOfSection
│
├── browsers/
│   ├── chromium.zig              # Master orchestrator (36 browsers × profiles × 6 collectors)
│   ├── chromium_paths.zig        # 36 XOR-encrypted Chromium browser paths
│   ├── chromium_login.zig        # Login Data → AES-GCM decrypt
│   ├── chromium_cookies.zig      # Cookies → AES-GCM decrypt
│   ├── chromium_cards.zig        # Web Data → credit cards + CVC
│   ├── chromium_history.zig      # History → URLs
│   ├── chromium_autofill.zig     # Autofill → names/values
│   ├── chromium_bookmarks.zig    # Bookmarks JSON parser
│   ├── appbound.zig              # COM Elevator IElevator::DecryptData (Chrome v20+)
│   ├── appbound_inject.zig       # Self-copy + CreateProcessAsUser for path validation bypass
│   ├── firefox.zig               # Master orchestrator (10 Gecko browsers)
│   ├── firefox_paths.zig         # 10 XOR-encrypted Gecko paths
│   ├── firefox_asn1.zig          # ASN1 DER + 3 PBE decoders
│   ├── firefox_login.zig         # key4.db + logins.json → NSS decrypt
│   ├── firefox_cookies.zig       # cookies.sqlite (plaintext)
│   ├── firefox_history.zig       # places.sqlite → history
│   └── firefox_bookmarks.zig     # places.sqlite → bookmarks
│
├── wallets/
│   ├── wallets.zig               # Master orchestrator
│   ├── wallet_extensions.zig     # 62 browser extension wallet directories
│   └── wallet_desktop.zig        # 10 desktop wallets (Exodus, Electrum, etc.)
│
├── messengers/
│   ├── messengers.zig            # Master orchestrator
│   ├── discord.zig               # LevelDB token extraction
│   ├── telegram.zig              # Copy tdata session
│   ├── signal.zig                # Copy Signal config + sql + storage
│   └── pidgin.zig                # accounts.xml parse + chat logs
│
├── gaming/
│   ├── gaming.zig                # Master orchestrator
│   ├── steam.zig                 # ssfn* + config/*.vdf + userdata/
│   ├── uplay.zig                 # Ubisoft Game Launcher data
│   ├── minecraft.zig             # .minecraft + 17 alternate launchers
│   ├── battlenet.zig             # *.db + *.config
│   └── roblox.zig                # DPAPI RobloxCookies.dat → .ROBLOSECURITY
│
├── system/
│   ├── system_info.zig           # Master collector → formatted string
│   ├── os_info.zig               # Registry HKLM\...\CurrentVersion via NtOpenKey
│   ├── hardware.zig              # CPU, GPU, RAM via syscall + registry
│   ├── network_info.zig          # Hostname, IP, MAC (registry + kernel32)
│   ├── wifi.zig                  # Wlansvc XML profile parsing
│   ├── screenshot.zig            # GDI desktop screenshot
│   └── grabber.zig               # File grabber by mask from Desktop/Documents/Downloads
│
└── network/
    ├── ws2.zig                   # Winsock wrappers (hash-resolved, LdrLoadDll)
    ├── schannel.zig              # TLS via secur32.dll (AcquireCredentialsHandle → InitializeSecurityContext)
    ├── tls_socket.zig            # TCP + TLS convenience wrapper
    ├── http.zig                  # HTTP/1.1 client, multipart/form-data, response parser
    ├── panel_http.zig            # POST /api/log with Bearer token
    ├── telegram.zig              # POST /bot<TOKEN>/sendDocument
    └── zip.zig                   # PKZIP Store (CRC32 LUT, in-memory)
```

### 2.2 Production Pipeline

```
main()
 ├─ initSyscallInfrastructure()
 │   ├─ PEB walk → getModuleByHash("ntdll.dll")
 │   ├─ resolve.initNativeResolver()  → LdrGetProcedureAddress bootstrap
 │   ├─ engine.resolve()              → Halo's Gate SSN resolution (22 syscalls)
 │   ├─ gadget.initialize()           → Scan ntdll .text for syscall;ret (pool of 64)
 │   └─ engine.resolveWin32u()        → NtUserGetSystemMetrics SSN
 │
 ├─ initAntiEvasion()
 │   ├─ mutex.ensureMutex()           → NtCreateEvent single instance
 │   ├─ anti_analysis.runAll()        → Weighted scoring (RAM/CPU/screen/VM/debugger/timing)
 │   ├─ anti_analysis.shouldExit()    → Return if score ≥ threshold (60)
 │   └─ peb_hide.unlinkModule()       → Remove ntdll from LDR lists
 │
 ├─ buildReport()                     → Collect all data into single text report
 │   ├─ system_info.collect()         → OS, hardware, network, WiFi, screenshot, file grabber
 │   ├─ chromium.collect()            → 36 Chromium browsers × 6 data types
 │   ├─ firefox.collect()             → 10 Gecko browsers × 4 data types
 │   ├─ wallets_mod.collect()         → 62 extension + 10 desktop wallets
 │   ├─ messengers_mod.collect()      → Discord + Telegram + Signal + Pidgin
 │   └─ gaming_mod.collect()          → Steam + Uplay + Minecraft + Battle.net + Roblox
 │
 ├─ zip_mod.ZipWriter                → In-memory PKZIP Store archive
 ├─ archive_crypt.encryptArchive()    → ChaCha20-Poly1305 with seed-derived key
 │
 ├─ sendToPanel()                     → HTTPS POST /api/log (primary)
 │   └─ panel_http.uploadLog()        → multipart/form-data + Bearer auth
 ├─ sendToTelegramBackup()            → HTTPS POST sendDocument (backup)
 │   └─ telegram_net.sendDocument()   → Multipart with caption
 │
 └─ (implicit cleanup via defer)
```

### 2.3 Threading Model

Single-threaded. Sequential execution. Each collector returns a result type — the orchestrator logs failure but continues on error. Total execution target: < 30 seconds.

---

## 3. Panel Architecture (Mirage.Panel)

### 3.1 Structure

```
Mirage.Panel/
├── App.xaml / App.xaml.cs              # WPF Application + DI setup
├── MainWindow.xaml / MainWindow.xaml.cs # Shell with sidebar navigation
│
├── Views/
│   ├── DashboardPage.xaml/.cs          # Stats cards, country heatmap, 30-day timeline, browser pie chart
│   ├── SessionsPage.xaml/.cs           # Sessions table (country flag, OS, IP, HWID)
│   ├── SessionDetailPage.xaml/.cs      # Full session drill-down (passwords, cookies, cards, wallets, files)
│   ├── SearchPage.xaml/.cs             # Full-text search across stolen passwords
│   ├── BuildPage.xaml/.cs              # PE builder: file picker, config fields, build button
│   └── SettingsPage.xaml/.cs           # Telegram config, server port, auth token
│
├── Services/
│   ├── PanelServer.cs                  # ASP.NET Core embedded server
│   ├── LogProcessor.cs                 # ZIP extraction → EF Core insert
│   ├── BuildService.cs                 # PE patching: MIRAGECFG search → AES-GCM encrypt → DLL overlay
│   └── TelegramProxy.cs                # HTTP client forwarding logs to Telegram Bot API
│
├── Data/
│   └── AppDbContext.cs                 # EF Core SQLite context (8 DbSets)
│
├── Models/
│   └── Session.cs                      # Session, Password, Cookie, Card, Wallet, StolenFile, SystemInfo, Build
│
└── Helpers/
    └── Flags.cs                        # Country code → flag emoji map (250+ entries)
```

### 3.2 Layered Architecture

```
┌──────────────────────────────────────────────────────────┐
│  WPF Shell (MainWindow)                                  │
│  ┌──────────┬───────────┬────────┬────────┬──────────┐   │
│  │Dashboard │ Sessions  │ Build  │ Search │ Settings │   │
│  └────┬─────┴─────┬─────┴───┬────┴───┬────┴────┬─────┘   │
│       │           │         │        │         │         │
│  ┌────┴───────────┴─────────┴────────┴─────────┴────┐    │
│  │  Service Layer                                     │    │
│  │  PanelServer | LogProcessor | BuildService | TP   │    │
│  └──────────────────────────┬────────────────────────┘    │
│                             │                             │
│  ┌──────────────────────────┴────────────────────────┐    │
│  │  Data Layer (EF Core + SQLite)                     │    │
│  │  AppDbContext → mirage_panel.db                    │    │
│  └───────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

### 3.3 ASP.NET Core Server (embedded)

Self-hosted on `http://127.0.0.1:5000` with three endpoints:

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/log` | POST | Bearer token | Accept multipart archive + metadata → extract → store to SQLite |
| `/api/stats` | GET | None | Dashboard JSON: total/today counts, geo dist, browser pie, 30-day timeline, top domains |
| `/api/search?q=` | GET | Bearer token | Full-text search across password URL/username/value |

Middleware: rate limiting (60 req/min/IP), payload limit (100 MB), IP-based brute-force lockout (10 failed auths).

### 3.4 Database Schema (SQLite)

```
builds (id, version, config_hash, file_size, created_at)
sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
  ├── passwords (id, session_id, url, username, password_value, browser)
  ├── cookies (id, session_id, domain, name, value, path)
  ├── cards (id, session_id, number, exp_month, exp_year, holder, cvc)
  ├── wallets (id, session_id, name, path)
  ├── stolen_files (id, session_id, filename, size)
  └── system_info (session_id, cpu, gpu, ram, os, screen, hostname, local_ip, mac)
```

### 3.5 Dashboard Features

- Material Design dark theme (MaterialDesignThemes 5.3.1)
- Stats cards: sessions today, total passwords, total wallets, online count
- Country heatmap (flag emoji + count list)
- 30-day timeline (LiveCharts2 LineSeries)
- Browser pie chart (LiveCharts2 PieChart)
- Top 10 most reused password domains
- Auto-refresh every 5 seconds

---

## 4. Data Flow

```
Victim Machine                          C2 Server
─────────────────                      ──────────────────
                                          Mirage.Panel (WPF)
Zig EXE executes                           ├── PanelServer (ASP.NET Core)
  │                                        │     port 5000, loopback
  ├── Collect phase                        │
  │   ├── system_info (OS, HW, net)        │
  │   ├── chromium (36 browsers)           │
  │   ├── firefox (10 browsers)            │
  │   ├── wallets (72 total)               │
  │   ├── messengers (4 apps)              │
  │   └── gaming (5 platforms)             │
  │                                        │
  ├── Write to %TEMP%\<random_hex>\        │
  │                                        │
  ├── ZIP (in-memory PKZIP Store)          │
  │                                        │
  ├── Encrypt (ChaCha20-Poly1305)          │
  │   key = PBKDF2(SEED, nonce)            │
  │                                        │
  ├── HTTPS POST ──────────────────────►   │
  │   /api/log                             │  POST /api/log
  │   Content-Type: multipart/form-data    │  ├── metadata (JSON)
  │   Authorization: Bearer <token>        │  ├── archive (encrypted ZIP)
  │                                        │  └── LogProcessor.Process()
  ├── HTTPS POST ──────────────────────►   │      ├── Parse ZIP entries
  │   api.telegram.org/bot<TOKEN>/          │      ├── Extract passwords/cookies/cards
  │   sendDocument (backup)                │      ├── Insert into SQLite
  │                                        │      └── Return Session
  └── Delete %TEMP% dir                    │
     (self-delete via cmd)                 ├── TelegramProxy forward (optional)
                                              POST to api.telegram.org
                                                                  
                                                                  User views Dashboard
                                                                    ├── GET /api/stats
                                                                    ├── Session list
                                                                    └── Drill-down detail
```

---

## 5. Build Pipeline

```
┌────────────────────────────────────────────────────────────────────┐
│  BuildService (C#, inside Mirage.Panel)                            │
│                                                                    │
│  1. Browse to select Mirage.Stealer.exe  ───  zig build            │
│  2. Browse to select MirageDecryptor.dll  ───  cl /MT /DLL         │
│  3. Fill config fields (C2, TG token, flags)                       │
│  4. Click [Build]                                                   │
│     ├── Load Mirage.Stealer.exe as byte[]                          │
│     ├── Scan .rdata for signature "MIRAGECFG"                      │
│     ├── AES-GCM encrypt config JSON with random key                │
│     │   Format: [key:32][nonce:12][tag:16][ciphertext:N]           │
│     ├── Overwrite placeholder bytes in .rdata                      │
│     ├── Append MirageDecryptor.dll as overlay (optional)           │
│     └── Save output EXE                                            │
│                                                                    │
│  Output PE Layout:                                                 │
│    .text    → Zig machine code (no CRT)                            │
│    .rdata   → XOR-encrypted config + "MIRAGECFG" sig               │
│    .data    → SSN globals, runtime state                           │
│    .rsrc    → (optional) version info                              │
│    overlay  → (optional) MirageDecryptor.dll                       │
└────────────────────────────────────────────────────────────────────┘
```

### Build Commands

```bash
# Stealer
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseSmall -fsingle-threaded

# Decryptor DLL
cl /O2 /MT /DLL mira_decryptor.cpp /Fe:MirageDecryptor.dll /link ole32.lib

# Panel
dotnet build -c Release

# Tests
zig build test -Dtarget=x86_64-windows
```

---

## 6. Security Model

### 6.1 Hash-Resolved APIs

- No direct imports for sensitive functions
- DLLs resolved by walking PEB `Ldr` list, comparing XOR-encrypted CRC32 hashes
- Functions resolved by scanning export directory, comparing XOR-encrypted CRC32 hashes
- `LdrGetProcedureAddress` used as bootstrap for system DLLs

### 6.2 Halo's Gate Syscalls

- 22 NT syscalls resolved dynamically from ntdll export table
- Neighbor walk (TartarusGate) for hooked stubs
- Random `syscall; ret` gadget from pool of 64 (scanned from ntdll .text)
- Win11 24H2 prologue support

### 6.3 XOR-Encrypted Strings

- All sensitive strings XOR'd at comptime using `STRING_KEY_ENC`
- API names, DLL names, paths, tokens — nothing in plaintext in binary
- `xorDecrypt` at runtime produces plaintext in stack buffer, zeroed after use

### 6.4 AES-GCM Build Config

- Builder generates random AES-256 key per build
- Config JSON (C2, TG token, flags) encrypted → placed in .rdata
- Binary contains encoded: key || nonce || tag || ciphertext
- Stealer decrypts at runtime before first use

---

## 7. Module Dependency Graph

```
main.zig
  ├── config (anonymous import)
  │     └── (no deps)
  ├── types/
  │     ├── types.zig          → (standalone, no deps)
  │     ├── peb.zig            → types
  │     ├── hash.zig           → config
  │     ├── peb_walk.zig       → types, hash
  │     ├── export_resolve.zig → types, hash, peb, peb_walk
  │     └── util.zig           → (standalone)
  │
  ├── syscalls/
  │     ├── engine.zig         → types, hash, peb_walk, export_resolve, stubs (comptime)
  │     ├── stubs.zig          → (global asm, references engine.zig SSN globals + gadget.zig pool)
  │     ├── gadget.zig         → types, hash, peb_walk
  │     └── dbg.zig            → peb, hash
  │
  ├── evasion/
  │     ├── evasion.zig        → types, config, engine, hash
  │     ├── anti_analysis.zig  → types, config, engine, evasion, dbg
  │     ├── peb_hide.zig       → types, peb, engine
  │     └── mutex.zig          → engine, hash
  │
  ├── crypto/
  │     ├── dpapi.zig          → hash, peb_walk, export_resolve
  │     ├── chrome_crypto.zig  → std.crypto, config
  │     ├── chrome_key.zig     → (standalone Base64 + JSON parser)
  │     ├── aes_gcm_bcrypt.zig → hash, peb_walk, export_resolve
  │     ├── chacha_poly.zig    → std.crypto
  │     ├── archive_crypt.zig  → config, hash, chacha_poly
  │     └── dll_loader.zig     → export_resolve
  │
  ├── parsers/
  │     ├── sqLoot.zig         → file_io (for SQLite page access)
  │     └── file_io.zig        → engine, types
  │
  ├── browsers/
  │     ├── chromium.zig       → chromium_paths, chromium_login/cookies/cards/history/autofill/bookmarks, appbound, crypto, parsers
  │     ├── chromium_paths.zig → hash (comptime XOR paths)
  │     ├── chromium_login.zig → sqLoot, chrome_crypto, file_io
  │     ├── chromium_cookies.zig → sqLoot, chrome_crypto, file_io
  │     ├── chromium_cards.zig → sqLoot, file_io
  │     ├── chromium_history.zig → sqLoot, file_io
  │     ├── chromium_autofill.zig → sqLoot, file_io
  │     ├── chromium_bookmarks.zig → file_io
  │     ├── appbound.zig       → export_resolve, engine, dll_loader
  │     ├── appbound_inject.zig → export_resolve, engine
  │     ├── firefox.zig        → firefox_paths, firefox_login/cookies/history/bookmarks, parsers
  │     ├── firefox_paths.zig  → hash
  │     ├── firefox_asn1.zig   → (standalone DER parser)
  │     ├── firefox_login.zig  → sqLoot, firefox_asn1, aes_gcm_bcrypt, file_io
  │     ├── firefox_cookies.zig → sqLoot, file_io
  │     ├── firefox_history.zig → sqLoot, file_io
  │     └── firefox_bookmarks.zig → sqLoot, file_io
  │
  ├── wallets/
  │     ├── wallets.zig        → wallet_extensions, wallet_desktop
  │     ├── wallet_extensions.zig → file_io
  │     └── wallet_desktop.zig → file_io
  │
  ├── messengers/
  │     ├── messengers.zig     → discord, telegram, signal, pidgin
  │     ├── discord.zig        → file_io
  │     ├── telegram.zig       → file_io
  │     ├── signal.zig         → file_io
  │     └── pidgin.zig         → file_io, parser for XML
  │
  ├── gaming/
  │     ├── gaming.zig         → steam, uplay, minecraft, battlenet, roblox
  │     ├── steam.zig          → file_io, engine (registry)
  │     ├── uplay.zig          → file_io
  │     ├── minecraft.zig      → file_io
  │     ├── battlenet.zig      → file_io
  │     └── roblox.zig         → dpapi, file_io
  │
  ├── system/
  │     ├── system_info.zig    → os_info, hardware, network_info, wifi, screenshot, grabber
  │     ├── os_info.zig        → engine
  │     ├── hardware.zig       → engine, export_resolve (kernel32)
  │     ├── network_info.zig   → export_resolve (kernel32), ws2? (hash-resolved)
  │     ├── wifi.zig           → dll_loader (wlanapi)
  │     ├── screenshot.zig     → dll_loader (gdi32)
  │     └── grabber.zig        → file_io
  │
  └── network/
        ├── ws2.zig            → export_resolve, dll_loader (ws2_32)
        ├── schannel.zig       → dll_loader (secur32), export_resolve
        ├── tls_socket.zig     → ws2, schannel
        ├── http.zig           → tls_socket
        ├── panel_http.zig     → http
        ├── telegram.zig       → http
        └── zip.zig            → (standalone CRC32 LUT + PKZIP)
```

---

## 8. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Zig over C++ | Comptime obfuscation, zero-CRT, inline asm without MASM |
| PEB-walk + hash resolution | No IAT entries for sensitive APIs → static analysis harder |
| ChaCha20-Poly1305 over AES-GCM | Faster on CPUs without AES-NI, constant-time |
| Custom SQLite parser | Avoid loading sqlite3.dll (detectable import), handle locked DBs |
| Single-threaded | Stealth — no thread creation anomalies, simpler control flow |
| WPF + embedded ASP.NET | Single exe deployment, no separate server process |
| Builder inside Panel | No separate builder project — reduces build complexity |
| MirageDecryptor.dll overlay | Chrome v20+ App-Bound requires separate process + COM |
