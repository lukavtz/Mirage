# Mirage Stealer — Roadmap

## Phases Overview

```
Phase 1: Foundation             ████████████████████  22/22 ✅
Phase 2: Core Evasion           ████████████████████  11/11 ✅
Phase 3: Crypto                 ████████████████████  12/12 ✅
Phase 4: Data Theft Core        ████████████████████  48/48 ✅
Phase 5: Network                ████████████████████  8/8 ✅
Phase 6: Panel + Builder        ████████████████████  31/31 ✅
Phase 7: Integration            ████████████████████  10/10 ✅
Phase 8: Unit Tests             ████████████████████  192/192 ✅
Phase 8b: Integration Tests     ░░░░░░░░░░░░░░░░░░░░   0/8
Phase 9: Engine Hardening       ████████████████████  27/27 ✅
Phase 10: Data Theft Expansion  ████████████████████  22/22 ✅
Phase 11: Additional Theft      ░░░░░░░░░░░░░░░░░░░░   0/16
Phase 12: Monetisation          ░░░░░░░░░░░░░░░░░░░░   0/16
Phase 13: Infrastructure        ░░░░░░░░░░░░░░░░░░░░   0/16
Phase 14: Panel Premium         ░░░░░░░░░░░░░░░░░░░░   0/40
Phase 15: Commercial Launch     ░░░░░░░░░░░░░░░░░░░░   0/16
```

**Total: 142/142 ✅ Done + 192 unit tests ✅ + 183 ⬜ New**

---

## Phase 1: Foundation (src/types/, src/syscalls/, src/config/) ✅

### 1.1 Project Setup
- [x] `build.zig` — create build configuration (x86_64-windows, ReleaseSmall, freestanding)
- [x] `build.zig.zon` — package manifest _(removed: not needed for Zig 0.16)_
- [x] `.gitignore` — Zig-specific
- [x] `src/main.zig` — entry point with `pub fn main()` stub
- [x] `config_decrypt.zig` — runtime config decryption
- [x] Verify `zig build` produces working EXE with no CRT (54,784 bytes)

### 1.2 NT Structures (src/types/)
- [x] `types.zig` — Windows NT types + IMAGE + PEB structures (HANDLE, NTSTATUS, PEB, IMAGE_NT_HEADERS64, SYSTEM_BASIC_INFORMATION, CONTEXT и др.)
- [x] `peb.zig` — `getPeb()` inline asm helper

### 1.3 Hash & Utility (src/types/)
- [x] `hash.zig` — XOR-encrypted comptime hash + xorEncrypt/xorDecrypt
- [x] `util.zig` — `secureZero()`, `trimmedLen()`, `readU32Le()`
- [x] Tests: hash determinism, case-insensitivity, uniqueness, encrypted hash

### 1.4 Syscall Engine (src/syscalls/)
- [x] `engine.zig` — Halo's Gate SSN resolution, hook detection, neighbor walk (TartarusGate)
- [x] `stubs.zig` — 22 indirect syscall stubs via global asm (gadget pool dispatch)
- [x] `gadget.zig` — `syscall; ret` gadget scan from ntdll .text (64 gadgets)
- [x] Win11 24H2 prologue support

### 1.5 Comptime Config (src/config/)
- [x] `config.zig` — XOR-encrypted placeholders (SEED, STRING_KEY_ENC, TG token/ChatID, C2, flags, thresholds)

### 1.6 PEB Module Resolution
- [x] `peb_walk.zig` — `getModuleByHash()` — find loaded DLL by hash
- [x] `export_resolve.zig` — `getFunctionByHash()` + `initNativeResolver()` (LdrGetProcedureAddress bootstrap)

---

## Phase 2: Core Evasion (src/evasion/) ✅

### 2.1 Anti-Analysis Gate
- [x] `anti_analysis.zig` — weighted scoring function
- [x] Debugger check: NtQueryInformationProcess(ProcessDebugPort)
- [x] RAM check: NtQuerySystemInformation
- [x] Screen check: NtUserGetSystemMetrics (win32u)
- [x] CPU core check: NtQuerySystemInformation
- [x] VM registry: BIOS проверка (VMware, VirtualBox, QEMU, Xen, Bochs)
- [x] Timing check: rdtsc + NtDelayExecution + rdtsc delta
- [x] Threshold configuration in config.zig

### 2.2 PEB Hide
- [x] `peb_hide.zig` — unlinkModule() — remove from all 3 LDR lists

### 2.3 Mutex / Single Instance
- [x] `mutex.zig` — unique mutex via NtCreateEvent

---

## Phase 3: Crypto (src/crypto/) ✅

### 3.1 DPAPI
- [x] `dpapi.zig` — CryptUnprotectData via PEB-resolved crypt32.dll

### 3.2 AES-GCM (Chrome Decryption)
- [x] `chrome_crypto.zig` — PBKDF2 + AES-256-GCM decrypt
- [x] `chrome_key.zig` — JSON Local State + Base64 decode

### 3.3 ChaCha20-Poly1305
- [x] `chacha_poly.zig` — AEAD encrypt-then-MAC

### 3.4 Archive Encryption
- [x] `archive_crypt.zig` — Encrypt ZIP with ChaCha20-Poly1305

### 3.5 BCrypt CNG Fallback
- [x] `aes_gcm_bcrypt.zig` — BCrypt CNG AES-GCM fallback

### 3.6 DLL Loader
- [x] `dll_loader.zig` — LdrLoadDll wrapper

---

## Phase 4: Data Theft Core ✅

### 4.1 sqLoot — SQLite Parser
- [x] `sqLoot.zig` — header/page/varint/record/overflow/column parsing
- [x] `file_io.zig` — file mapping via NtCreateFile + NtCreateSection + NtMapViewOfSection

### 4.2 Chrome Decryption
- [x] Chrome AES-GCM decrypt + Local State parser + BCrypt CNG
- [x] `appbound.zig` — COM Elevator IElevator::DecryptData (Chrome v20+)
- [x] `appbound_inject.zig` — Self-copy + CreateProcessAsUser

### 4.3 Chromium Browsers (36 шт)
- [x] `chromium_paths.zig` — 36 browser paths
- [x] `chromium_login.zig`, `chromium_cookies.zig`, `chromium_cards.zig`
- [x] `chromium_history.zig`, `chromium_autofill.zig`, `chromium_bookmarks.zig`
- [x] `chromium.zig` — master orchestrator

### 4.4 Firefox / Gecko (10 шт)
- [x] `firefox_paths.zig` — 10 Gecko paths
- [x] `firefox_asn1.zig`, `firefox_login.zig`, `firefox_cookies.zig`
- [x] `firefox_history.zig`, `firefox_bookmarks.zig`
- [x] `firefox.zig` — master orchestrator

### 4.5 Wallets (72 шт)
- [x] `wallet_extensions.zig` — 62 extension directories
- [x] `wallet_desktop.zig` — 10 desktop wallets
- [x] `wallets.zig` — master orchestrator

### 4.6 Messengers (4 шт)
- [x] `discord.zig` — LevelDB token extraction
- [x] `telegram.zig` — tdata session files
- [x] `signal.zig` — Signal config + sql
- [x] `pidgin.zig` — accounts.xml + logs
- [x] `messengers.zig` — orchestrator

### 4.7 Gaming (5 шт)
- [x] `steam.zig`, `uplay.zig`, `minecraft.zig` (17 launchers)
- [x] `battlenet.zig`, `roblox.zig`
- [x] `gaming.zig` — orchestrator

### 4.8 System Info
- [x] `os_info.zig`, `hardware.zig`, `network_info.zig`
- [x] `wifi.zig`, `screenshot.zig`, `grabber.zig`
- [x] `system_info.zig` — master collector

---

## Phase 5: Network (src/network/) ✅

### 5.1 TLS via SChannel
- [x] `ws2.zig` — Winsock (hash-resolved)
- [x] `schannel.zig` — secur32.dll TLS handshake
- [x] `tls_socket.zig` — TCP + TLS wrapper

### 5.2 Panel Protocol
- [x] `http.zig` — HTTP/1.1 client, multipart
- [x] `panel_http.zig` — POST /api/log with Bearer

### 5.3 Telegram Protocol
- [x] `telegram.zig` — POST /botTOKEN/sendDocument

### 5.4 ZIP Creation
- [x] `zip.zig` — PKZIP Store (CRC32 LUT)

---

## Phase 6: Panel + Builder (Mirage.Panel) ✅

### 6.1 Project Setup
- [x] WPF project (.NET 10) + NuGet: MaterialDesignThemes, LiveCharts2, SQLitePCLRaw
- [x] Dark theme, DI container, embedded resources

### 6.2 ASP.NET Core Server
- [x] Services/PanelServer.cs — loopback:5000
- [x] POST /api/log, GET /api/stats, GET /api/search
- [x] Token auth middleware + rate limiting (60 req/min) + brute-force protection

### 6.3 Database
- [x] EF Core SQLite: Session, Password, Cookie, Card, Wallet, StolenFile, SystemInfo, Build
- [x] LogProcessor.cs — ZIP → parse → DB
- [x] BuildService.cs — PE patching (MIRAGECFG → XOR → overlay)

### 6.4 Dashboard UI
- [x] 5 pages: Dashboard, Sessions, Session Detail, Search, Settings
- [x] Charts: country heatmap, browser pie, timeline, top passwords

### 6.5 Builder
- [x] BuildPage.xaml — PE patching, DLL overlay, version management

### 6.6 Telegram Proxy
- [x] Telegram bot forwarding + inline summary

---

## Phase 7: Integration & Hardening ✅

### 7.1 Build Pipeline
- [x] build.zig — ReleaseSmall, strip, single-threaded, Windows subsystem
- [x] scripts/build_and_verify.ps1 — CI + IAT verification

### 7.2 Security Review
- [x] XOR-encrypted strings (29 files), PEB walk, Win11 24H2 support

### 7.3 Documentation
- [x] ARCHITECTURE.md, OPSEC.md, TESTING.md, spec.md, overall-plan.md
- [x] features-to-implement.md, code-audit-report.md

---

## Phase 8: Unit Tests ✅

### 8.1 Существующие тесты (192 assertions в main.zig)
- [x] Foundation: PEB, SSN, gadget pool, memory alloc/free/protect (17 checks)
- [x] Evasion: RAM, CPU, screen, VM registry, timing, PEB hide, mutex (10 checks)
- [x] Crypto: DPAPI, AES-GCM, ChaCha20-Poly1305, archive, Chrome key (13 checks)
- [x] SQLite: header, varint, serial types, columns, records, overflow (10 checks)
- [x] Browser: 46 browsers, Chrome decrypt, App-Bound, bookmarks (13 checks)
- [x] Wallets: 62 extensions + 10 desktop (8 checks)
- [x] Messengers: Discord tokens, Telegram files (14 checks)
- [x] Gaming: 5 sub-modules aggregation (2 checks)
- [x] System: OS, hardware, grabber masks (9 checks)
- [x] Network: CRC32, ZIP, uploadLog params (9 checks)

## Phase 8b: Integration Tests ⬜
- [ ] Full pipeline: collect → archive → encrypt → send → panel receives
- [ ] Size check: verify < 150 KB output EXE
- [ ] Static check: scan with Windows Defender
- [ ] Cross-module: all collectors run without crashing
- [ ] Memory leak check: allocations freed
- [ ] Error isolation: one module failure doesn't crash others
- [ ] Network timeout: 15s timeout works
- [ ] Panel end-to-end: receive log → SQLite → return stats

---

## Phase 9: Engine Hardening ⬜

### 9.1 Syscall — EDR Evasion
- [x] `evasion/ntdll_unhook.zig` — NTDLL userland hook removal через \KnownDlls (clean .text mapping)
- [x] `syscalls/stack_spoof.zig` — Stack spoofing (ROP desync через RtlVirtualUnwind)
- [x] `syscalls/freshycalls.zig` — FreshyCalls: динамические stub-заглушки (сортировка Zw* по VA)
- [x] `syscalls/ssn_obfuscation.zig` — Runtime SSN encryption (XOR ключ в config, расшифровка в stub)
- [x] `evasion/amsi_bypass.zig` — AMSI bypass (AmsiScanBuffer → 0xC3 RET)
- [x] `evasion/etw_bypass.zig` — ETW bypass (ntdll!EtwEventWrite → 0xC3 RET)
- [x] `evasion/registry_unhook.zig` — Registry hook верификация (уже через сисколлы)
- [x] NtOpenSection, NtUnmapViewOfSection — добавить сисколлы (для \KnownDlls unhook)
- [x] NtCreateThreadEx, NtOpenProcess, NtResumeThread, NtSuspendThread — добавить сисколлы
- [x] `browsers/dbsc_bypass.zig` — Chrome 147+ DBSC cookies bypass через шеллкод

### 9.2 Evasion — Расширение анти-анализа
- [x] `evasion/process_list.zig` — Process list check (36 процессов, хеш-сравнение)
- [x] `evasion/detection.zig` — Disk < 60GB → sandbox
- [x] `evasion/detection.zig` — Uptime < 30 min → sandbox
- [x] `evasion/detection.zig` — Mouse отсутствует → sandbox
- [x] `evasion/detection.zig` — Geo-block: IP + раскладка + язык + timezone (тройная проверка)
- [x] `PanelServer.cs` — GET /api/geo — серверная валидация гео
- [x] `evasion/detection.zig` — HWID: SHA-256 от disk serial + motherboard + ProductID
- [x] `config.zig` — SLEEP_MIN_MS/SLEEP_JITTER usage в main.zig pipeline
- [x] `config.zig` — HWID_BAN_LIST (пустой по умолчанию, заполняется в Builder)
- [x] `anti_analysis.zig` — Интеграция всех 5 новых checks + weighted scoring

### 9.3 Self-Defense
- [x] `engine.zig` + `stubs.zig` — NtSetInformationFile сисколл для FileDispositionInfo
- [x] `cleanup/self_delete.zig` — 3 уровня: NtSetInformationFile → MoveFileEx → cmd batch
- [x] `cleanup/temp_wipe.zig` — Temp directory wiping через NtDeleteFile
- [x] `evasion/uac_bypass.zig` — Fodhelper UAC bypass (HKCU\ms-settings)
- [x] `main.zig` — Интеграция self-delete + temp wipe в конец pipeline

---

## Phase 10: Data Theft Expansion ⬜

### 10.1 Browser — Dynamic Scan
- [x] `browsers/browser_scanner.zig` — Dynamic %LOCALAPPDATA% scan (Local State → os_crypt)
- [x] `browsers/browser_scanner.zig` — Dynamic %APPDATA% scan (profiles.ini → Gecko)
- [x] `browsers/browser_scanner.zig` — Profile enumeration (Default, Profile N)
- [x] `chromium_paths.zig` — Expand to 70+ (Canary, Dev, Beta, CryptoTab, Avast, UC, QQ, 360 и др.)
- [x] `firefox_paths.zig` — Expand to 30+ (LibreWolf, Floorp, IceCat, Firefox Nightly/Dev/Beta и др.)

### 10.2 Browser — Google & MS OAuth
- [x] `browsers/google_tokens.zig` — Token Service → MultiLogin, GAIA ID, access tokens
- [x] `browsers/outlook_tokens.zig` — Outlook OAuth tokens (MSAL cache + registry)
- [x] `browsers/outlook_tokens.zig` — Classic Outlook credentials (registry)
- [x] `browsers/chromium_localstorage.zig` — Local Storage data

### 10.3 Wallets — Расширение
- [x] `wallet_extensions.zig` — Add: Slope, Rise, HaloWallet, FuelWallet, Lace, DPal, Alby, HOT, 2FA, PM, Notes
- [x] `wallet_extensions.zig` — Add: 2FAS Authenticator, 2FAAuthenticator, KeepassXC, Norton PM, Avira PM, Passky PM, Padloc PM
- [x] `wallet_extensions.zig` — Add: Notion, Evernote, Google Keep notes
- [x] `wallet_desktop.zig` — Expand to 21+ (Bitcoin Core, Litecoin Core, Dogecoin Core, Dash Core, Armory, Bytecoin, MultiDoge, ElectrumLTC, ElectronCash, Zcoin/Firo, BitcoinGold)
- [x] `wallet_desktop.zig` — Deep collect: wallet.dat, configs
- [x] `wallets/wallet_inject.zig` — Exodus + Atomic app.asar injection locator

### 10.4 System — Расширение
- [x] `system/processes.zig` — List of running processes (NtQuerySystemInformation)
- [x] `system/applications.zig` — List of installed applications (registry Uninstall)
- [x] `system/clipboard.zig` — Clipboard content capture (user32)
- [x] `system/launch_info.zig` — Launch mode (Disk/Memory), executable path
- [x] `hardware.zig` — GPU detailed info (DriverVersion, VRAM)
- [x] `grabber.zig` — Rewrite: configurable rules (path + mask + exclude + depth + size + dedup)
- [x] `system_info.zig` — Integrate: launch_info, processes, applications, clipboard

### 10.5 Regex-граббер
- [ ] `system/regex_grabber.zig` — BIP39 seed phrase scanner (12/18/24 words)
- [ ] `system/regex_grabber.zig` — Private key scanner (BTC WIF, ETH hex, SOL base58, XMR)
- [ ] `system/regex_grabber.zig` — API keys / JWT tokens scanner
- [ ] `system/regex_grabber.zig` — In-memory only scan

### 10.6 Server-Side Processing (SSP)
- [ ] `browsers/ssp.zig` — Билд: копировать сырые .db, не открывать SQLite
- [ ] `browsers/ssp.zig` — Извлечь мастер-ключ из Local State
- [ ] `browsers/ssp.zig` — Отправить ключ + сырые .db на сервер
- [ ] `Panel/Services/ServerSideDecryptor.cs` — C# SQLite парсинг
- [ ] `Panel/Services/ServerSideDecryptor.cs` — AES-GCM расшифровка через BCrypt
- [ ] `Panel/Services/ServerSideDecryptor.cs` — App-Bound расшифровка на сервере
- [ ] `config.zig` — Флаг ENABLE_SSP

---

## Phase 11: Additional Theft Modules ⬜

### 11.1 Telegram моды
- [ ] `messengers/telegram_mods.zig` — Поиск по множеству путей
- [ ] `messengers/telegram_mods.zig` — AyuGram, 64Gram, Kotatogram
- [ ] `messengers/telegram_mods.zig` — Nekogram, Forkgram, Unigram, iMe

### 11.2 Дополнительные мессенджеры
- [ ] `messengers/session.zig` — Session messenger
- [ ] `messengers/tox.zig` — Tox/uTox profile
- [ ] `messengers/skype.zig` — Skype local data
- [ ] `messengers/viber.zig` — Viber data
- [ ] `messengers/element.zig` — Element (Matrix) session
- [ ] `messengers/whatsapp.zig` — WhatsApp Desktop

### 11.3 Discord Injection
- [ ] `messengers/discord_inject.zig` — JS injection into discord_desktop_core
- [ ] `messengers/discord_inject.zig` — BetterDiscord bypass
- [ ] `messengers/discord_inject.zig` — TokenProtector bypass
- [ ] `discord.zig` — MFA + encrypted tokens support

### 11.4 Gaming
- [ ] `gaming/epic.zig` — Epic Games Store auth
- [ ] `gaming/riot.zig` — Riot Games (LoL, VALORANT)

---

## Phase 12: Monetisation Modules ⬜

### 12.1 Clipper
- [ ] `clipper/clipper.zig` — OpenClipboard polling monitor
- [ ] `clipper/clipper.zig` — BTC (Legacy 1, SegWit 3, bech32 bc1)
- [ ] `clipper/clipper.zig` — ETH + EVM (0x...)
- [ ] `clipper/clipper.zig` — TRX, XMR, SOL, TON, LTC, DASH, DOGE, ADA, XLM
- [ ] `clipper/clipper.zig` — Non-resident (до перезагрузки)

### 12.2 Loader
- [ ] `loader/loader.zig` — HTTP download file from URL
- [ ] `loader/loader.zig` — .exe → CreateProcessW (NO_WINDOW)
- [ ] `loader/loader.zig` — .dll → LdrLoadDll
- [ ] `loader/loader.zig` — .ps1 → powershell -exec bypass
- [ ] `loader/loader.zig` — Multi-file (до 10), env var expansion, target dir

### 12.3 Keylogger
- [ ] `keylogger/keylogger.zig` — SetWindowsHookEx(WH_KEYBOARD_LL)
- [ ] `keylogger/keylogger.zig` — Key buffer in memory
- [ ] `keylogger/keylogger.zig` — Send with archive via panel_http

### 12.4 Webcam
- [ ] `system/webcam.zig` — AVICAP32: capCreateCaptureWindowW
- [ ] `system/webcam.zig` — WM_CAP_EDIT_COPY → Clipboard → save
- [ ] `system/webcam.zig` — Add screenshot to archive

---

## Phase 13: Infrastructure ⬜

### 13.1 Chunked Upload
- [ ] `network/chunked.zig` — Chunk splitting (1 MB)
- [ ] `network/chunked.zig` — Chunk retry (3 attempts)
- [ ] `network/chunked.zig` — Session management
- [ ] PanelServer.cs — POST /api/log/chunk
- [ ] PanelServer.cs — POST /api/log/complete
- [ ] PanelServer.cs — Chunk reassembly + validation

### 13.2 Прокладки (Redirect Proxies)
- [ ] `network/proxy.zig` — Level 1: Telegram post (t.me → C2)
- [ ] `network/proxy.zig` — Level 1: TON transaction parser
- [ ] `network/proxy.zig` — Level 1: Steam profile parser
- [ ] `network/proxy.zig` — Level 2: GitHub Releases parser
- [ ] `network/proxy.zig` — Level 3: VPS Bridge (SSH + nginx)
- [ ] `network/proxy.zig` — Proxy cache
- [ ] PanelServer.cs — Bridge management UI

### 13.3 VPN / FTP / Email
- [ ] `vpn/vpn.zig` — NordVPN, OpenVPN, ProtonVPN, ExpressVPN, Surfshark, CyberGhost, PIA, Windscribe, TunnelBear, Hotspot Shield, VyprVPN
- [ ] `ftp/ftp.zig` — FileZilla, WinSCP, Total Commander, Far Manager, CuteFTP, SmartFTP, FlashFXP, CoreFTP
- [ ] `email/email.zig` — Outlook, Thunderbird, Foxmail, eM Client, Windows Mail, Mailbird

---

## Phase 14: Panel Premium ⬜

### 14.1 Smart Filters & Search
- [ ] POST /api/search/advanced — multi-field search
- [ ] Column filters (country, IP, OS, build tag, date preset)
- [ ] Color-coded labels by domain tags
- [ ] Duplicate detection (HWID + IP) with counter
- [ ] "Empty logs" hide toggle
- [ ] Column blur settings (IP/страна/счётчики для скриншотов)
- [ ] DomainDetect table + auto-tagging
- [ ] Comments table + Bans table (HWID, IP, time, reason)

### 14.2 Log Detail
- [ ] Password reveal toggle
- [ ] Wallet names with icons
- [ ] In-browser archive preview
- [ ] Comment box per session
- [ ] Mark as viewed/checked
- [ ] Mass export: JSON, HTML, ZIP

### 14.3 Builder Improvements
- [ ] Build tags (custom text label)
- [ ] Module toggles (disable password/cookie/wallet)
- [ ] Custom icon (.ico) + manifest
- [ ] Custom startup delay (ms)
- [ ] Domain Detect config (paste domains)
- [ ] Download counter per build

### 14.4 Telegram Proxy — Множественные боты
- [ ] Multiple bot support (3/7/15 by tier)
- [ ] Bot per build configuration
- [ ] Notification filters (country, build tag, data type)
- [ ] Discord webhook notifications

### 14.5 UI/UX
- [ ] Light/dark theme toggle
- [ ] Collapsible sidebar
- [ ] Column visibility settings table

### 14.6 Team / Multi-user
- [ ] Users/Roles tables (admin, traffer, checker, vbiver)
- [ ] Invite codes with roles + expiration
- [ ] Worker management UI
- [ ] Session lock (checker takes → others hidden)
- [ ] Activity log per worker
- [ ] Ban management per worker
- [ ] API endpoints: GET /api/logs, POST /api/build, GET /api/stats/filtered

### 14.7 Cookie Restore / Google Restore
- [ ] Google Refresh Token → Access Token exchange
- [ ] Upload cookies + proxy config UI
- [ ] SOCKS5 proxy integration

### 14.8 Public Statistics
- [ ] Public link generation
- [ ] Metrics: total logs, crypto %, duplicates %, empty %
- [ ] Geo distribution (flag + country + count)

---

## Phase 15: Commercial Launch ⬜

### 15.1 Pricing & Licensing
- [ ] Finalize pricing (Starter $70, Pro $150, Team $350)
- [ ] License key generation system
- [ ] Subscription expiry enforcement
- [ ] Trial period (7 days) mechanism

### 15.2 Landing & Support
- [ ] Setup Telegram bot for sales/support
- [ ] Setup Exploit.in / XSS thread
- [ ] Refund policy documentation
- [ ] Referral program (20%) tracking

### 15.3 Resident Module (Botnet) — Premium
- [ ] Reverse proxy (traffic через бота)
- [ ] Reverse CMD shell
- [ ] Reverse PowerShell
- [ ] Self-update mechanism
- [ ] Blockchain-based C2 parsing (TON/STEEM)
- [ ] Panel management UI

### 15.4 OpSec & Cleanup
- [ ] Global runtime cleanup
- [ ] Full remorph (section names, entry point)
- [ ] Replace all proxy/bridge servers
- [ ] Final Defender/AV scan (< 5/70)

### 15.5 Morpher (Build Uniqueness)
- [ ] Junk code insertion (NOP/mov/xor)
- [ ] Section renaming (.c0de, .cnst, .vars)
- [ ] Entry point obfuscation
- [ ] IAT reordering + fake imports
- [ ] Target: 75%+ uniqueness per build

---

## Summary: Total Tasks

| Phase | Tasks | Est. Effort | Status |
|-------|-------|------------|--------|
| 1. Foundation | 22 | ✅ Done | **22/22** |
| 2. Core Evasion | 11 | ✅ Done | **11/11** |
| 3. Crypto | 12 | ✅ Done | **12/12** |
| 4. Data Theft Core | 48 | ✅ Done | **48/48** |
| 5. Network | 8 | ✅ Done | **8/8** |
| 6. Panel + Builder | 31 | ✅ Done | **31/31** |
| 7. Integration | 10 | ✅ Done | **10/10** |
| 8. Unit Tests | 192 | ✅ Pass | **192/192** |
| 8b. Integration Tests | 8 | 1 day | **0/8** |
| 9. Engine Hardening | 23 | 7 days | **0/23** |
| 10. Data Theft Expansion | 22 | ✅ Done | **22/22** |
| 11. Additional Theft | 16 | 4 days | **0/16** |
| 12. Monetisation | 16 | 5 days | **0/16** |
| 13. Infrastructure | 16 | 4 days | **0/16** |
| 14. Panel Premium | 40 | 9 days | **0/40** |
| 15. Commercial Launch | 16 | 7 days | **0/16** |
| **Total (done)** | **142 + 192 tests** | | **142/142 + 192/192 ✅** |
| **Total (new)** | **183** | **~45 days** | **0/183 ⬜** |

## Execution Sequence

### Sprint 1 (Дни 1-3): Quick Wins
- Phase 8b: 8 integration tests
- Phase 9.3: Self-delete + temp wipe + UAC bypass
- Phase 12.1: Clipper

### Sprint 2 (Дни 4-7): Data Coverage
- Phase 10.1: Dynamic browser scan + path expansions
- Phase 10.2: Google OAuth tokens
- Phase 11.1: Telegram mods

### Sprint 3 (Дни 8-12): Server-Side Processing + Monetisation
- Phase 10.6: Server-Side Processing (SSP) — ключевая фича
- Phase 12.2: Loader
- Phase 10.3: Wallet Injection + wallet expansion

### Sprint 4 (Дни 13-18): Infrastructure
- Phase 13.1: Chunked upload
- Phase 13.2: Proxies Level 1-2
- Phase 13.3: VPN/FTP/Email theft
- Phase 9.1: NTDLL unhook + stack spoofing + DBSC bypass

### Sprint 5 (Дни 19-25): Panel Upgrade
- Phase 14.1: Smart filters + column blur
- Phase 14.2: Log detail improvements
- Phase 14.3: Builder improvements
- Phase 14.4: Multiple TG bots + Discord webhooks
- Phase 14.5: UI/UX (theme toggle, sidebar, column config)

### Sprint 6 (Дни 26-32): Team & Premium
- Phase 14.6: Team/Multi-user system
- Phase 14.7: Cookie Restore
- Phase 14.8: Public stats + bans

### Sprint 7 (Дни 33-40): Advanced Features
- Phase 11.2: Additional messengers (Session, Tox, Skype, Viber, Element, WhatsApp)
- Phase 11.3: Discord injection
- Phase 11.4: Epic + Riot games
- Phase 10.4: System expansion + regex grabber
- Phase 12.3: Keylogger
- Phase 12.4: Webcam

### Sprint 8 (Дни 41-47): Final Hardening
- Phase 15.4: OpSec cleanup + remorph
- Phase 15.5: Morpher (75%+ uniqueness)
- Phase 9.2: Extended anti-analysis + geo-block

### Sprint 9 (День 48+): Launch
- Phase 15.1: Pricing & licensing
- Phase 15.2: Landing & support
- Phase 15.3: Resident module (botnet)
