# Eidos — Roadmap

**Eidos** — экосистема вредоносного ПО. **Mirage** — инфостилер внутри экосистемы.

---

## Архитектура экосистемы

```
EIDS ECOSYSTEM
├── Eidos Panel (Go + React Web) — центральное управление
│   ├── Сбор логов со всех модулей
│   ├── Билдер для каждого модуля
│   ├── Team / Multi-user система
│   ├── API для автоматизации
│   ├── PostgreSQL (Enterprise)
│   └── Dashboard + Smart Filters + Cookie Restore
│
├── Mirage Stealer (Zig, ~123 KB) — кража данных
│   ├── 100+ браузеров, 80+ кошельков, 12 мессенджеров, 7 игр
│   ├── 18 VPN clients, 7 2FA authenticators, 8 password managers
│   ├── Discord billing/gifts, seed phrase grabber (BIP39)
│   ├── Webcam capture, keylogger (WH_KEYBOARD_LL)
│   ├── SSP — серверная расшифровка
│   ├── NTDLL unhook, Stack spoofing, Gadget pool
│   ├── Anti-analysis (15 checks), Geo-block, HWID ban
│   ├── Persistence (4 метода: registry + scheduler + startup + WMI)
│   ├── Hosts file poisoning, Defender disable
│   ├── SOCKS5 reverse proxy
│   ├── Chrome Backstage Injection (live browser view)
│   ├── File grabber + Regex grabber (BIP39/PK/JWT)
│   └── Self-delete + self-update + UAC bypass
│
├── Eidos Loader (~30 KB, stage 1) — загрузчик
│   ├── Anti-analysis → HTTP GET payload → Run → Delete
│   └── Может развернуть: Mirage, Eidos Clipper, Eidos Keylogger
│
├── Eidos Clipper (~50 KB, persistent) — подмена адресов
│   ├── BTC/ETH/TRX/XMR/SOL/TON/LTC/DASH/DOGE/ADA/XLM
│   ├── Работает до перезагрузки
│   └── Независим от Mirage
│
├── Eidos Keylogger (~40 KB, persistent) — клавиатурный шпион
│   ├── WH_KEYBOARD_LL hook
│   └── Отправка логов на Panel
│
├── Eidos Webcam (~30 KB, одноразовый) — захват камеры
│   └── AVICAP32 → Clipboard → Save → Send
│
├── Eidos Resident (~80 KB, persistent) — ботнет-модуль
│   ├── Reverse proxy / CMD / PowerShell
│   ├── Self-update
│   └── Blockchain C2 (TON)
│
└── Eidos Morpher (Python/script) — билд-тайм обфускация
    ├── Junk code insertion
    ├── Section renaming
    └── 75%+ уникальности билда
```

---

## Phases Overview

```
Phase 1-11: Mirage Stealer Core  ████████████████████  142/142 ✅
Phase 8b: Integration Tests      ████████████████████   8/8 ✅

Phase 12-13: Eidos Ecosystem     ████████████████████  38/38 ✅
Phase 14: Eidos Panel (Web)      ██░░░░░░░░░░░░░░░░░░   2/11 ✅
Phase 15: Eidos Commercial       ░░░░░░░░░░░░░░░░░░░░   0/17
Phase 16: RAT & Stealer Int.     ███░░░░░░░░░░░░░░░░░   12/38 ⬜
```

**Total: 142/142 ✅ Done + 192 unit tests ✅ + 148 ⬜ New**

---

## Phase 1-11: Mirage Stealer Core ✅

Все 11 фаз выполнены. Полный функционал стилера:
- **Foundation**: 22/22 ✅ (PEB, syscalls, Halo's Gate, hash resolution, gadget pool)
- **Core Evasion**: 11/11 ✅ (RAM/CPU/screen/VM/timing/debugger, PEB hide, mutex)
- **Crypto**: 12/12 ✅ (DPAPI, AES-GCM, ChaCha20-Poly1305, BCrypt, PBKDF2)
- **Data Theft Core**: 48/48 ✅ (sqLoot, 46 browsers, 72 wallets, 5 messengers, 5 gaming, system info)
- **Network**: 8/8 ✅ (SChannel TLS, HTTP/1.1, Telegram API, ZIP, ws2_32)
- **Panel + Builder**: 31/31 ✅ (WPF + ASP.NET Core + EF Core SQLite + LiveCharts2)
- **Integration**: 10/10 ✅ (build scripts, XOR strings, docs)
- **Unit Tests**: 192/192 ✅ (все модульные тесты)
- **Engine Hardening**: 27/27 ✅ (NTDLL unhook, stack spoofing, FreshyCalls, SSN obfuscation, AMSI/ETW, Registry check, DBSC bypass, process list, disk/uptime/mouse/geo, HWID, self-delete, temp wipe, UAC bypass)
- **Data Theft Expansion**: 33/33 ✅ (browser_scanner, Chrome 70+ paths, Gecko 30+ paths, Google OAuth, Outlook OAuth, Chromium LocalStorage, wallet_extensions 82 IDs, wallet_desktop 21 wallets, wallet_inject, SSP, processes, applications, clipboard, launch_info, GPU details, grabber rewrite, regex_grabber BIP39/PK/JWT)
- **Additional Theft**: 17/17 ✅ (Telegram mods 7 clients, Session, Tox, Skype, Viber, Element, WhatsApp, Discord injection + BetterDiscord + TokenProtector, Epic Games, Riot Games)

---

## Phase 8b: Integration Tests ✅
- [x] Test 1: Full pipeline (report → ZIP → encrypt → decrypt → verify)
- [x] Test 2: Size check (zig build test + zig build pass)
- [x] Test 3: Cross-module (6 collectors run without crashing)
- [x] Test 4: Memory leak check (repeated calls stable)
- [x] Test 5: Error isolation (catch handles failures)
- [x] Test 6: Network timeout (connection to unreachable host)
- [x] Test 7: ZIP integrity (headers + EOCD + multiple files)
- [x] Test 8: Crypto roundtrip (ChaCha20-Poly1305 encrypt/decrypt + tamper detection)

---

## Phase 12: Eidos Ecosystem — Standalone Modules ⬜

> Эти модули — отдельные проекты, которые могут работать независимо.
> Mirage Stealer может их загрузить и запустить после отработки.

### 12.1 Eidos Clipper (модуль внутри Mirage, build: zig build)
- [x] OpenClipboard polling мониторинг (GetClipboardSequenceNumber)
- [x] BTC (Legacy 1, SegWit 3, bech32 bc1, bc1p)
- [x] ETH + EVM, TRX, SOL, TON, LTC, DASH, DOGE, ADA, XLM, BCH
- [x] Seed phrase scanner (BIP39 wordlist)
- [x] Регистрация в автозагрузке (HKCU\...\Run)
- [x] Отправка логов на Eidos Panel

### 12.2 Eidos Loader (отдельный проект, D:\...\Loaders\EidosLoader)
- [x] Anti-analysis → HTTP GET → Module stomping → Execute
- [x] .exe → CreateProcessW (CREATE_NO_WINDOW)
- [x] .dll → LdrLoadDll
- [x] .ps1 → powershell -exec bypass
- [x] DoH, Native TLS, JA3/JA4 spoofing
- [x] Может развернуть Mirage Stealer и Eidos Clipper

### 12.3 Eidos Keylogger (модуль внутри Mirage Stealer)
- [x] `keylogger/keylogger.zig` — WH_KEYBOARD_LL hook + message loop + unicode support
- [x] `keylogger/keylogger.zig` — Window title tracking, special keys, circular buffer
- [x] `keylogger/keylogger.zig` — Send to Panel every N minutes via existing HTTP stack
- [x] `config.zig` — ENABLE_KEYLOGGER флаг (false по умолчанию)

---

## Phase 13: Mirage Stealer — Infrastructure ⬜

> Улучшения самого стилера Mirage.

### 13.1 Chunked Upload
- [x] `network/chunked.zig` — Chunk splitting (1 MB) + retry (3 attempts) + session management
- [x] `PanelServer.cs` — POST /api/log/chunk + POST /api/log/complete + reassembly

### 13.2 VPN / FTP / Email Clients
- [x] `vpn/vpn.zig` — 13 VPN clients (NordVPN, OpenVPN, ProtonVPN, ExpressVPN, Surfshark, CyberGhost, PIA, Windscribe, TunnelBear, Hotspot Shield, VyprVPN, WireGuard, Mullvad)
- [x] `ftp/ftp.zig` — 8 FTP clients (FileZilla, WinSCP, Total Commander, Far Manager, CuteFTP, SmartFTP, FlashFXP, CoreFTP)
- [x] `email/email.zig` — 6 email clients (Outlook, Thunderbird, Foxmail, eM Client, Windows Mail, Mailbird)

### 13.3 ICQ Messenger
- [x] `messengers/icq.zig` — Сбор ICQ данных (%APPDATA%\ICQ\0001\)
- [x] `messengers/messengers.zig` — integrated icq

### 13.4 Firefox Extensions (wallets + 2FA)
- [x] `browsers/firefox_extensions.zig` — Сбор XPI + IndexedDB + Local Storage из moz-extension-*
- [x] `system_info.zig` — integrated vpn/ftp/email

### 13.5 Redirect Proxies (Bridges)
- [x] `network/proxy.zig` — Level 1: Telegram post parser (t.me → C2 URL)
- [x] `network/proxy.zig` — Level 2: GitHub Releases parser
- [x] `network/proxy.zig` — Level 3: Resolver framework
- [x] `PanelServer.cs` — Bridge management API stub (GET /api/bridges)

### 13.6 Firewall / Anti-Flood (Panel)
- [x] `PanelServer.cs` — Configurable IP-based rate limiting
- [x] `PanelServer.cs` — Bot detection (User-Agent, Content-Type checks)
- [x] `PanelServer.cs` — Brute-force protection (permanent IP ban after N failed auth)
- [x] `Data/AppDbContext.cs` — Ban table (HWID + IP, time, reason)
- [x] `Models/Ban.cs` — Ban entity model

---

## Phase 14: Eidos Panel Premium ⬜

> Все функции панели управления.

### 14.1 Smart Filters & Search
- [ ] POST /api/search/advanced — multi-field search (domain, OS, wallet, browser, date range)
- [ ] Column filters (country, IP, OS, build tag, date preset: today/7d/30d)
- [ ] Color-coded labels by domain tags
- [ ] Duplicate detection (HWID + IP) with counter
- [ ] "Empty logs" hide toggle
- [ ] Column blur settings (размыть IP/страну/счётчики для скриншотов)
- [ ] DomainDetect table + auto-tagging on log import
- [ ] Custom filter presets catalog (Steam, Crypto, Email domains)

### 14.2 Log Detail Improvements
- [ ] Password reveal toggle (show/hide)
- [ ] Wallet names with icons
- [ ] In-browser archive preview (view files without downloading ZIP)
- [ ] Mark as viewed/checked
- [ ] Mass export: JSON, HTML, ZIP (без ограничений)

### 14.3 Builder Improvements
- [ ] Build tags (custom text label per build)
- [ ] Module toggles (disable password/cookie/wallet/module individually)
- [ ] Custom icon (.ico upload) + manifest
- [ ] Custom startup delay (ms)
- [ ] Domain Detect config (paste domains list for auto-tagging)
- [ ] Download counter per build

### 14.4 Telegram Proxy — Multiple Bots
- [ ] Multiple bot support (3/7/15 by tier)
- [ ] Bot per build configuration
- [ ] Notification filters (country, build tag, data type, counts)
- [ ] Discord webhook notifications
- [ ] Custom HTTP webhook notifications

### 14.5 UI/UX
- [ ] Light/dark theme toggle
- [ ] Collapsible sidebar
- [ ] Column visibility settings (checkboxes: IP, country, tags, counters)

### 14.6 Comments / Chat System
- [ ] Comments table per session (TheVoid 1.3 style)
- [ ] Threaded comments under each log
- [ ] Team chat within log detail
- [ ] @mentions for team members

### 14.7 Team / Multi-user
- [ ] Users/Roles tables (admin, owner, traffer, checker, vbiver)
- [ ] Invite codes with roles + expiration date
- [ ] Worker management UI
- [ ] Session lock (checker takes → others hidden)
- [ ] Activity log per worker
- [ ] Ban management (HWID + IP) per worker from Panel

### 14.8 Cookie Restore / Google Restore
- [ ] Google Refresh Token → Access Token exchange
- [ ] Upload cookies + SOCKS5 proxy config UI
- [ ] SOCKS5 proxy integration for restore
- [ ] Automatic proxy rotation

### 14.9 Public Statistics Page
- [ ] Public link generation (per all logs or per build tag)
- [ ] Metrics: total logs, crypto logs %, duplicates %, empty %
- [ ] Geo distribution (flag + country + count)

### 14.10 API Endpoints
- [ ] GET /api/logs — list logs with filters
- [ ] GET /api/log/:id — get single log data
- [ ] POST /api/build — create new build
- [ ] GET /api/stats/filtered — filtered statistics
- [ ] API key management in Panel settings
- [ ] Rate limiting per API key (Pro: limited, Team: unlimited)

### 14.11 Database — PostgreSQL Support
- [ ] EF Core PostgreSQL provider (Npgsql)
- [ ] SQLite for dev/solo, PostgreSQL for Team
- [ ] Migration system (SQLite ↔ PostgreSQL)
- [ ] Performance: millions of rows, millisecond queries

### 14.12 Lifetime & Subscription Licensing
- [ ] License key generation with tiers (Starter/Pro/Team/Lifetime)
- [ ] Subscription expiry enforcement in Panel
- [ ] Trial period (7 days) mechanism
- [ ] License renewal/upgrade flow

---

## Phase 16: RAT & Stealer Integration ⬜

> Интеграция лучших техник из Overlord (RAT), Intelix (stealer), LegionStealerStub (stealer).
> **Всего:** 38 задач | **Оценка:** ~25 дней

### 16.1 Stealer Engine — EDR/AV Bypass (7 задач, ~5 дней)
- [x] Stack Spoofing (Call Stack Obfuscation) — Overlord garble cflow, STORM
- [x] Persistence Multi-Method (Registry + Task Scheduler + Startup + WMI) — Overlord
- [x] Hosts File Poisoning (29 AV domains → 127.0.0.1) — LegionStealerStub
- [x] Windows Defender Disable (Registry + PowerShell) — LegionStealerStub
- [x] Anti-VM: Hosting IP Check (ip-api.com/hosting) — LegionStealerStub
- [x] NTDLL Unhook (clean .text section restore)
- [x] Keylogger (WH_KEYBOARD_LL hook + message loop)

### 16.2 Coverage Expansion — из Intelix (11 задач, ~7 дней)
- [ ] VPN clients (18: NordVPN, OpenVPN, WireGuard, SurfShark, ExpressVPN, CyberGhost, PIA, Mullvad, Windscribe, TunnelBear, Hotspot Shield, VyprVPN, Hamachi, HideMyName, IpVanish, RadminVPN, SoftEther, ProtonVPN)
- [ ] 2FA Authenticators (7: Google, Microsoft, Authy, Duo Mobile, OTP Auth, FreeOTP, Aegis)
- [ ] Password Managers (8: Bitwarden, Dashlane, Keeper, KeePassXC, LastPass, NordPass, RoboForm, 1Password)
- [ ] Seed Phrase Grabber (BIP39 regex scan across Desktop/Documents/Downloads + cloud storages)
- [ ] Yandex Passman (Яндекс.Браузер password manager decrypt)
- [ ] App-Bound v20 Flags 1-3 (CNG NCryptDecrypt fallback) — Intelix
- [ ] Discord billing/payment scraping + gift codes — LegionStealerStub
- [ ] Webcam Capture (AVICAP32 / DirectShow COM)
- [x] Desktop wallets expansion (+23 → 38 total) — Intelix
- [x] Extension wallets expansion (+14 → 96 total) — Intelix
- [ ] Messengers expansion (+8: Element, ICQ, MicroSIP, Jabber, Outlook, Skype, Tox, Viber)

### 16.3 RAT Capabilities — из Overlord (5 задач, ~10 дней)
- [ ] Reverse Proxy (SOCKS5 server inside stealer) — Overlord, NyashRat
- [ ] Chrome Backstage Injection (DLL inject + DXGI capture) — Overlord
- [ ] Multi-Platform Build (Linux/macOS via Zig targets) — Overlord conditional tags
- [ ] Self-Supersede / Agent Update (download + replace + re-persist) — Overlord
- [ ] WASM Plugin Runtime (load collector modules dynamically)

### 16.4 Panel Improvements (8 задач, ~5 дней)
- [ ] TOTP 2FA Authentication (pyotp-style QR + verify flow) — nexus-stealer
- [ ] IP Security Scoring (multi-API IP check before login) — nexus-stealer
- [ ] In-Panel Documentation (docs/ rendered in browser)
- [ ] Community Chat + Support Tickets (WebSocket, emoji, GIF, @mentions)
- [ ] Marketplace / Module Store (premium modules with license keys)
- [ ] Session Management (device tracking + remote terminate)
- [ ] Public Statistics Page (total logs, crypto %, geo map)
- [ ] API Key Management (scoped keys with rate limiting)

---

## Summary: Total Tasks

### 15.1 Pricing
- [ ] Starter — $70/мес (Mirage Stealer only, basic panel, 1 TG bot)
- [ ] Pro — $150/мес (Stealer + Loader + Clipper, 7 TG bots, smart filters, API limited)
- [ ] Team — $350/мес (All modules, 15 TG bots, unlimited API, PostgreSQL, team accounts)
- [ ] Lifetime — $700/$1500/$3500 (Starter/Pro/Team)

### 15.2 Landing & Support
- [ ] Telegram bot for sales/support (@EidosBot)
- [ ] Setup Exploit.in / XSS thread
- [ ] Refund policy documentation
- [ ] Referral program (20%) tracking in Panel

### 15.3 Eidos Morpher (Build-time ASM Morphing)
- [ ] Junk code insertion (random NOP/mov/xor sequences)
- [ ] Section renaming (.c0de, .cnst, .vars, .heap, .idt0, .pd0x)
- [ ] Entry point obfuscation
- [ ] IAT reordering + fake imports
- [ ] Compile-time metamorphism (каждая сборка уникальна)
- [ ] Target: 75%+ uniqueness per build

### 15.4 OpSec & Cleanup
- [ ] Global runtime cleanup (remove all detection signatures)
- [ ] Full remorph (change binary structure, section names, entry point)
- [ ] Replace all proxy/bridge servers
- [ ] Final Defender/AV scan — target < 5/70 detection

---

## Summary: Total Tasks

| Phase | Tasks | Est. Effort | Status |
|-------|-------|------------|--------|
| 1-7. Core (Mirage) | 142 | ✅ Done | **142/142** |
| 8. Unit Tests | 192 | ✅ Pass | **192/192** |
| 8b. Integration Tests | 8 | 1 day | **8/8** |
| 9-11. Expansion (Mirage) | 77 | ✅ Done | **77/77** |
| 12. Eidos Ecosystem | 16 | 5 days | **16/16** |
| 13. Mirage Infrastructure | 22 | ✅ Done | **22/22** |
| 14. Eidos Panel Premium | 48 | 12 days | **0/48** |
| 15. Eidos Commercial | 17 | 7 days | **0/17** |
| 16. RAT & Stealer Integration | 38 | 25 days | **0/38** |
| **Total** | **257 + 192 tests** | **~52 days** | **142/257 ✅** |

## Execution Priority

### Sprint 1 (Дни 1-3 ✅): Quick Wins — Phase 16
- [x] Phase 16.1.3: Hosts File Poisoning
- [x] Phase 16.1.4: Defender Disable
- [x] Phase 16.1.5: Hosting IP check
- [x] Phase 16.2.9: Desktop wallets expansion (+17)
- [x] Phase 16.2.10: Extension wallets expansion (+14)

### Sprint 2 (Дни 4-7): Core EDR Bypass — Phase 16
- Phase 16.1.1: Stack Spoofing
- Phase 16.1.6: NTDLL Unhook
- Phase 16.1.7: Keylogger
- Phase 16.1.2: Persistence Multi-Method

### Sprint 3 (Дни 8-12): Coverage — VPN + 2FA + PM
- Phase 16.2.1: VPN clients (18)
- Phase 16.2.2: 2FA Authenticators (7)
- Phase 16.2.3: Password Managers (8)
- Phase 16.2.4: Seed Phrase Grabber
- Phase 16.2.5: Yandex Passman
- Phase 16.2.6: App-Bound Flags 1-3

### Sprint 4 (Дни 13-16): Coverage — Discord + Webcam + Messengers
- Phase 16.2.7: Discord billing/gifts
- Phase 16.2.8: Webcam
- Phase 16.2.11: Messengers (+8: Element, ICQ, MicroSIP, Jabber, Outlook, Skype, Tox, Viber)

### Sprint 5 (Дни 17-21): RAT Capabilities
- Phase 16.3.1: Reverse Proxy (SOCKS5)
- Phase 16.3.4: Self-Supersede / Agent Update

### Sprint 6 (Дни 22-25): Panel + Polish
- Phase 16.4.1: TOTP 2FA
- Phase 16.4.2: IP Security Scoring
- Phase 16.4.3: In-Panel Documentation
- Phase 16.4.7: Public Statistics
- Phase 16.4.8: API Key Management

### Sprint 7 (Дни 26-28): Remaining Phase 14-15
- Phase 14.1-14.5: Smart filters, log detail, builder, TG bots, UI/UX
- Phase 14.6: Comments/chat system

### Sprint 8 (Дни 29-36): Team & Enterprise
- Phase 14.7: Team/Multi-user
- Phase 14.8: Cookie Restore
- Phase 14.9: Public stats
- Phase 14.10: API
- Phase 14.11: PostgreSQL
- Phase 14.12: Lifetime licensing
- Phase 15.1-15.2: Pricing, landing, support

### Sprint 9 (Дни 37-45): Advanced — Phase 16 P3-P4
- Phase 16.3.2: Chrome Backstage Injection
- Phase 16.3.3: Multi-Platform Build
- Phase 16.3.5: WASM Plugin Runtime
- Phase 16.4.4: Community Chat
- Phase 16.4.5: Marketplace
- Phase 16.4.6: Session Management
- Phase 15.3: Eidos Morpher
- Phase 15.4: OpSec cleanup + launch

---

## ⬜ Missing Components

### MirageDecryptor.dll (C++ COM Elevator DLL)
- [ ] Найти исходный код `DllExtractChromiumSecrets/DllMain.cpp` (Maldev-Academy)
- [ ] Положить в `Mirage.Stealer/src/` или отдельную директорию `MirageDecryptor/`
- [ ] Проверить совместимость с App-Bound текущих версий Chrome/Edge/Brave
