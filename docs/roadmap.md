# Eidos — Roadmap

**Eidos** — экосистема вредоносного ПО. **Mirage** — инфостилер внутри экосистемы.

---

## Архитектура экосистемы

```
EIDS ECOSYSTEM
├── Eidos Panel (C# WPF + ASP.NET Core) — центральное управление
│   ├── Сбор логов со всех модулей
│   ├── Билдер для каждого модуля
│   ├── Team / Multi-user система
│   ├── API для автоматизации
│   ├── PostgreSQL (Enterprise)
│   └── Dashboard + Smart Filters + Cookie Restore
│
├── Mirage Stealer (Zig, ~123 KB) — кража данных
│   ├── 100+ браузеров, 80+ кошельков, 12 мессенджеров, 7 игр
│   ├── SSP — серверная расшифровка
│   ├── NTDLL unhook, Stack spoofing, FreshyCalls
│   ├── Anti-analysis, Geo-block, HWID ban
│   ├── File grabber + Regex grabber (BIP39/PK/JWT)
│   └── Self-delete + UAC bypass
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
Phase 8b: Integration Tests      ░░░░░░░░░░░░░░░░░░░░   0/8

Phase 12: Eidos Ecosystem        ░░░░░░░░░░░░░░░░░░░░   0/16
Phase 13: Mirage — Infrastructure ████████████████████  22/22 ✅
Phase 14: Eidos Panel Premium    ░░░░░░░░░░░░░░░░░░░░   0/48
Phase 15: Eidos Commercial       ░░░░░░░░░░░░░░░░░░░░   0/17
```

**Total: 142/142 ✅ Done + 192 unit tests ✅ + 110 ⬜ New**

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

## Phase 12: Eidos Ecosystem — Standalone Modules ⬜

> Эти модули — отдельные проекты, которые могут работать независимо.
> Mirage Stealer может их загрузить и запустить после отработки.

### 12.1 Eidos Clipper (отдельный проект, ~50 KB, нерезидентный)
- [ ] OpenClipboard polling monitor (SetWindowsHookEx)
- [ ] BTC (Legacy 1, SegWit 3, bech32 bc1, bc1p)
- [ ] ETH + EVM-совместимые (0x...)
- [ ] TRX, XMR, SOL, TON, LTC, DASH, DOGE, ADA, XLM, BCH
- [ ] Работает до перезагрузки ПК жертвы
- [ ] Отправка логов на Eidos Panel

### 12.2 Eidos Loader (отдельный проект, ~30 KB, stage 1)
- [ ] Anti-analysis → HTTP GET payload → CreateProcess → Delete
- [ ] .exe → CreateProcessW (CREATE_NO_WINDOW)
- [ ] .dll → LdrLoadDll
- [ ] .ps1 → powershell -exec bypass
- [ ] Multi-file (до 10), env var expansion, target dir
- [ ] Может развернуть Mirage Stealer, Eidos Clipper, Eidos Keylogger

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

## Phase 15: Eidos Commercial Launch ⬜

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
| 9-11. Expansion (Mirage) | 77 | ✅ Done | **77/77** |
| 8b. Integration Tests | 8 | 1 day | **0/8** |
| 12. Eidos Ecosystem | 16 | 5 days | **0/16** |
| 13. Mirage Infrastructure | 22 | ✅ Done | **22/22** |
| 14. Eidos Panel Premium | 48 | 12 days | **0/48** |
| 15. Eidos Commercial | 17 | 7 days | **0/17** |
| **Total** | **219 + 192 tests** | **~30 days** | **142/219 ✅** |

## Execution Priority

### Sprint 1 (Дни 1-3): Quick Wins
- Phase 8b: Integration tests
- Phase 13.5: Redirect proxies (Level 1-2)

### Sprint 2 (Дни 4-7): Infrastructure
- Phase 13.1: Chunked upload
- Phase 13.2: VPN/FTP/Email clients
- Phase 13.6: Anti-flood / Firewall

### Sprint 3 (Дни 8-12): Ecosystem — Clipper + Loader
- Phase 12.1: Eidos Clipper (отдельный проект)
- Phase 12.2: Eidos Loader (отдельный проект)

### Sprint 4 (Дни 13-17): Mirage — Coverage
- Phase 13.3: ICQ messenger
- Phase 13.4: Firefox extensions

### Sprint 5 (Дни 18-24): Panel Premium
- Phase 14.1-14.5: Smart filters, log detail, builder, TG bots, UI/UX
- Phase 14.6: Comments/chat system

### Sprint 6 (Дни 25-32): Team & Enterprise
- Phase 14.7: Team/Multi-user
- Phase 14.8: Cookie Restore
- Phase 14.9: Public stats
- Phase 14.10: API
- Phase 14.11: PostgreSQL

### Sprint 7 (Дни 33-38): Commercial
- Phase 14.12: Lifetime licensing
- Phase 15.1-15.2: Pricing, landing, support
- Phase 15.5: Eidos Morpher

### Sprint 8 (Дни 39-45): Premium Modules
- Phase 12.3: Eidos Keylogger
- Phase 12.4: Eidos Webcam
- Phase 12.5: Eidos Resident
- Phase 15.4: OpSec cleanup + launch
