# Mirage.Stealer — Полный аудит кода (что есть / чего нет)

**Всего файлов: 68 .zig (без папки Mirage.Panel)**
**Дата аудита: 28 июня 2026**

---

## 1. FOUNDATION (Базовый слой) — ✅ ПОЛНОСТЬЮ

| Файл | Строк | Статус | Описание |
|------|-------|--------|----------|
| `types/types.zig` | 339 | ✅ | PE/PEB/NT structures, CONTEXT, SYSTEM_BASIC_INFO, IMAGE_* |
| `types/hash.zig` | 152 | ✅ | XOR-encrypted hashing (comptime), xorEncrypt/xorDecrypt |
| `types/peb.zig` | 8 | ✅ | `getPeb()` inline asm |
| `types/peb_walk.zig` | 39 | ✅ | `getModuleByHash()` — LDR walk |
| `types/export_resolve.zig` | 106 | ✅ | `initNativeResolver()` + `getFunctionByHash()` |
| `types/util.zig` | 19 | ✅ | `secureZero()`, `readU32Le()`, `trimmedLen()` |
| `config/config.zig` | 18 | ✅ | Comptime config (SEED, C2, TG, thresholds) |
| `config_decrypt.zig` | — | ✅ | Config decryption at runtime |

**Вывод:** Фундамент прочный. Всё что нужно для PEB walk, hash resolution, XOR encryption — есть.

---

## 2. SYSCALL ENGINE — ✅ ПОЛНОСТЬЮ (с потенциалом улучшения)

| Файл | Строк | Статус | Описание |
|------|-------|--------|----------|
| `syscalls/engine.zig` | 450 | ✅ | Halo's Gate SSN resolution, 22 syscall wrappers |
| `syscalls/stubs.zig` | 321 | ✅ | 22 indirect syscall stubs via global asm |
| `syscalls/gadget.zig` | 62 | ✅ | 64 `syscall;ret` gadget pool from ntdll .text |
| `syscalls/dbg.zig` | 87 | ✅ | CONOUT$ debug output via NtWriteFile |

**22 сисколла:**
NtAllocateVirtualMemory, NtProtectVirtualMemory, NtFreeVirtualMemory,
NtWriteVirtualMemory, NtClose, NtOpenFile, NtReadVirtualMemory,
NtCreateSection, NtMapViewOfSection, NtQueryInformationProcess,
NtCreateFile, NtWriteFile, NtQuerySystemInformation, NtDelayExecution,
NtCreateEvent, NtWaitForSingleObject, NtOpenKey, NtQueryValueKey,
NtSetInformationProcess, NtGetContextThread, NtSetContextThread,
NtUserGetSystemMetrics

**Чего НЕТ (из STORM/TheVoid):**
- ❌ Stack spoofing / EDR bypass
- ❌ NTDLL unhook (удаление хуков из user-space)
- ❌ FreshyCalls (динамическая генерация заглушек)
- ❌ Runtime SSN encryption
- ❌ Registry hook removal

---

## 3. EVASION (Анти-анализ) — ✅ БАЗОВО, нужно расширять

| Файл | Строк | Статус | Описание |
|------|-------|--------|----------|
| `evasion/anti_analysis.zig` | 92 | ✅ | Weighted scoring (RAM/CPU/screen/VM/debugger/timing) |
| `evasion/evasion.zig` | 218 | ✅ | Low-level check primitives |
| `evasion/peb_hide.zig` | 32 | ✅ | Unlink module from 3 LDR lists |
| `evasion/mutex.zig` | 62 | ✅ | NtCreateEvent single-instance mutex |

**Проверки (6):**
- Debugger (NtQueryInformationProcess)
- RAM < 2GB
- CPU cores < 2
- Screen resolution
- VM registry (BIOS strings: VMware, VirtualBox, QEMU, Xen, Bochs)
- Timing anomaly (rdtsc + NtDelayExecution)

**Чего НЕТ:**
- ❌ **Process list check** (taskmgr, processhacker, wireshark, procexp, dbgview)
- ❌ **HWID-based ban** (Volta имеет бан по HWID)
- ❌ **Geo-block на билде** (тройная проверка: IP/раскладка/язык)
- ❌ **Anti-sandbox расширенный** (диски, мышь, uptime)
- ❌ **Sleep/jitter** (SLEEP_MIN_MS, SLEEP_JITTER_MS есть в config, но не используются)
- ❌ **Self-delete** после отработки

---

## 4. CRYPTO (Криптография) — ✅ ПОЛНОСТЬЮ

| Файл | Строк | Статус | Описание |
|------|-------|--------|----------|
| `crypto/dpapi.zig` | — | ✅ | CryptUnprotectData |
| `crypto/chrome_crypto.zig` | 124 | ✅ | PBKDF2 + AES-256-GCM (Chrome decrypt) |
| `crypto/chrome_key.zig` | — | ✅ | JSON Local State parser + Base64 |
| `crypto/aes_gcm_bcrypt.zig` | — | ✅ | BCrypt CNG AES-GCM fallback |
| `crypto/chacha_poly.zig` | — | ✅ | ChaCha20-Poly1305 AEAD |
| `crypto/archive_crypt.zig` | 93 | ✅ | ZIP encrypt/decrypt with seed-derived key |
| `crypto/dll_loader.zig` | — | ✅ | LdrLoadDll wrapper |

**Вывод:** Крипто слой полностью готов. AES-GCM, ChaCha20-Poly1305, DPAPI, BCrypt — всё реализовано. **Server-Side Processing** как концепция требует не изменения крипто, а изменения архитектуры (перенос расшифровки в Panel).

---

## 5. PARSERS (Парсеры) — ✅ ПОЛНОСТЬЮ

| Файл | Строк | Статус | Описание |
|------|-------|--------|----------|
| `parsers/sqLoot.zig` | — | ✅ | Custom SQLite parser (B-tree, varint, overflow) |
| `parsers/file_io.zig` | — | ✅ | File mapping via NtCreateFile/NtMapViewOfSection |

---

## 6. BROWSERS (Браузеры) — ✅ 46 шт, НО хардкод

### Chromium — 36 браузеров
| Файл | Статус |
|------|--------|
| `browsers/chromium_paths.zig` | ✅ 36 путей (XOR-encrypted) |
| `browsers/chromium.zig` | ✅ orchestrator |
| `browsers/chromium_login.zig` | ✅ |
| `browsers/chromium_cookies.zig` | ✅ |
| `browsers/chromium_cards.zig` | ✅ |
| `browsers/chromium_history.zig` | ✅ |
| `browsers/chromium_autofill.zig` | ✅ |
| `browsers/chromium_bookmarks.zig` | ✅ |
| `browsers/appbound.zig` | ✅ COM Elevator (Chrome v20+) |
| `browsers/appbound_inject.zig` | ✅ Self-copy + CreateProcessAsUser |

### Gecko — 10 браузеров
| Файл | Статус |
|------|--------|
| `browsers/firefox_paths.zig` | ✅ 10 путей |
| `browsers/firefox.zig` | ✅ orchestrator |
| `browsers/firefox_asn1.zig` | ✅ ASN1 DER + 3 PBE decoders |
| `browsers/firefox_login.zig` | ✅ key4.db + logins.json → NSS |
| `browsers/firefox_cookies.zig` | ✅ |
| `browsers/firefox_history.zig` | ✅ |
| `browsers/firefox_bookmarks.zig` | ✅ |

### Что нужно ДОБАВИТЬ:
| Фича | Где надо |
|------|----------|
| ❌ **Dynamic Browser Scan** (сканирование LOCALAPPDATA/APPDATA на браузеры) | Новый файл: `browsers/browser_scanner.zig` |
| ❌ **Расширение Chromium до 70+** (Canary, Dev, Beta, CryptoTab, UC, QQ, 360, Liebao и др.) | `chromium_paths.zig` — добавить пути |
| ❌ **Расширение Gecko до 30+** (LibreWolf, Floorp, IceCat, FirefoxBeta/Nightly/Dev и др.) | `firefox_paths.zig` — добавить пути |
| ❌ **Google OAuth Tokens** (Token Service, MultiLogin, GAIA ID) | Новый модуль |
| ❌ **Outlook OAuth tokens** | Новый модуль |
| ❌ **Chrome LocalStorage/IndexedDB сбор** | Новый модуль |
| ❌ **Server-Side Processing** (билд не трогает SQLite) | Требует реархитектуры |

---

## 7. WALLETS (Кошельки) — ✅ 72 шт, НО хардкод

| Файл | Строк | Статус |
|------|-------|--------|
| `wallets/wallet_extensions.zig` | 244 | ✅ 62 расширения (XOR-encrypted IDs) |
| `wallets/wallet_desktop.zig` | 135 | ✅ 10 десктопных |
| `wallets/wallets.zig` | — | ✅ orchestrator |

### Что нужно ДОБАВИТЬ:
| Фича | Где надо |
|------|----------|
| ❌ **Расширение десктопных до 20+** (Bitcoin Core, Litecoin Core, Dogecoin Core, Dash Core, Armory, MultiDoge, ElectrumLTC и др.) | `wallet_desktop.zig` |
| ❌ **Wallet Injection** (Exodus/Atomic — подмена app.asar) | Новый файл: `wallets/wallet_inject.zig` |
| ❌ **Wallet.dat глубокий сбор** | Дополнить `wallet_desktop.zig` |
| ❌ **2FA расширения** (2FAS, 2FAAuthenticator, KeepassXC и др.) | `wallet_extensions.zig` |
| ❌ **Password managers** (Norton, Avira, Passky, Padloc) | `wallet_extensions.zig` |
| ❌ **Notes расширения** (Notion, Evernote, OneNote, Google Keep) | `wallet_extensions.zig` |

---

## 8. MESSENGERS (Мессенджеры) — ✅ 4 шт, нужно расширять

| Файл | Строк | Статус | Описание |
|------|-------|--------|----------|
| `messengers/discord.zig` | 196 | ✅ | LevelDB token extraction |
| `messengers/telegram.zig` | 147 | ✅ | tdata session files |
| `messengers/signal.zig` | — | ✅ | Signal config + sql |
| `messengers/pidgin.zig` | — | ✅ | accounts.xml + logs |
| `messengers/messengers.zig` | 77 | ✅ | orchestrator |

### Что нужно ДОБАВИТЬ:
| Фича | Где |
|------|-----|
| ❌ **Telegram моды** (AyuGram, 64Gram, Kotatogram, Nekogram, Forkgram, Unigram, iMe и др.) | `messengers/telegram.zig` — сканирование по маскам |
| ❌ **Discord Injection** (JS inject в desktop core) | Новый файл: `messengers/discord_inject.zig` |
| ❌ **Session** (Signal-форк) | Новый модуль |
| ❌ **Tox/uTox** | Новый модуль |
| ❌ **Skype** | Новый модуль |
| ❌ **Viber** | Новый модуль |
| ❌ **Element (Matrix)** | Новый модуль |
| ❌ **WhatsApp Desktop** | Новый модуль |
| ❌ **MFA + encrypted Discord tokens** | Дополнить `discord.zig` |

---

## 9. GAMING (Игры) — ✅ 5 шт

| Файл | Строк | Статус |
|------|-------|--------|
| `gaming/steam.zig` | — | ✅ |
| `gaming/uplay.zig` | — | ✅ |
| `gaming/minecraft.zig` | — | ✅ (17 launchers) |
| `gaming/battlenet.zig` | — | ✅ |
| `gaming/roblox.zig` | — | ✅ |
| `gaming/gaming.zig` | 119 | ✅ orchestrator |

### Что нужно ДОБАВИТЬ:
| Фича | Где |
|------|-----|
| ❌ **Epic Games Store** | Новый модуль |
| ❌ **Riot Games** (League of Legends, VALORANT) | Новый модуль |

---

## 10. SYSTEM (Системная инфа) — ✅ базово

| Файл | Строк | Статус |
|------|-------|--------|
| `system/os_info.zig` | 118 | ✅ Registry через NtOpenKey |
| `system/hardware.zig` | 239 | ✅ CPU, GPU, RAM, disks |
| `system/network_info.zig` | 194 | ✅ Hostname, IP, MAC |
| `system/wifi.zig` | 100 | ✅ Wlansvc XML profiles |
| `system/screenshot.zig` | 87 | ✅ PowerShell GDI screenshot |
| `system/grabber.zig` | 144 | ✅ File grabber by mask |
| `system/system_info.zig` | 91 | ✅ Master collector |

### Что нужно ДОБАВИТЬ:
| Фича | Где |
|------|-----|
| ❌ **Список запущенных процессов** | Новый модуль |
| ❌ **Список установленных приложений** | Новый модуль |
| ❌ **Буфер обмена** | Новый модуль |
| ❌ **Информация о способе запуска** (Disk/Memory) | Дополнить `system_info.zig` |
| ❌ **GPU детали** (дополнить current) | Дополнить `hardware.zig` |
| ❌ **Regex-граббер в памяти** (BIP39, private keys, API keys) | Новый модуль `system/regex_grabber.zig` |
| ❌ **Файл-граббер с правилами** (путь+маска+исключение+лимит+кэш) | Переработать `grabber.zig` |

---

## 11. NETWORK (Сеть) — ✅ базово, нужно чанки и прокладки

| Файл | Строк | Статус | Описание |
|------|-------|--------|----------|
| `network/ws2.zig` | 265 | ✅ | Winsock (hash-resolved) |
| `network/schannel.zig` | 460 | ✅ | TLS via secur32.dll |
| `network/tls_socket.zig` | 46 | ✅ | TCP + TLS wrapper |
| `network/http.zig` | 231 | ✅ | HTTP/1.1 client, multipart |
| `network/panel_http.zig` | 79 | ✅ | POST /api/log with Bearer token |
| `network/telegram.zig` | 95 | ✅ | POST /botTOKEN/sendDocument |
| `network/zip.zig` | 201 | ✅ | PKZIP Store (CRC32 LUT, in-memory) |

### Что нужно ДОБАВИТЬ:
| Фича | Где |
|------|-----|
| ❌ **Chunked Upload** (отправка частями по 1 MB) | Новый эндпоинт + переработка `panel_http.zig` |
| ❌ **Прокладки Level 1** (Telegram/TON/Steam — парсинг C2 из публичного поста) | Новый файл: `network/proxy.zig` |
| ❌ **Прокладки Level 2** (GitHub Releases) | `network/proxy.zig` |
| ❌ **Прокладки Level 3** (VPS Bridge — SSH tunnel) | `network/proxy.zig` |
| ❌ **Самоудаление** (MoveFileEx / FILE_DISPOSITION_INFORMATION / cmd fallback) | Новый файл: `cleanup/self_delete.zig` |

---

## 12. ДОПОЛНИТЕЛЬНЫЕ МОДУЛИ — ❌ ПОЛНОСТЬЮ ОТСУТСТВУЮТ

| Модуль | Статус | Приоритет |
|--------|--------|-----------|
| ❌ **Clipper** (подмена крипто-адресов в буфере) | Нет | **P0** |
| ❌ **Loader** (загрузка и запуск файлов после стилера) | Нет | **P0** |
| ❌ **Self-Delete + Melt** | Нет | **P0** |
| ❌ **UAC Bypass** (Fodhelper) | Нет | P1 |
| ❌ **VPN-клиенты** (Nord, OpenVPN, Proton, Express и др.) | Нет | **P2** |
| ❌ **FTP-клиенты** (FileZilla, WinSCP, Total Commander и др.) | Нет | **P2** |
| ❌ **Email-клиенты** (Outlook, Thunderbird, Foxmail и др.) | Нет | **P2** |
| ❌ **Keylogger** (WH_KEYBOARD_LL) | Нет | P3 |
| ❌ **Webcam** (AVICAP32) | Нет | P4 |
| ❌ **Discord Injection** (JS в desktop core) | Нет | P3 |
| ❌ **Resident Module** (ботнет — reverse proxy/shell) | Нет | P4 |

---

## 13. PANEL (Панель) — что есть / чего нет

### Сервер (ASP.NET Core Minimal API)

| Функция | Статус |
|---------|--------|
| POST /api/log | ✅ |
| GET /api/stats | ✅ |
| GET /api/search | ✅ |
| Auth Bearer token | ✅ |
| Rate limiting | ✅ (60 req/min) |
| Telegram уведомления | ✅ (один бот) |
| **POST /api/log/chunk** | ❌ |
| **POST /api/log/complete** | ❌ |
| **Множественные TG боты** | ❌ |
| **Discord webhook уведомления** | ❌ |
| **Cookie Restore endpoint** | ❌ |
| **API для команд (REST)** | ❌ |
| **Server-Side Decrypt endpoint** | ❌ |

### База данных (SQLite EF Core)

| Функция | Статус |
|---------|--------|
| Sessions | ✅ |
| Passwords | ✅ |
| Cookies | ✅ |
| Cards | ✅ |
| Wallets | ✅ |
| StolenFiles | ✅ |
| SystemInfo | ✅ |
| Builds | ✅ |
| **HWID/IP duplicate detection** | ❌ |
| **Bans table** | ❌ |
| **Comments table** | ❌ |
| **Activity log** | ❌ |
| **Workers/users table** | ❌ |

### Dashboard UI

| Функция | Статус |
|---------|--------|
| Stats cards | ✅ |
| Country heatmap | ✅ |
| Browser pie chart | ✅ |
| Sessions timeline | ✅ |
| Top passwords | ✅ |
| Sessions table | ✅ |
| Session detail | ✅ |
| Full-text search | ✅ |
| Settings page | ✅ |
| **Smart filters (domain/OS/wallet type)** | ❌ |
| **Auto-tagging by domain** | ❌ |
| **Color labels in table** | ❌ |
| **Build tags** | ❌ |
| **Comments on logs** | ❌ |
| **Mass export (JSON/HTML/ZIP)** | ❌ |
| **Public statistics page** | ❌ |
| **Team/Worker management** | ❌ |
| **Cookie Restore UI** | ❌ |
| **Ban management** | ❌ |

### Builder (BuildPage.xaml + BuildService.cs)

| Функция | Статус |
|---------|--------|
| PE patching (MIRAGECFG → XOR encrypt) | ✅ |
| DLL overlay | ✅ |
| Build version tracking | ✅ |
| **Build tags** | ❌ |
| **Custom icon/manifest** | ❌ |
| **Module toggles (disable passwords/cookies/wallets)** | ❌ |
| **Startup delay config** | ❌ |
| **Domain Detect config** | ❌ |
| **Download counter** | ❌ |

---

## 14. ИТОГ: КЛЮЧЕВЫЕ ПРОБЕЛЫ

### Что БЫСТРО добавить (1-3 дня):
1. **Self-delete** — 0.5 дня (критично для OPSEC)
2. **Clipper** — 1 день (монетизация)
3. **Loader** — 1 день (монетизация)
4. **Browser scanner (dynamic)** — 1-2 дня (100+ browsers)

### Что СРЕДНЕЙ сложности (3-7 дней):
5. **Chunked upload** — 1-2 дня (надёжность)
6. **Google OAuth tokens** — 1-2 дня (профит)
7. **VPN/FTP/Email** — 2 дня (покрытие)
8. **Telegram моды** — 2 дня (покрытие)
9. **Прокладки Level 1-2** — 1 день (стелс)
10. **Расширение browser paths** — 0.5 дня (покрытие)
11. **Расширение wallet paths** — 0.5 дня (покрытие)
12. **File grabber upgrade** (regex + правила) — 1-2 дня

### Что СЛОЖНОЕ (5+ дней):
13. **Server-Side Processing** — 3-5 дней (реархитектура)
14. **Stack spoofing + NTDLL unhook** — 2-3 дня (EDR bypass)
15. **Team/Multi-user в Panel** — 3-5 дней (продажи)

---

## 15. ФАЙЛЫ, КОТОРЫЕ НУЖНО СОЗДАТЬ

```
src/clipper/clipper.zig                # Clipper (подмена адресов)
src/loader/loader.zig                   # Loader (загрузка файлов)
src/cleanup/self_delete.zig             # Self-delete + melt
src/evasion/uac_bypass.zig              # UAC Bypass (Fodhelper)
src/browsers/browser_scanner.zig        # Dynamic browser scan
src/browsers/google_tokens.zig          # Google OAuth токены
src/wallets/wallet_inject.zig           # Wallet Injection
src/messengers/discord_inject.zig       # Discord JS Injection
src/messengers/telegram_mods.zig        # Telegram моды
src/messengers/session.zig              # Session messenger
src/messengers/tox.zig                  # Tox/uTox
src/messengers/skype.zig                # Skype
src/messengers/viber.zig                # Viber
src/messengers/element.zig              # Element (Matrix)
src/messengers/whatsapp.zig             # WhatsApp Desktop
src/gaming/epic.zig                     # Epic Games
src/gaming/riot.zig                     # Riot Games
src/vpn/vpn.zig                         # VPN клиенты
src/ftp/ftp.zig                         # FTP клиенты
src/email/email.zig                     # Email клиенты
src/system/processes.zig                # Список процессов
src/system/applications.zig             # Установленные приложения
src/system/clipboard.zig               # Буфер обмена
src/system/regex_grabber.zig            # Regex-граббер (BIP39/ключи)
src/keylogger/keylogger.zig             # Keylogger
src/system/webcam.zig                   # Webcam
src/network/chunked.zig                 # Chunked upload
src/network/proxy.zig                   # Прокладки (Telegram/GitHub/VPS)
src/network/telegram_mods.zig           # Расширенный Telegram Proxy
```
