# zialfi — Ответы на вопросы

## Q: Почему 3/4 E2E тестов?
**A:** Panel connectivity тест FAIL потому что API ключ не настроен в базе данных. Панель работает, но для `upload_log()` нужен валидный API ключ. Создаётся через веб-интерфейс панели. Остальные 3 теста (browser/wallet/messenger enumeration) — PASS.

## Q: Аудит 2026-07-29: что исправлено?
**A:** 8 файлов, +56/-37 строк:
- **C1** uac_bypass.c — buffer overflow при ASCII→WCHAR конверсии
- **C3** schannel.c/h — double-free CredHandle при фейле handshake
- **H2** schannel.h — uint32_t→ULONG_PTR (потеря бит на x64)
- Medium: clipper.c (&&/||), persistence.c (REG_SZ), evasion.c (dead code)
- Low: keylogger, clipper (unused vars)

## Q: Chrome App-Bound (v20) — почему не работает через SSH?
**A:** Chrome v120+ использует COM IElevator для App-Bound Encryption. Класс регистрируется только в GUI сессии (Session 1+). Через SSH (Session 0) CoCreateInstance выдаёт 0x80040154. Альтернативы:
- NCrypt "Google Chromekey1" — не создан на тестовой машине (0x80090016)
- Chrome memory scan — 0 кандидатов (ключ не хранится в памяти)
- Session migration — нужен SeTcbPrivilege (только SYSTEM)
- **Решение:** запуск через GUI (double-click)

## Q: Результаты на реальном Windows 10?
**A:** Тест на `192.168.3.43` (Win10 22H2):
- Indirect syscalls — ✅ PEB walk success
- Chrome autofill — ✅ 6 записей (Chrome + Edge)
- Memory read — ✅ master key получен
- Screenshot, system info — ✅
- Steam, Minecraft, KeePassXC — ✅ данные собраны
- Windows Defender — **0 детектов**
- Chrome v20 пароли — ❌ (требуют GUI сессию)

## Q: Почему Zig 0.16.0 не работает?
**A:** ReleaseSmall режим — баг компилятора. `return 42` из main → exit 0. `@breakpoint()` → exit 0. Вся функция main() оптимизируется в `return 0`. Debug режим работает идеально.

## Q: Почему сисколы непрямые?
**A:** Используются NASM stubs с gadget pool (64 `syscall;ret` из ntdll .text). SSN resolution через Halo's Gate. XOR obfuscation (0xA3B5C7D9). Не прямой `syscall` — indirect через gadget.

## Q: Почему nt_types.h конфликтует с windows.h?
**A:** Определения типов (ULONG, DWORD, IMAGE_*) конфликтуют. Решение: `#ifndef _WIN32` guards для конфликтующих структур. Типы UNICODE_STRING, LIST_ENTRY, PEB определены всегда.

## Q: Что собирает стилер?
**A:**
- 68 Chromium + 10 Gecko браузеров (пароли, куки, карты, история)
- 96 extensions + 38 desktop кошельков
- 13 мессенджеров (Discord, Telegram, Signal, WhatsApp...)
- System info, WiFi
- Crypto: AES-256-GCM, ChaCha20, DPAPI
- Evasion: AMSI, ETW, UAC bypass, PEB hide, defender disable
- Cleanup: persistence (Registry, Task Scheduler, WMI), self-delete

## Q: Почему.panel не настраивается через SSH?
**A:** Панель требует: 1) запуск с правильными env vars, 2) миграции БД, 3) создание invite code, 4) регистрацию пользователя, 5) создание API ключа. Через SSH каждый шаг требует отдельных Go программ. Через веб-интерфейс — 2 клика.

## Q: Что нужно для полного E2E теста?
**A:**
1. Запустить panel: `.\bin\panel.exe`
2. Открыть `http://127.0.0.1:9999` в браузере
3. Зарегистрировать пользователя (invite code: default)
4. Создать API ключ
5. Запустить: `.\tests\test_e2e.exe 127.0.0.1 9999`

## Q: Как пересобрать?
**A:**
```bash
# На Linux (cross-compile):
cd zialfi && make clean && make

# На Windows:
cd Mirage.Stealer && zig build -Dtarget=x86_64-windows
```

## Q: Как запустить тесты?
**A:**
```powershell
# На Windows:
cd zialfi
make test-unit     # Все 9 unit тестов
make test-e2e      # E2E тест
```

## Q: Что осталось доделать?
**A:**
1. Panel API ключ (настроить через веб-интерфейс)
2. uac_bypass (fodhelper bypass)
3. defender_disable (полная реализация)
4. wifi (реализовать сбор паролей)
