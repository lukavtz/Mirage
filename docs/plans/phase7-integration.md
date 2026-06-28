# Phase 6.1 (finish) + Phase 7: Integration & Hardening — План

## Phase 6.1 — Embedded Resources

**Задача:** Встроить `Mirage.Stealer.exe` и `MirageDecryptor.dll` в Panel.exe как embedded resources.

**Референс:** SentinelStealer `Resources.Designer.cs` (Standard `ResourceManager`),
PhantomStealer `ResourceManager.cs` (AES-CBC encrypted + decoy resources)

**Реализация:**
1. Добавить файлы в `Panel/Resources/Mirage.Stealer.exe` и `Panel/Resources/MirageDecryptor.dll`
2. В `.csproj` добавить как `<EmbeddedResource Include="Resources\*" />`
3. Создать `Services/ResourceExtractor.cs` — `ExtractStealer()` / `ExtractDecryptor()` 
   через `Assembly.GetManifestResourceStream`
4. Подключить в BuildPage.xaml.cs — при билде вызывать ResourceExtractor вместо OpenFileDialog

## Phase 7.1 — Compile Pipeline

**build.zig — финализация:**
- ReleaseSmall, strip, single-threaded — уже есть ✅
- Добавить проверку: `zig build` → `zig build test` → verify size < 150KB
- IAT verification скрипт (PowerShell через dumpbin /imports)

**Референс:** PhantomLoader `scripts/verify.ps1`, EidosLoader `tools/run-e2e.ps1`

## Phase 7.2 — Security

**String review:** Аудит уже показал XOR-encrypted строки в 29 файлах ✅
**PEB walk тесты:** Добавить тест в main.zig
**Syscall SSN тесты:** Добавить тест что все SSN < 0x500 и уникальны

## Phase 7.3 — Documentation

Создать:
- `ARCHITECTURE.md` — системная диаграмма + описание модулей
- `OPSEC.md` — operational security guidance
- `TESTING.md` — как тестировать каждый модуль

**Референс:** PhantomLoader `docs/design.md` (610 lines), `docs/anti_attribution.md` (686 lines),
Browser-Data-Grabber `ARCHITECTURE.md` (323 lines)
